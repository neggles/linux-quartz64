/*
 * Mac80211 driver for BES2600 device
 *
 * Copyright (c) 2022, Bestechnic
 * Author:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/types.h>

#include "bes2600.h"
#include "epta_coex.h"
#include "epta_request.h"

static bool coex_ps_en;
static bool coex_fdd_mode;  /* fdd or fdd hybrid */
static uint8_t epta_conn_state; /* dafault invalid stat */
static uint32_t epta_freeze_bitmap;  /*bit0: conn, bit1: tp, bit2: tts */
static int epta_freezed_wlan_duration[EPTA_FREEZE_MAX] = {0};
static int epta_freezed_wlan_duration_cfg = 0;
static int wlan_duration_cfg;
static int bt_duration_cfg;
static int hw_epta_enable_cfg; /* bit0~bit1: epta mode, bit7: prot flag, other bits: reserved */
static int epta_ps_mode;	/* 0 - normal mode, 1 - power save mode */
static int epta_adjust_cnt;
static int coex_bt_state;
static uint32_t g_coex_mode;

#define EPTA_MODE_CFG (hw_epta_enable_cfg & 0x03)

/*
 * This function will send wsm command to set epta module with inputing parameters.
 * The inputing parameters may not be used really if epta_freeze_bitmap is not zero.
 * @hw_epta_enable:  when hw_epta_enable is 1, use hardware pta, epta does not work,
	wlan_duration and bt_duration mean nothing.
 * @wlan_duration and bt_duration:  need set hw_epta_enable to 0, use software epta.
	Allow 10~100000 us.
 * e.g.
 * coex_set_epta_params(20000, 20000, 0);  means use software epta, wlan get 20ms, bt get 20ms.
 * coex_set_epta_params(20000, 20000, 1);  means use hardware pta, hardware arbitrate.
 */
int coex_set_epta_params(struct bes2600_common *hw_priv, int wlan_duration, int bt_duration, int hw_epta_enable)
{
	struct wsm_epta_msg msg;

	if (hw_priv == NULL) {
		bes2600_dbg(BES2600_DBG_EPTA, "hw_priv is NULL\n");
		return -1;
	}

	bes2600_dbg(BES2600_DBG_EPTA, "set epta w:%d hw:%d wc:%d fbit:%x fw:%d\n", wlan_duration, hw_epta_enable,
		   wlan_duration_cfg, epta_freeze_bitmap, epta_freezed_wlan_duration_cfg);

	if (wlan_duration_cfg == wlan_duration && bt_duration_cfg == bt_duration && hw_epta_enable_cfg == hw_epta_enable) {
		bes2600_dbg(BES2600_DBG_EPTA, "same epta params\n");
		return 0;
	}

	wlan_duration_cfg = wlan_duration;
	bt_duration_cfg = bt_duration;
	hw_epta_enable_cfg = hw_epta_enable;

	/* If in freeze mode, use freezed wlan duration; */
	if (epta_freeze_bitmap) {
		if (epta_freeze_bitmap & EPTA_FREEZE_SCANNING) {
			bes2600_info(BES2600_DBG_EPTA, "skip bt state in wifi scanning");
			return 0;
		}

		/*
		 if new wlan duration is more than freezed one, update fw settings with new duration
		 if new wlan duration is less than freezed one, update fw settings with freezed duration
		*/
		if (wlan_duration < epta_freezed_wlan_duration_cfg) {
			bes2600_info(BES2600_DBG_EPTA, "epta_freeze_bitmap:0x%x, wlan:%u < %u",
				epta_freeze_bitmap, wlan_duration, epta_freezed_wlan_duration_cfg);
			wlan_duration = epta_freezed_wlan_duration_cfg;
			bt_duration = EPTA_FREEZE_TDD_PERIOD - epta_freezed_wlan_duration_cfg;
		}
	}

	/* epta disconnect status,force use HW epta */
	if (epta_conn_state == EPTA_STATE_WIFI_DISCONNECTED && hw_epta_enable == 0)
		hw_epta_enable = 1;

	msg.wlan_duration = wlan_duration;
	msg.bt_duration = bt_duration;
	msg.hw_epta_enable = hw_epta_enable;

	return wsm_epta_cmd(hw_priv, &msg);
}

static int coex_epta_freeze_update(struct bes2600_common *hw_priv)
{
	struct wsm_epta_msg msg;
	int i = 0;
	int max_freeze = 0;

	if (hw_priv == NULL) {
		bes2600_dbg(BES2600_DBG_EPTA, "hw_priv is NULL\n");
		return -1;
	}

	bes2600_dbg(BES2600_DBG_EPTA, "epta update. bitmap:0x%x. fw:%d",
		epta_freeze_bitmap, epta_freezed_wlan_duration_cfg);

	bes2600_dbg(BES2600_DBG_EPTA, "%s, %d", __FUNCTION__, hw_epta_enable_cfg);

	/* Exit freeze mode and recover the configuration of epta module; */
	if (epta_freeze_bitmap == 0) {
		epta_freezed_wlan_duration_cfg = 0;
		return -1;
	}

	/* Enter freeze mode and set the configuration of the epta module; */
	/* select max wifi freeze value */
	for (i = 0; i < EPTA_FREEZE_MAX; i++) {
		if (max_freeze < epta_freezed_wlan_duration[i])
			max_freeze = epta_freezed_wlan_duration[i];
	}

	/* same cfg don't change it */
	if (max_freeze == epta_freezed_wlan_duration_cfg)
		return 0;

	epta_freezed_wlan_duration_cfg = max_freeze;

	/* only support epta_freezed_wlan_duration_cfg > wlan_duration_cfg */
	// wlan_duration_cfg may be override by wsm_epta_cmd
	// if (max_freeze <= wlan_duration_cfg) {
	// 	return 0;
	// }
	msg.wlan_duration = max_freeze;
	msg.bt_duration = EPTA_FREEZE_TDD_PERIOD - max_freeze;
	msg.hw_epta_enable = 0x00;

	return wsm_epta_cmd(hw_priv, &msg);
}

/*
 * coex_epta_freeze
 * freeze coex duration for specific senario
 * @wlan_duration: 20~100ms
 * @type:
 *  EPTA_FREEZE_CONENCTING,
 *  EPTA_FREEZE_TTS,
 *  EPTA_FREEZE_THP,
 * note: the value of wlan_duration should be less than 100000.
 */
int coex_epta_freeze(struct bes2600_common *hw_priv, int wlan_duration, uint32_t type)
{
	uint32_t i;

	epta_freeze_bitmap |= type;

	for (i = 0; i < EPTA_FREEZE_MAX; ++i) {
		if (type & (1 << i))
			epta_freezed_wlan_duration[i] = wlan_duration;
	}
	/* reset epta value */
	epta_ps_mode = 0;
	epta_adjust_cnt = 0;

	return coex_epta_freeze_update(hw_priv);
}

static int coex_epta_recover_update(struct bes2600_common *hw_priv)
{
	struct wsm_epta_msg msg;
	int i = 0;
	int max_freeze = 0;

	if (hw_priv == NULL) {
		bes2600_dbg(BES2600_DBG_EPTA, "hw_priv is NULL\n");
		return -1;
	}

	bes2600_dbg(BES2600_DBG_EPTA, "epta update. bitmap:0x%x. fw:%d",
		epta_freeze_bitmap, epta_freezed_wlan_duration_cfg);

	bes2600_dbg(BES2600_DBG_EPTA, "%s, %d", __FUNCTION__, hw_epta_enable_cfg);

	/* Exit freeze mode and recover the configuration of epta module; */
	if (epta_freeze_bitmap == 0) {
		if (epta_freezed_wlan_duration_cfg == 0)
			return -1;
		epta_freezed_wlan_duration_cfg = 0;
		// coex_set_epta_params will skip epta:0 after got_ip(use connected epta3)
		msg.wlan_duration = wlan_duration_cfg;
		msg.bt_duration = bt_duration_cfg;
		msg.hw_epta_enable = hw_epta_enable_cfg;
		return wsm_epta_cmd(hw_priv, &msg);
	}

	/* Enter freeze mode and set the configuration of the epta module; */
	/* select max wifi freeze value */
	for (i = 0; i < EPTA_FREEZE_MAX; i++) {
		if (max_freeze < epta_freezed_wlan_duration[i])
			max_freeze = epta_freezed_wlan_duration[i];
	}

	epta_freezed_wlan_duration_cfg = max_freeze;
	msg.wlan_duration = max_freeze;
	msg.bt_duration = EPTA_FREEZE_TDD_PERIOD - max_freeze;
	msg.hw_epta_enable = hw_epta_enable_cfg;

	return wsm_epta_cmd(hw_priv, &msg);
}

int coex_epta_recover(struct bes2600_common *hw_priv, uint32_t type)
{
	uint32_t i;

	if (epta_freeze_bitmap == 0)
		return 0;

	if (type == EPTA_FREEZE_ALL) {
		for (i = 0; i < EPTA_FREEZE_MAX; i++) {
			epta_freezed_wlan_duration[i] = 0;
		}
		epta_freeze_bitmap = 0;
	} else {
		epta_freeze_bitmap &= (~type);
		for (i = 0; i < EPTA_FREEZE_MAX; ++i) {
			if (type & (1 << i))
				epta_freezed_wlan_duration[i] = 0;
		}
	}
	return coex_epta_recover_update(hw_priv);
}

int coex_epta_ps(struct bes2600_common *hw_priv, uint8_t enable)
{
	struct wsm_epta_msg msg;
	if (hw_priv == NULL) {
		bes2600_dbg(BES2600_DBG_EPTA, "hw_priv is NULL\n");
		return -1;
	}

	if (enable && !epta_ps_mode) {
		epta_ps_mode = 1;
		msg.wlan_duration = EPTA_PS_WLAN_DURATION;
		msg.bt_duration = EPTA_PS_BT_DURATION;
		msg.hw_epta_enable = 0;
		return wsm_epta_cmd(hw_priv, &msg);
	} else if (!enable && epta_ps_mode) {
		epta_ps_mode = 0;
		msg.wlan_duration = wlan_duration_cfg;
		msg.bt_duration = bt_duration_cfg;
		msg.hw_epta_enable = 0;
		return wsm_epta_cmd(hw_priv, &msg);
	}

	return 0;
}

int coex_epta_set_connect(struct bes2600_common *hw_priv, int wlan_duration, int bt_duration, int epta)
{
	struct wsm_epta_msg msg;
	if (!hw_priv) {
		bes2600_dbg(BES2600_DBG_EPTA, "hw_priv is NULL\n");
		return -1;
	}
	if (epta != 4) {
		msg.wlan_duration = (wlan_duration_cfg >= wlan_duration) ? wlan_duration_cfg : wlan_duration;
		msg.bt_duration = (wlan_duration_cfg >= wlan_duration) ? bt_duration_cfg : bt_duration;
	} else {
		msg.wlan_duration = wlan_duration;
		msg.bt_duration = bt_duration;
	}
	msg.hw_epta_enable = epta;
	return wsm_epta_cmd(hw_priv, &msg);
}

/* TDD mode conn status change */
void coex_set_wifi_conn(struct bes2600_common *hw_priv, uint8_t connect_status)
{
	if (connect_status != EPTA_STATE_WIFI_SCAN_COMP) {
		if (epta_conn_state == connect_status) {
			bes2600_dbg(BES2600_DBG_EPTA, "same connect_status:%d\r", connect_status);
			return;
		}
	}

	if (connect_status == EPTA_STATE_WIFI_GOT_IP) {
		if (epta_conn_state == EPTA_STATE_WIFI_DISCONNECTED || epta_conn_state == EPTA_STATE_WIFI_CONNECTING) {
			bes2600_dbg(BES2600_DBG_EPTA, "ignore got ip in disconnected\r");
			return;
		}
	}
	epta_conn_state = connect_status;

	bes2600_dbg(BES2600_DBG_EPTA, "%s connect_status=%d coex_mode=%d\r", __func__, connect_status, g_coex_mode);
	if (g_coex_mode &  WIFI_COEX_MODE_FDD_BIT) {
		if (g_coex_mode &  WIFI_COEX_MODE_FDD_HYBRID_BIT) {
			if (connect_status == EPTA_STATE_WIFI_CONNECTED) {
				coex_epta_set_connect(hw_priv, wlan_duration_cfg, bt_duration_cfg, 3);
			} else if (connect_status == EPTA_STATE_WIFI_DISCONNECTED) {
				coex_epta_recover(hw_priv, EPTA_FREEZE_ALL); // wifi disconect need to recover all requests
				/* HYBRID MODE: if wlan is disconnect, default use hw epta */
				coex_epta_set_connect(hw_priv, 100000, 0, 1);
			}
		} else {
			if (connect_status == EPTA_STATE_WIFI_DISCONNECTED) {
				coex_epta_recover(hw_priv, EPTA_FREEZE_ALL); // wifi disconect need to recover all requests
				coex_epta_set_connect(hw_priv, 100000, 0, 1);
			}
		}
	} else {
		int wlan_tdd_duration = EPTA_TDD_CONNECT_WIFI;
		int bt_tdd_duration = EPTA_TDD_CONNECT_BT;

		/* if wlan_duration_cfg>　EPTA_TDD_CONNECT_WIFI; chose wlan_duration_cfg, in TDD mode */
		if (wlan_duration_cfg > EPTA_TDD_CONNECT_WIFI) {
			wlan_tdd_duration = wlan_duration_cfg;
			bt_tdd_duration = bt_duration_cfg;
		}
		if (connect_status == EPTA_STATE_WIFI_CONNECTED) {
			coex_epta_set_connect(hw_priv, wlan_duration_cfg, bt_duration_cfg, 3);
		} else if (connect_status == EPTA_STATE_WIFI_SCANNING) {
			/* in scan status, only valid param 0, others wlan_tdd_duration,bt_tdd_duratio is invalid */
			coex_epta_freeze(hw_priv, wlan_duration_cfg, EPTA_FREEZE_SCANNING);
		} else if (connect_status == EPTA_STATE_WIFI_SCAN_COMP) {
			coex_epta_set_connect(hw_priv, wlan_duration_cfg, bt_duration_cfg, 0);
		} else if (connect_status == EPTA_STATE_WIFI_GOT_IP) {
			coex_epta_set_connect(hw_priv, 2000, 80000, 3);
			coex_epta_recover(hw_priv, EPTA_FREEZE_SCANNING | EPTA_FREEZE_CONNECTING);
		} else if (connect_status == EPTA_STATE_WIFI_CONNECTING) {
			coex_epta_freeze(hw_priv, wlan_tdd_duration, EPTA_FREEZE_CONNECTING);
			if (bt_duration_cfg > 50000) //bt audio
				coex_epta_set_connect(hw_priv, 30000, 10000, 4);
		} else if (connect_status == EPTA_STATE_WIFI_DISCONNECTED) {
			coex_epta_recover(hw_priv, EPTA_FREEZE_ALL); // wifi disconect need to recover all requests
			/* TDD MODE: if wlan is disconnect, default use hw epta */
			// coex_epta_set_connect(hw_priv, 100000, 0, 1);
		} else {
			/* do nothing */
		}
	}
}

bool coex_is_wifi_inactive(void)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s, epta_conn_state:%d", __FUNCTION__, epta_conn_state);
	return epta_conn_state == EPTA_STATE_WIFI_DISCONNECTED;
}
/*
 * coex_set_epta_tts
 * @tts_state: 0 - tts start, 1 - tts end
 */
void coex_set_epta_tts(struct bes2600_common *hw_priv, uint32_t tts_state)
{
	if (EPTA_MODE_CFG == 0) {
		if (tts_state) {
			coex_epta_recover(hw_priv, EPTA_FREEZE_TTS);
		} else {
			coex_epta_freeze(hw_priv, 50000, EPTA_FREEZE_TTS);
		}
	}
}

void coex_set_epta_thp(struct bes2600_common *hw_priv, uint32_t total_bps)
{
	int epta_adjust_inv = 3;
	int wlan_tp_low;

	if (coex_fdd_mode && epta_conn_state >= EPTA_STATE_WIFI_GOT_IP)
		return;

	//bes2600_dbg(BES2600_DBG_EPTA, "coex_set_epta_thp %d bt_state %d epta_freeze_bitmap=%d epta_adjust_cnt=%d coex_ps_en=%d fw=%d\n",
	//       total_bps, coex_bt_state, epta_freeze_bitmap, epta_adjust_cnt, coex_ps_en, epta_freezed_wlan_duration_cfg);

	/* sniffer mode always work with ble and tts, need adjust more quickly */
	// wlan_tp_low = netdev_sniffer_get_stat() ? EPTA_WLAN_TP_LOW : 500;
	wlan_tp_low = 500;

	/* only need adjust in sw epta mode */
	if (EPTA_MODE_CFG != 0)
		return;

	if ((coex_bt_state == 0) && (total_bps > EPTA_WLAN_TP_HIGH)) {
		coex_epta_freeze(hw_priv, EPTA_ADJUST_WLAN_DURATION_HIGH, EPTA_FREEZE_THP);
	} else if (total_bps > EPTA_WLAN_TP_MEDIUM) {
		coex_epta_freeze(hw_priv, EPTA_ADJUST_WLAN_DURATION_MEDIUM, EPTA_FREEZE_THP);
	} else if (total_bps > wlan_tp_low) {
		coex_epta_freeze(hw_priv, EPTA_ADJUST_WLAN_DURATION_LOW, EPTA_FREEZE_THP);
	} else {
		if ((epta_freeze_bitmap & (1 << EPTA_FREEZE_THP)) &&
			(((++epta_adjust_cnt) % epta_adjust_inv) == 0)) {
			// recover if wifi idle 3 secs
			epta_adjust_cnt = 0;
			coex_epta_recover(hw_priv, EPTA_FREEZE_THP);
		} else if (coex_ps_en && !epta_freeze_bitmap) {
			if ((total_bps > EPTA_WLAN_TP_PS)) {
				coex_epta_ps(hw_priv, 0);
				epta_adjust_cnt = 0;
			} else if ((total_bps < EPTA_WLAN_TP_PS) &&
				   (((++epta_adjust_cnt) % epta_adjust_inv) == 0)) {
				coex_epta_ps(hw_priv, 1);
			}
		}
	}
}

// void coex_band_update(struct bes2600_common *hw_priv, enum nl80211_band band)
// {
// 	bes2600_info(BES2600_DBG_EPTA, "coex_band_update band:%u\n", (uint32_t)band);
// }

void coex_rssi_update(struct bes2600_common *hw_priv, int rssi, int channel, int connected)
{
	bool fdd_en = 0;

	if (g_coex_mode == 0 || // tdd
		g_coex_mode == (WIFI_COEX_MODE_FDD_HYBRID_BIT | WIFI_COEX_MODE_FDD_BIT)) {

		bes2600_info(BES2600_DBG_EPTA, "coex_rssi_update rssi:%d, ch:%d, con:%d\n",
			rssi, channel, connected);
		if (channel > 14) {
			fdd_en = 1;
		///TODO: HYBRID mode
		// } else if (rssi >= COEX_FDD_RSSI_THR) {
		// 	fdd_en = 1;
		// } else if (rssi < COEX_TDD_RSSI_THR) {
		// 	fdd_en = 0;
		}

		if (fdd_en != coex_fdd_mode) {
			coex_fdd_mode = fdd_en;
			coex_set_epta_params(hw_priv, wlan_duration_cfg, bt_duration_cfg, hw_epta_enable_cfg);
		}
	}
}

void coex_set_bt_state(struct bes2600_common *hw_priv, int state)
{
	bes2600_info(BES2600_DBG_EPTA, "coex_set_bt_state %d\n", state);
	coex_bt_state = state;
}

void coex_peroid_handle(struct bes2600_common *hw_priv, int connected, int rssi, int channel, uint32_t tp)
{
	if (connected) {
		/*
		 * Adjust wifi/bt duration dynamically according to throughput for a better performance;
		 */
		coex_set_epta_thp(hw_priv, tp);
	}

	if (g_coex_mode == 0 || // tdd
		g_coex_mode == (WIFI_COEX_MODE_FDD_HYBRID_BIT | WIFI_COEX_MODE_FDD_BIT)) {
		coex_rssi_update(hw_priv, rssi, channel, connected);
	}
}

/*
 * set fdd or fdd hybrid
 * 1: fdd
 * 0: fddhybrid
 */
void coex_set_fdd_mode(bool fdd_mode)
{
	if (g_coex_mode == 0 || // tdd
		g_coex_mode == (WIFI_COEX_MODE_FDD_HYBRID_BIT | WIFI_COEX_MODE_FDD_BIT)) { //hybrid
		bes2600_dbg(BES2600_DBG_EPTA, "%s, %d", __FUNCTION__, fdd_mode);
		coex_fdd_mode = fdd_mode;
	}
}

bool coex_is_fdd_mode(void)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s, %d", __FUNCTION__, coex_fdd_mode);
	return coex_fdd_mode;
}

bool coex_is_bt_a2dp(void)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s, coex_bt_state:%d", __FUNCTION__, coex_bt_state);
	return coex_bt_state == 3;
}

bool coex_is_bt_inactive(void)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s, coex_bt_state:%d", __FUNCTION__, coex_bt_state);
	return coex_bt_state == 0;
}

int coex_init_mode(struct bes2600_common *hw_priv, int coex_mode)
{
	bes2600_info(BES2600_DBG_EPTA, "coex_init_mode coex_mode %d\n", coex_mode);

	g_coex_mode = coex_mode;

	if (coex_mode & WIFI_COEX_MODE_FDD_BIT)
		coex_fdd_mode = true;
	else
		coex_fdd_mode = false;

	coex_wifi_bt_ts_thread_init(hw_priv);
	return 0;
}

int coex_deinit_mode(struct bes2600_common *hw_priv)
{
	bes2600_info(BES2600_DBG_EPTA, "coex_deinit_mode\n");

	coex_wifi_bt_ts_thread_deinit(hw_priv);

	return 0;
}

int coex_start(struct bes2600_common *hw_priv)
{
	bes2600_info(BES2600_DBG_EPTA, "%s\n", __FUNCTION__);

	coex_ps_en = false;
	if (g_coex_mode & WIFI_COEX_MODE_FDD_BIT)
		coex_fdd_mode = true;
	else
		coex_fdd_mode = false;
	epta_conn_state = 0xff;
	epta_freeze_bitmap = 0;
	epta_freezed_wlan_duration_cfg = 0;
	wlan_duration_cfg = 20000;
	bt_duration_cfg = 80000;
	hw_epta_enable_cfg = 0;
	epta_ps_mode = 0;
	epta_adjust_cnt = 0;
	coex_bt_state = 0;

	return 0;
}

int coex_stop(struct bes2600_common *hw_priv)
{
	bes2600_info(BES2600_DBG_EPTA, "%s\n", __FUNCTION__);
	return 0;
}