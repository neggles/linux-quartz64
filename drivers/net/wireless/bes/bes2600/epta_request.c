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
#include <linux/kernel.h>
#include <linux/list.h>

#include "epta_coex.h"
#include "epta_request.h"

#define EPTA_PERIOD_TIME					102400

#define BT_TIME_MAX							80000

#define BT_SHUTDOWN_TIME					0
#define BT_SHUTDOWN_MIN_TIME				0
#define BT_DISCONNECTED_TIME				0
#define BT_DISCONNECTED_MIN_TIME			0
#define BT_CONNECTING_TIME					60000
#define BT_CONNECTING_MIN_TIME				0
#define BT_CONNECTED_TIME					0
#define BT_CONNECTED_MIN_TIME				25000
#define BT_CONNECTED_SNIFF_TIME				0
#define BT_CONNECTED_SNIFF_MIN_TIME			20000

#define BT_BOTHSCAN_DISABLE_TIME			0
#define BT_BOTHSCAN_DISABLE_MIN_TIME		0
#define BT_BOTHSCAN_ENABLE_TIME				0
#define BT_BOTHSCAN_ENABLE_MIN_TIME			20000
#define BT_PSCAN_ENABLE_TIME				0
#define BT_PSCAN_ENABLE_MIN_TIME			20000
#define BT_ISCAN_ENABLE_TIME				0
#define BT_ISCAN_ENABLE_MIN_TIME			20000

#define BT_AUDIO_NONE_TIME					0
#define BT_AUDIO_NONE_MIN_TIME				0
#define BT_AUDIO_A2DP_TIME					60000
#define BT_AUDIO_A2DP_MIN_TIME				0
#define BT_AUDIO_SCO_TIME					80000
#define BT_AUDIO_SCO_MIN_TIME				0

#define BT_INQ_START_TIME					20000
#define BT_INQ_START_MIN_TIME				30000
#define BT_INQ_STOP_TIME					0
#define BT_INQ_STOP_MIN_TIME				0

#define BT_LE_SCAN_START_TIME				20000
#define BT_LE_SCAN_START_MIN_TIME			30000
#define BT_LE_SCAN_STOP_TIME				0
#define BT_LE_SCAN_STOP_MIN_TIME			0

#define BT_LE_ADV_START_TIME				10000
#define BT_LE_ADV_START_MIN_TIME			30000
#define BT_LE_ADV_STOP_TIME					0
#define BT_LE_ADV_STOP_MIN_TIME				0

#define BT_LE_CONNECTED_TIME				0
#define BT_LE_CONNECTED_MIN_TIME			20000
#define BT_LE_DISCONNECTED_TIME				0
#define BT_LE_DISCONNECTED_MIN_TIME			0

// BIT[2:0]
#define BT_REQUEST_STATUS_SHIFT       0
#define BT_REQUEST_STATUS_MASK        (0x7 << BT_REQUEST_STATUS_SHIFT)
#define BT_REQUEST_STATUS_VALUE(n)    (((n) & BT_REQUEST_STATUS_MASK) >> BT_REQUEST_STATUS_SHIFT)

// BIT[5:3]
#define BT_REQUEST_SCAN_SHIFT         3
#define BT_REQUEST_SCAN_MASK          (0x7 << BT_REQUEST_SCAN_SHIFT)
#define BT_REQUEST_SCAN_VALUE(n)      (((n) & BT_REQUEST_SCAN_MASK) >> BT_REQUEST_SCAN_SHIFT)

// BIT[8:6]
#define BT_REQUEST_AUDIO_SHIFT        6
#define BT_REQUEST_AUDIO_MASK         (0x7 << BT_REQUEST_AUDIO_SHIFT)
#define BT_REQUEST_AUDIO_VALUE(n)     (((n) & BT_REQUEST_AUDIO_MASK) >> BT_REQUEST_AUDIO_SHIFT)

// BIT[10:9]
#define BT_REQUEST_INQ_SHIFT          9
#define BT_REQUEST_INQ_MASK           (0x3 << BT_REQUEST_INQ_SHIFT)
#define BT_REQUEST_INQ_VALUE(n)       (((n) & BT_REQUEST_INQ_MASK) >> BT_REQUEST_INQ_SHIFT)

// BIT[12:11]
#define BT_REQUEST_LE_SCAN_SHIFT      11
#define BT_REQUEST_LE_SCAN_MASK       (0x3 << BT_REQUEST_LE_SCAN_SHIFT)
#define BT_REQUEST_LE_SCAN_VALUE(n)   (((n) & BT_REQUEST_LE_SCAN_MASK) >> BT_REQUEST_LE_SCAN_SHIFT)

// BIT[15:13]
#define BT_REQUEST_LE_ADV_SHIFT       13
#define BT_REQUEST_LE_ADV_MASK        (0x7 << BT_REQUEST_LE_ADV_SHIFT)
#define BT_REQUEST_LE_ADV_VALUE(n)    (((n) & BT_REQUEST_LE_ADV_MASK) >> BT_REQUEST_LE_ADV_SHIFT)

// BIT[17:16]
#define BT_REQUEST_LE_STATUS_SHIFT    16
#define BT_REQUEST_LE_STATUS_MASK     (0x3 << BT_REQUEST_LE_STATUS_SHIFT)
#define BT_REQUEST_LE_STATUS_VALUE(n) (((n) & BT_REQUEST_LE_STATUS_MASK) >> BT_REQUEST_LE_STATUS_SHIFT)

typedef enum {
	BWIFI_BT_STATUS_SHUTDOWN          = 0,
	BWIFI_BT_STATUS_DISCONNECTED      = 1,
	BWIFI_BT_STATUS_CONNECTING        = 2,
	BWIFI_BT_STATUS_CONNECTED_SNIFF   = 3,//
	BWIFI_BT_STATUS_CONNECTED         = 4,//
} BWIFI_BT_STATUS_T;

typedef enum {
	BWIFI_BT_BOTHSCAN_DISABLE         = 0,
	BWIFI_BT_BOTHSCAN_ENABLE          = 1,
	BWIFI_BT_PSCAN_ENABLE             = 2,
	BWIFI_BT_ISCAN_ENABLE             = 3,
} BWIFI_BT_SCAN_T;

typedef enum {
	BWIFI_BT_AUDIO_NONE               = 0,
	BWIFI_BT_AUDIO_A2DP               = 1,
	BWIFI_BT_AUDIO_SCO                = 2,
} BWIFI_BT_AUDIO_T;

typedef enum {
	BWIFI_BT_INQ_STOP                 = 0,//
	BWIFI_BT_INQ_START                = 1,//
} BWIFI_BT_INQ_T;

typedef enum {
	BWIFI_LE_SCAN_STOP                = 0,//
	BWIFI_LE_SCAN_START               = 1,//
} BWIFI_BT_LE_SCAN_T;

typedef enum {
	BWIFI_LE_ADV_STOP                 = 0,//
	BWIFI_LE_ADV_START                = 1,//
} BWIFI_BT_LE_ADV_T;

typedef enum {
	BWIFI_LE_DISCONNECTED             = 0,//
	BWIFI_LE_CONNECTED                = 1,//
} BWIFI_BT_LE_STATUS_T;

enum COEX_BT_OPER_T {
	COEX_BT_OPER_STATUS,
	COEX_BT_OPER_SCAN,
	COEX_BT_OPER_AUDIO,
	COEX_BT_OPER_INQ,
	COEX_BT_OPER_LE_SCAN,
	COEX_BT_OPER_LE_ADV,
	COEX_BT_OPER_LE_STATUS,

	COEX_BT_OPER_NUM,
};

union COEX_BT_OPER_TYPE_T {
	BWIFI_BT_STATUS_T status;
	BWIFI_BT_SCAN_T scan;
	BWIFI_BT_AUDIO_T audio;
	BWIFI_BT_INQ_T inq;
	BWIFI_BT_LE_SCAN_T le_scan;
	BWIFI_BT_LE_ADV_T le_adv;
	BWIFI_BT_LE_STATUS_T le_status;
};

struct COEX_BT_OPER_TIME_T {
	enum COEX_BT_OPER_T oper;
	union COEX_BT_OPER_TYPE_T type;
	uint32_t time;
	uint32_t min_time;
};

struct COEX_BT_OPER_TIME_T g_coex_bt_oper[COEX_BT_OPER_NUM];

static void coex_bt_time_init(void)
{
	memset(g_coex_bt_oper, 0, sizeof(g_coex_bt_oper));
	g_coex_bt_oper[COEX_BT_OPER_STATUS].type.status = BWIFI_BT_STATUS_SHUTDOWN;
	g_coex_bt_oper[COEX_BT_OPER_SCAN].type.scan = BWIFI_BT_BOTHSCAN_DISABLE;
	g_coex_bt_oper[COEX_BT_OPER_AUDIO].type.audio = BWIFI_BT_AUDIO_NONE;
	g_coex_bt_oper[COEX_BT_OPER_INQ].type.inq = BWIFI_BT_INQ_STOP;
	g_coex_bt_oper[COEX_BT_OPER_LE_SCAN].type.le_scan = BWIFI_LE_SCAN_STOP;
	g_coex_bt_oper[COEX_BT_OPER_LE_ADV].type.le_adv = BWIFI_LE_ADV_STOP;
	g_coex_bt_oper[COEX_BT_OPER_LE_STATUS].type.le_status = BWIFI_LE_DISCONNECTED;
}

static uint32_t coex_calc_bt_time(void)
{
	uint32_t i;
	uint32_t time = 0, min_time = 0;

	for (i = 0; i < COEX_BT_OPER_NUM; ++i) {
		time += g_coex_bt_oper[i].time;
		if (min_time < g_coex_bt_oper[i].min_time)
			min_time = g_coex_bt_oper[i].min_time;
	}

	bes2600_dbg(BES2600_DBG_EPTA, "%s time:%u, min_time:%u", __func__, time, min_time);
	time = time < min_time ? min_time : time;
	return time < BT_TIME_MAX ? time : BT_TIME_MAX;
}

void coex_calc_wifi_scan_time(uint32_t *min_chan, uint32_t *max_chan)
{
	uint32_t time = coex_calc_bt_time();

	if (time == 0) {
		*min_chan = 110;
		*max_chan = 110;
	} else if (time < 40000) {
		*min_chan = 50;
		*max_chan = 110;
	} else if (time < 60000) {
		*min_chan = 40;
		*max_chan = 110;
	} else if (time < 80000) {
		*min_chan = 30;
		*max_chan = 120;
	} else {
		*min_chan = 30;
		*max_chan = 130;
	}
}

static void coex_bt_state_notify(struct bes2600_common *hw_priv)
{
	int32_t wifi_dur, bt_dur, mode;

	bt_dur = coex_calc_bt_time();
	wifi_dur = EPTA_PERIOD_TIME - bt_dur;
	mode = 0;
	coex_set_epta_params(hw_priv, wifi_dur, bt_dur, mode);
}

static void coex_bt_oper_status(struct bes2600_common *hw_priv, BWIFI_BT_STATUS_T type)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s type:%d", __func__, type);

	switch (type) {
	case BWIFI_BT_STATUS_SHUTDOWN:
		coex_bt_time_init();
		break;
	case BWIFI_BT_STATUS_DISCONNECTED:
		g_coex_bt_oper[COEX_BT_OPER_STATUS].type.status = BWIFI_BT_STATUS_DISCONNECTED;
		g_coex_bt_oper[COEX_BT_OPER_STATUS].time = BT_DISCONNECTED_TIME;
		g_coex_bt_oper[COEX_BT_OPER_STATUS].min_time = BT_DISCONNECTED_MIN_TIME;
		g_coex_bt_oper[COEX_BT_OPER_AUDIO].type.audio = BWIFI_BT_AUDIO_NONE;
		g_coex_bt_oper[COEX_BT_OPER_AUDIO].time = BT_AUDIO_NONE_TIME;
		g_coex_bt_oper[COEX_BT_OPER_AUDIO].min_time = BT_AUDIO_NONE_MIN_TIME;
		break;
	case BWIFI_BT_STATUS_CONNECTING:
		g_coex_bt_oper[COEX_BT_OPER_STATUS].type.status = BWIFI_BT_STATUS_CONNECTING;
		g_coex_bt_oper[COEX_BT_OPER_STATUS].time = BT_CONNECTING_TIME;
		g_coex_bt_oper[COEX_BT_OPER_STATUS].min_time = BT_CONNECTING_MIN_TIME;
		g_coex_bt_oper[COEX_BT_OPER_AUDIO].type.audio = BWIFI_BT_AUDIO_NONE;
		g_coex_bt_oper[COEX_BT_OPER_AUDIO].time = BT_AUDIO_NONE_TIME;
		g_coex_bt_oper[COEX_BT_OPER_AUDIO].min_time = BT_AUDIO_NONE_MIN_TIME;
		break;
	case BWIFI_BT_STATUS_CONNECTED:
		g_coex_bt_oper[COEX_BT_OPER_STATUS].type.status = BWIFI_BT_STATUS_CONNECTED;
		g_coex_bt_oper[COEX_BT_OPER_STATUS].time = BT_CONNECTED_TIME;
		g_coex_bt_oper[COEX_BT_OPER_STATUS].min_time = BT_CONNECTED_MIN_TIME;
		break;
	case BWIFI_BT_STATUS_CONNECTED_SNIFF:
		g_coex_bt_oper[COEX_BT_OPER_STATUS].type.status = BWIFI_BT_STATUS_CONNECTED_SNIFF;
		g_coex_bt_oper[COEX_BT_OPER_STATUS].time = BT_CONNECTED_SNIFF_TIME;
		g_coex_bt_oper[COEX_BT_OPER_STATUS].min_time = BT_CONNECTED_SNIFF_MIN_TIME;
		break;
	default:
		bes2600_err(BES2600_DBG_EPTA, "%s type error:%d", __func__, type);
		break;
	}
}

static void coex_bt_oper_scan(struct bes2600_common *hw_priv, BWIFI_BT_SCAN_T type)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s type:%d", __func__, type);

	switch (type) {
	case BWIFI_BT_BOTHSCAN_DISABLE:
		g_coex_bt_oper[COEX_BT_OPER_SCAN].type.scan = BWIFI_BT_BOTHSCAN_DISABLE;
		g_coex_bt_oper[COEX_BT_OPER_SCAN].time = BT_BOTHSCAN_DISABLE_TIME;
		g_coex_bt_oper[COEX_BT_OPER_SCAN].min_time = BT_BOTHSCAN_DISABLE_MIN_TIME;
		break;
	case BWIFI_BT_BOTHSCAN_ENABLE:
		g_coex_bt_oper[COEX_BT_OPER_SCAN].type.scan = BWIFI_BT_BOTHSCAN_ENABLE;
		g_coex_bt_oper[COEX_BT_OPER_SCAN].time = BT_BOTHSCAN_ENABLE_TIME;
		g_coex_bt_oper[COEX_BT_OPER_SCAN].min_time = BT_BOTHSCAN_ENABLE_MIN_TIME;
		break;
	case BWIFI_BT_PSCAN_ENABLE:
		g_coex_bt_oper[COEX_BT_OPER_SCAN].type.scan = BWIFI_BT_PSCAN_ENABLE;
		g_coex_bt_oper[COEX_BT_OPER_SCAN].time = BT_PSCAN_ENABLE_TIME;
		g_coex_bt_oper[COEX_BT_OPER_SCAN].min_time = BT_PSCAN_ENABLE_MIN_TIME;
		break;
	case BWIFI_BT_ISCAN_ENABLE:
		g_coex_bt_oper[COEX_BT_OPER_SCAN].type.scan = BWIFI_BT_ISCAN_ENABLE;
		g_coex_bt_oper[COEX_BT_OPER_SCAN].time = BT_ISCAN_ENABLE_TIME;
		g_coex_bt_oper[COEX_BT_OPER_SCAN].min_time = BT_ISCAN_ENABLE_MIN_TIME;
		break;
	default:
		bes2600_err(BES2600_DBG_EPTA, "%s type error:%d", __func__, type);
		break;
	}
}

static void coex_bt_oper_audio(struct bes2600_common *hw_priv, BWIFI_BT_AUDIO_T type)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s type:%d", __func__, type);

	switch (type) {
	case BWIFI_BT_AUDIO_NONE:
		g_coex_bt_oper[COEX_BT_OPER_AUDIO].type.audio = BWIFI_BT_AUDIO_NONE;
		g_coex_bt_oper[COEX_BT_OPER_AUDIO].time = BT_AUDIO_NONE_TIME;
		g_coex_bt_oper[COEX_BT_OPER_AUDIO].min_time = BT_AUDIO_NONE_MIN_TIME;
		break;
	case BWIFI_BT_AUDIO_A2DP:
		g_coex_bt_oper[COEX_BT_OPER_AUDIO].type.audio = BWIFI_BT_AUDIO_A2DP;
		g_coex_bt_oper[COEX_BT_OPER_AUDIO].time = BT_AUDIO_A2DP_TIME;
		g_coex_bt_oper[COEX_BT_OPER_AUDIO].min_time = BT_AUDIO_A2DP_MIN_TIME;
		break;
	case BWIFI_BT_AUDIO_SCO:
		g_coex_bt_oper[COEX_BT_OPER_AUDIO].type.audio = BWIFI_BT_AUDIO_SCO;
		g_coex_bt_oper[COEX_BT_OPER_AUDIO].time = BT_AUDIO_SCO_TIME;
		g_coex_bt_oper[COEX_BT_OPER_AUDIO].min_time = BT_AUDIO_SCO_MIN_TIME;
		break;
	default:
		bes2600_err(BES2600_DBG_EPTA, "%s type error:%d", __func__, type);
		break;
	}
}

static void coex_bt_oper_inq(struct bes2600_common *hw_priv, BWIFI_BT_INQ_T type)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s type:%d", __func__, type);

	switch (type) {
	case BWIFI_BT_INQ_START:
		g_coex_bt_oper[COEX_BT_OPER_INQ].type.inq = BWIFI_BT_INQ_START;
		g_coex_bt_oper[COEX_BT_OPER_INQ].time = BT_INQ_START_TIME;
		g_coex_bt_oper[COEX_BT_OPER_INQ].min_time = BT_INQ_START_MIN_TIME;
		break;
	case BWIFI_BT_INQ_STOP:
		g_coex_bt_oper[COEX_BT_OPER_INQ].type.inq = BWIFI_BT_INQ_STOP;
		g_coex_bt_oper[COEX_BT_OPER_INQ].time = BT_INQ_STOP_TIME;
		g_coex_bt_oper[COEX_BT_OPER_INQ].min_time = BT_INQ_STOP_MIN_TIME;
		break;
	default:
		bes2600_err(BES2600_DBG_EPTA, "%s type error:%d", __func__, type);
		break;
	}
}

static void coex_bt_oper_le_scan(struct bes2600_common *hw_priv, BWIFI_BT_LE_SCAN_T type)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s type:%d", __func__, type);

	switch (type) {
	case BWIFI_LE_SCAN_START:
		g_coex_bt_oper[COEX_BT_OPER_LE_SCAN].type.le_scan = BWIFI_LE_SCAN_START;
		g_coex_bt_oper[COEX_BT_OPER_LE_SCAN].time = BT_LE_SCAN_START_TIME;
		g_coex_bt_oper[COEX_BT_OPER_LE_SCAN].min_time = BT_LE_SCAN_START_MIN_TIME;
		break;
	case BWIFI_LE_SCAN_STOP:
		g_coex_bt_oper[COEX_BT_OPER_LE_SCAN].type.le_scan = BWIFI_LE_SCAN_STOP;
		g_coex_bt_oper[COEX_BT_OPER_LE_SCAN].time = BT_LE_SCAN_STOP_TIME;
		g_coex_bt_oper[COEX_BT_OPER_LE_SCAN].min_time = BT_LE_SCAN_STOP_MIN_TIME;
		break;
	default:
		bes2600_err(BES2600_DBG_EPTA, "%s type error:%d", __func__, type);
		break;
	}
}

static void coex_bt_oper_le_adv(struct bes2600_common *hw_priv, BWIFI_BT_LE_ADV_T type)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s type:%d", __func__, type);

	switch (type) {
	case BWIFI_LE_ADV_START:
		g_coex_bt_oper[COEX_BT_OPER_LE_ADV].type.le_adv = BWIFI_LE_ADV_START;
		g_coex_bt_oper[COEX_BT_OPER_LE_ADV].time = BT_LE_ADV_START_TIME;
		g_coex_bt_oper[COEX_BT_OPER_LE_ADV].min_time = BT_LE_ADV_START_MIN_TIME;
		break;
	case BWIFI_LE_ADV_STOP:
		g_coex_bt_oper[COEX_BT_OPER_LE_ADV].type.le_adv = BWIFI_LE_ADV_STOP;
		g_coex_bt_oper[COEX_BT_OPER_LE_ADV].time = BT_LE_ADV_STOP_TIME;
		g_coex_bt_oper[COEX_BT_OPER_LE_ADV].min_time = BT_LE_ADV_STOP_MIN_TIME;
		break;
	default:
		bes2600_err(BES2600_DBG_EPTA, "%s type error:%d", __func__, type);
		break;
	}
}

static void coex_bt_oper_le_status(struct bes2600_common *hw_priv, BWIFI_BT_LE_STATUS_T type)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s type:%d", __func__, type);

	switch (type) {
	case BWIFI_LE_CONNECTED:
		g_coex_bt_oper[COEX_BT_OPER_LE_STATUS].type.le_status = BWIFI_LE_CONNECTED;
		g_coex_bt_oper[COEX_BT_OPER_LE_STATUS].time = BT_LE_CONNECTED_TIME;
		g_coex_bt_oper[COEX_BT_OPER_LE_STATUS].min_time = BT_LE_CONNECTED_MIN_TIME;
		break;
	case BWIFI_LE_DISCONNECTED:
		g_coex_bt_oper[COEX_BT_OPER_LE_STATUS].type.le_status = BWIFI_LE_DISCONNECTED;
		g_coex_bt_oper[COEX_BT_OPER_LE_STATUS].time = BT_LE_DISCONNECTED_TIME;
		g_coex_bt_oper[COEX_BT_OPER_LE_STATUS].min_time = BT_LE_DISCONNECTED_MIN_TIME;
		break;
	default:
		bes2600_err(BES2600_DBG_EPTA, "%s type error:%d", __func__, type);
		break;
	}
}

static int coex_wifi_state_notify(struct bes2600_common *hw_priv, enum bwifi_epta_state state)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s state:%d", __func__, state);
	switch (state) {
	case EPTA_STATE_WIFI_DISCONNECTED:
		coex_set_wifi_conn(hw_priv, state);
		break;
	case EPTA_STATE_WIFI_SCANNING:
		coex_set_wifi_conn(hw_priv, state);
		break;
	case EPTA_STATE_WIFI_SCAN_COMP:
		coex_set_wifi_conn(hw_priv, state);
		break;
	case EPTA_STATE_WIFI_CONNECTING:
		coex_set_wifi_conn(hw_priv, state);
		break;
	case EPTA_STATE_WIFI_CONNECTED:
		coex_set_wifi_conn(hw_priv, state);
		break;
	case EPTA_STATE_WIFI_GOT_IP:
		coex_set_wifi_conn(hw_priv, state);
		break;
	case EPTA_STATE_WIFI_TTS_START:
		coex_set_epta_tts(hw_priv, 0);
		break;
	case EPTA_STATE_WIFI_TTS_END:
		coex_set_epta_tts(hw_priv, 1);
		break;
	default:
		return -1;
	}
	return 0;
}

static void coex_wifi_idle(struct bes2600_common *hw_priv, BWIFI_STATUS_T value)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s", __func__);
	coex_set_fdd_mode(false);
	coex_wifi_state_notify(hw_priv, EPTA_STATE_WIFI_DISCONNECTED);
}

static void coex_wifi_scanning(struct bes2600_common *hw_priv, BWIFI_STATUS_T value)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s", __func__);
	coex_set_fdd_mode(false); //scan use tdd
	coex_wifi_state_notify(hw_priv, EPTA_STATE_WIFI_SCANNING);
}

static void coex_wifi_scan_comp(struct bes2600_common *hw_priv, BWIFI_STATUS_T value)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s", __func__);
	coex_wifi_state_notify(hw_priv, EPTA_STATE_WIFI_SCAN_COMP);
}

static void coex_wifi_connecting(struct bes2600_common *hw_priv, BWIFI_STATUS_T value)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s", __func__);
	coex_set_fdd_mode(false);
	coex_wifi_state_notify(hw_priv, EPTA_STATE_WIFI_CONNECTING);
}

static void coex_wifi_connecting_5g(struct bes2600_common *hw_priv, BWIFI_STATUS_T value)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s", __func__);
	coex_set_fdd_mode(true);
	coex_wifi_state_notify(hw_priv, EPTA_STATE_WIFI_CONNECTING);
}

static void coex_wifi_connected(struct bes2600_common *hw_priv, BWIFI_STATUS_T value)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s", __func__);
	coex_wifi_state_notify(hw_priv, EPTA_STATE_WIFI_CONNECTED);
}

static void coex_wifi_connected_5g(struct bes2600_common *hw_priv, BWIFI_STATUS_T value)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s", __func__);
	coex_set_fdd_mode(true);
	coex_wifi_state_notify(hw_priv, EPTA_STATE_WIFI_CONNECTED);
}

static void coex_wifi_got_ip(struct bes2600_common *hw_priv, BWIFI_STATUS_T value)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s", __func__);
	coex_wifi_state_notify(hw_priv, EPTA_STATE_WIFI_GOT_IP);
}

static void coex_wifi_got_ip_5g(struct bes2600_common *hw_priv, BWIFI_STATUS_T value)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s", __func__);
	coex_set_fdd_mode(true); // used for scan -> got ip 5g
	coex_wifi_state_notify(hw_priv, EPTA_STATE_WIFI_GOT_IP);
}

static void coex_wifi_disconnecting(struct bes2600_common *hw_priv, BWIFI_STATUS_T value)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s", __func__);
}

static void coex_wifi_disconnected(struct bes2600_common *hw_priv, BWIFI_STATUS_T value)
{
	bes2600_dbg(BES2600_DBG_EPTA, "%s", __func__);
	coex_set_fdd_mode(false);
	coex_wifi_state_notify(hw_priv, EPTA_STATE_WIFI_DISCONNECTED);
}

static int coex_wifi_bt_ts_request(struct bes2600_common *hw_priv, COEX_TS_TYPE_T type, uint32_t value)
{
	COEX_WIFI_BT_TS_T *wifi_bt_ts_event;

	bes2600_info(BES2600_DBG_EPTA, "%s type:%u, value:0x%x", __func__, type, value);

	if (atomic_read(&hw_priv->netdevice_start) == 0) {
		bes2600_info(BES2600_DBG_EPTA, "net down. skip");
		return 0;
	}

	/* called from spin lock vif_lock context */
	wifi_bt_ts_event = kmalloc(sizeof(COEX_WIFI_BT_TS_T), GFP_ATOMIC);
	if (wifi_bt_ts_event == NULL) {
		bes2600_err(BES2600_DBG_EPTA, "ts_event: malloc fail");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&wifi_bt_ts_event->node);
	wifi_bt_ts_event->type = type;
	wifi_bt_ts_event->value = value;

	spin_lock(&hw_priv->coex_event_lock);
	list_add_tail(&wifi_bt_ts_event->node, &hw_priv->coex_event_list);
	spin_unlock(&hw_priv->coex_event_lock);

	schedule_work(&hw_priv->coex_work);

	return 0;
}

void bbt_change_current_status(struct bes2600_common *hw_priv, uint32_t new_status)
{
	coex_wifi_bt_ts_request(hw_priv, COEX_TS_TYPE_BT, new_status);
}

void bwifi_change_current_status(struct bes2600_common *hw_priv, BWIFI_STATUS_T new_status)
{
	coex_wifi_bt_ts_request(hw_priv, COEX_TS_TYPE_WIFI, new_status);
}

static void coex_wifi_bt_ts_cb(struct bes2600_common *hw_priv, COEX_WIFI_BT_TS_T *evt)
{
	if (evt->type == COEX_TS_TYPE_BT) {
		coex_bt_oper_scan(hw_priv, (BWIFI_BT_SCAN_T)BT_REQUEST_SCAN_VALUE(evt->value));
		coex_bt_oper_audio(hw_priv, (BWIFI_BT_AUDIO_T)BT_REQUEST_AUDIO_VALUE(evt->value));
		coex_bt_oper_inq(hw_priv, (BWIFI_BT_INQ_T)BT_REQUEST_INQ_VALUE(evt->value));
		coex_bt_oper_le_scan(hw_priv, (BWIFI_BT_LE_SCAN_T)BT_REQUEST_LE_SCAN_VALUE(evt->value));
		coex_bt_oper_le_adv(hw_priv, (BWIFI_BT_LE_ADV_T)BT_REQUEST_LE_ADV_VALUE(evt->value));
		coex_bt_oper_le_status(hw_priv, (BWIFI_BT_LE_STATUS_T)BT_REQUEST_LE_STATUS_VALUE(evt->value));
		// process BT STATUS in the end
		coex_bt_oper_status(hw_priv, (BWIFI_BT_STATUS_T)BT_REQUEST_STATUS_VALUE(evt->value));
		coex_bt_state_notify(hw_priv);
	} else if (evt->type == COEX_TS_TYPE_WIFI) {
		switch (evt->value) {
		case BWIFI_STATUS_IDLE:
			coex_wifi_idle(hw_priv, (BWIFI_STATUS_T)evt->value);
			break;
		case BWIFI_STATUS_SCANNING:
			coex_wifi_scanning(hw_priv, (BWIFI_STATUS_T)evt->value);
			break;
		case BWIFI_STATUS_SCANNING_COMP:
			coex_wifi_scan_comp(hw_priv, (BWIFI_STATUS_T)evt->value);
			break;
		case BWIFI_STATUS_CONNECTING:
			coex_wifi_connecting(hw_priv, (BWIFI_STATUS_T)evt->value);
			break;
		case BWIFI_STATUS_CONNECTING_5G:
			coex_wifi_connecting_5g(hw_priv, (BWIFI_STATUS_T)evt->value);
			break;
		case BWIFI_STATUS_CONNECTED:
			coex_wifi_connected(hw_priv, (BWIFI_STATUS_T)evt->value);
			break;
		case BWIFI_STATUS_CONNECTED_5G:
			coex_wifi_connected_5g(hw_priv, (BWIFI_STATUS_T)evt->value);
			break;
		case BWIFI_STATUS_GOT_IP:
			coex_wifi_got_ip(hw_priv, (BWIFI_STATUS_T)evt->value);
			break;
		case BWIFI_STATUS_GOT_IP_5G:
			coex_wifi_got_ip_5g(hw_priv, (BWIFI_STATUS_T)evt->value);
			break;
		case BWIFI_STATUS_DISCONNECTING:
			coex_wifi_disconnecting(hw_priv, (BWIFI_STATUS_T)evt->value);
			break;
		case BWIFI_STATUS_DISCONNECTED:
			coex_wifi_disconnected(hw_priv, (BWIFI_STATUS_T)evt->value);
			break;
		default:
			bes2600_err(BES2600_DBG_EPTA, "UNKNOWN WIFI type %d", evt->value);
			break;
		}
	} else {
		bes2600_err(BES2600_DBG_EPTA, "UNKNOWN EPTA type %d, %d", evt->type, evt->value);
	}
}

static void coex_wifi_bt_ts_thread(struct work_struct *work)
{
	COEX_WIFI_BT_TS_T *coex_event;
	struct bes2600_common *hw_priv = container_of(work, struct bes2600_common, coex_work);

	spin_lock(&hw_priv->coex_event_lock);
	while (!list_empty(&hw_priv->coex_event_list)) {
		coex_event = list_first_entry(&hw_priv->coex_event_list, COEX_WIFI_BT_TS_T, node);
		spin_unlock(&hw_priv->coex_event_lock);
		coex_wifi_bt_ts_cb(hw_priv, coex_event);
		list_del(&coex_event->node);
		kfree(coex_event);

		spin_lock(&hw_priv->coex_event_lock);
	}
	spin_unlock(&hw_priv->coex_event_lock);
}

void coex_wifi_bt_ts_thread_init(struct bes2600_common *hw_priv)
{
	coex_bt_time_init();

	INIT_WORK(&hw_priv->coex_work, coex_wifi_bt_ts_thread);
	INIT_LIST_HEAD(&hw_priv->coex_event_list);
	spin_lock_init(&hw_priv->coex_event_lock);
}

void coex_wifi_bt_ts_thread_deinit(struct bes2600_common *hw_priv)
{
	cancel_work_sync(&hw_priv->coex_work);
}
