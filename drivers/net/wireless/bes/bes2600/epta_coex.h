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
#ifndef __EPTA_COEX_H__
#define __EPTA_COEX_H__

#include <linux/types.h>
#include <linux/nl80211.h>

#include "bes2600.h"

#define WIFI_COEX_MODE_FDD_BIT          (1<<0)
#define WIFI_COEX_MODE_FDD_HYBRID_BIT   (1<<1)

enum bwifi_epta_state {
	EPTA_STATE_WIFI_DISCONNECTED     = 0,
	EPTA_STATE_WIFI_SCANNING         = 1,
	EPTA_STATE_WIFI_SCAN_COMP		 = 2,
	EPTA_STATE_WIFI_CONNECTING       = 3,
	EPTA_STATE_WIFI_CONNECTED        = 4,
	EPTA_STATE_WIFI_GOT_IP           = 5,
	EPTA_STATE_WIFI_TTS_START        = 6,
	EPTA_STATE_WIFI_TTS_END          = 7,

	EPTA_STATE_NUM
};

/* max FREEZE BIT */
#define EPTA_FREEZE_MAX 32
typedef enum {
	EPTA_FREEZE_SCANNING = 1 << 0,
	EPTA_FREEZE_CONNECTING = 1 << 1,
	EPTA_FREEZE_TTS = 1 << 2,
	EPTA_FREEZE_THP = 1 << 3,
	/* clear all FREEZE BIT */
	EPTA_FREEZE_ALL
} EPTA_FREEZE_TYPE_T;

#ifndef COEX_TDD_RSSI_THR
#define COEX_TDD_RSSI_THR                 (-15)
#endif
#ifndef COEX_FDD_RSSI_THR
#define COEX_FDD_RSSI_THR                 (-10)
#endif

#define EPTA_PS_WLAN_DURATION             (20000)
#define EPTA_PS_BT_DURATION               (80000)
#define EPTA_ADJUST_WLAN_DURATION_HIGH    (80000)
#define EPTA_ADJUST_WLAN_DURATION_MEDIUM  (55000)
#define EPTA_ADJUST_WLAN_DURATION_LOW     (40000)
#define EPTA_WLAN_TP_HIGH                 (4000)
#define EPTA_WLAN_TP_MEDIUM               (2000)
#define EPTA_WLAN_TP_LOW                  (100)
#define EPTA_WLAN_TP_PS                   (50)
#define EPTA_FREEZE_TDD_PERIOD	          (102400)
#define EPTA_TDD_CONNECT_WIFI             (50000)
#define EPTA_TDD_CONNECT_BT               (50000)

int coex_set_epta_params(struct bes2600_common *hw_priv, int wlan_duraiton, int bt_duration, int hw_epta_enable);
void coex_peroid_handle(struct bes2600_common *hw_priv, int connected, int rssi, int channel, uint32_t tp);
void coex_set_bt_state(struct bes2600_common *hw_priv, int state);
void coex_set_wifi_conn(struct bes2600_common *hw_priv, uint8_t connect_status);
void coex_set_epta_tts(struct bes2600_common *hw_priv, uint32_t tts_state);
int coex_init_mode(struct bes2600_common *hw_priv, int coex_mode);
int coex_deinit_mode(struct bes2600_common *hw_priv);
int coex_start(struct bes2600_common *hw_priv);
int coex_stop(struct bes2600_common *hw_priv);

void coex_rssi_update(struct bes2600_common *hw_priv, int rssi, int channel, int connected);
// void coex_band_update(struct bes2600_common *hw_priv, enum nl80211_band band);
bool coex_is_fdd_mode(void);
void coex_set_fdd_mode(bool fdd_mode);
bool coex_is_bt_a2dp(void);
bool coex_is_bt_inactive(void);
bool coex_is_wifi_inactive(void);

#endif


