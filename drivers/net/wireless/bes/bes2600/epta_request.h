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
#ifndef EPTA_REQUEST_H
#define EPTA_REQUEST_H

#include "linux/list.h"
#include "bes2600.h"

typedef enum {
	BWIFI_STATUS_IDLE                 = 0,
	BWIFI_STATUS_DISCONNECTING        = 1,
	BWIFI_STATUS_SCANNING             = 2,
	BWIFI_STATUS_CONNECTING           = 3,
	BWIFI_STATUS_CONNECTING_5G        = 4,
	BWIFI_STATUS_WPS_CONNECTING       = 5,
	BWIFI_STATUS_CONNECTED            = 6,
	BWIFI_STATUS_CONNECTED_5G         = 7,
	BWIFI_STATUS_DISCONNECTED         = 8,
	BWIFI_STATUS_DHCPING              = 9,
	BWIFI_STATUS_GOT_IP               = 10,
	BWIFI_STATUS_GOT_IP_5G            = 11,
	BWIFI_STATUS_SCANNING_5G          = 12,
	BWIFI_STATUS_SCANNING_COMP        = 13,
} BWIFI_STATUS_T;

typedef enum {
	COEX_TS_TYPE_BT,
	COEX_TS_TYPE_WIFI,
} COEX_TS_TYPE_T;

typedef struct {
	struct list_head node;
	COEX_TS_TYPE_T type;
	uint32_t value;
} COEX_WIFI_BT_TS_T;

void bbt_change_current_status(struct bes2600_common *hw_priv, uint32_t new_status);
void bwifi_change_current_status(struct bes2600_common *hw_priv, BWIFI_STATUS_T new_status);
void coex_wifi_bt_ts_thread_init(struct bes2600_common *hw_priv);
void coex_wifi_bt_ts_thread_deinit(struct bes2600_common *hw_priv);
void coex_calc_wifi_scan_time(uint32_t *min_chan, uint32_t *max_chan);
#endif /*EPTA_REQUEST_H*/