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
#ifndef BES2600_CFGVENDOR_H
#define BES2600_CFGVENDOR_H

#include "bes2600.h"
#include "txrx.h"
#include "sbus.h"
#include "fwio.h"
#include "hwio.h"
#include "bh.h"
#include "sta.h"
#include "ap.h"
#include "scan.h"
#include "debug.h"
#include "pm.h"

#define OUI_GOOGLE  0x001A11
#define GSCAN_BATCH_NO_THR_SET    101
#define FALSE		0
#define FAIL	(-1)
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

typedef enum bes2600_own_event {
    BES2600_RESERVED1,
    BES2600_RESERVED2,
    GSCAN_EVENT_SIGNIFICANT_CHANGE_RESULTS ,
    GSCAN_EVENT_HOTLIST_RESULTS_FOUND,
    GSCAN_EVENT_SCAN_RESULTS_AVAILABLE,
    GSCAN_EVENT_FULL_SCAN_RESULTS,
    RTT_EVENT_COMPLETE,
    GSCAN_EVENT_COMPLETE_SCAN,
    GSCAN_EVENT_HOTLIST_RESULTS_LOST,
    GSCAN_EVENT_EPNO_EVENT,
    GOOGLE_DEBUG_RING_EVENT,
    GOOGLE_DEBUG_MEM_DUMP_EVENT,
    GSCAN_EVENT_ANQPO_HOTSPOT_MATCH,
    GOOGLE_RSSI_MONITOR_EVENT
} bes2600_own_event_t;

enum andr_wifi_feature_set_attr {
	ANDR_WIFI_ATTRIBUTE_NUM_FEATURE_SET,
	ANDR_WIFI_ATTRIBUTE_FEATURE_SET,
	ANDR_WIFI_ATTRIBUTE_RANDOM_MAC_OUI,
	ANDR_WIFI_ATTRIBUTE_NODFS_SET,
	ANDR_WIFI_ATTRIBUTE_COUNTRY,
	ANDR_WIFI_ATTRIBUTE_ND_OFFLOAD_VALUE
	// Add more attribute here
};

typedef enum {
    /* don't use 0 as a valid subcommand */
    VENDOR_NL80211_SUBCMD_UNSPECIFIED,

    /* define all vendor startup commands between 0x0 and 0x0FFF */
    VENDOR_NL80211_SUBCMD_RANGE_START = 0x0001,
    VENDOR_NL80211_SUBCMD_RANGE_END   = 0x0FFF,

    /* define all GScan related commands between 0x1000 and 0x10FF */
    ANDROID_NL80211_SUBCMD_GSCAN_RANGE_START = 0x1000,
    ANDROID_NL80211_SUBCMD_GSCAN_RANGE_END   = 0x10FF,

    /* define all NearbyDiscovery related commands between 0x1100 and 0x11FF */
    ANDROID_NL80211_SUBCMD_NBD_RANGE_START = 0x1100,
    ANDROID_NL80211_SUBCMD_NBD_RANGE_END   = 0x11FF,

    /* define all RTT related commands between 0x1100 and 0x11FF */
    ANDROID_NL80211_SUBCMD_RTT_RANGE_START = 0x1100,
    ANDROID_NL80211_SUBCMD_RTT_RANGE_END   = 0x11FF,

    ANDROID_NL80211_SUBCMD_LSTATS_RANGE_START = 0x1200,
    ANDROID_NL80211_SUBCMD_LSTATS_RANGE_END   = 0x12FF,

    /* define all Logger related commands between 0x1400 and 0x14FF */
    ANDROID_NL80211_SUBCMD_DEBUG_RANGE_START = 0x1400,
    ANDROID_NL80211_SUBCMD_DEBUG_RANGE_END   = 0x14FF,

    /* define all wifi offload related commands between 0x1600 and 0x16FF */
    ANDROID_NL80211_SUBCMD_WIFI_OFFLOAD_RANGE_START = 0x1600,
    ANDROID_NL80211_SUBCMD_WIFI_OFFLOAD_RANGE_END   = 0x16FF,

    /* define all NAN related commands between 0x1700 and 0x17FF */
    ANDROID_NL80211_SUBCMD_NAN_RANGE_START = 0x1700,
    ANDROID_NL80211_SUBCMD_NAN_RANGE_END   = 0x17FF,

    /* define all Android Packet Filter related commands between 0x1800 and 0x18FF */
    ANDROID_NL80211_SUBCMD_PKT_FILTER_RANGE_START = 0x1800,
    ANDROID_NL80211_SUBCMD_PKT_FILTER_RANGE_END   = 0x18FF,

    /* This is reserved for future usage */

} ANDROID_VENDOR_SUB_COMMAND;

enum {
    LSTATS_SUBCMD_GET_INFO = ANDROID_NL80211_SUBCMD_LSTATS_RANGE_START,
	LSTATS_SUBCMD_SET_INFO,
	LSTATS_SUBCMD_CLEAR_INFO,
};

enum bes2600_vendor_subcmd {
    GSCAN_SUBCMD_GET_CAPABILITIES = ANDROID_NL80211_SUBCMD_GSCAN_RANGE_START,

    GSCAN_SUBCMD_SET_CONFIG,                            /* 0x1001 */

    GSCAN_SUBCMD_SET_SCAN_CONFIG,                       /* 0x1002 */
    GSCAN_SUBCMD_ENABLE_GSCAN,                          /* 0x1003 */
    GSCAN_SUBCMD_GET_SCAN_RESULTS,                      /* 0x1004 */
    GSCAN_SUBCMD_SCAN_RESULTS,                          /* 0x1005 */

    GSCAN_SUBCMD_SET_HOTLIST,                           /* 0x1006 */

    GSCAN_SUBCMD_SET_SIGNIFICANT_CHANGE_CONFIG,         /* 0x1007 */
    GSCAN_SUBCMD_ENABLE_FULL_SCAN_RESULTS,              /* 0x1008 */
    GSCAN_SUBCMD_GET_CHANNEL_LIST,                       /* 0x1009 */

    WIFI_SUBCMD_GET_FEATURE_SET,                         /* 0x100A */
    WIFI_SUBCMD_GET_FEATURE_SET_MATRIX,                  /* 0x100B */
    WIFI_SUBCMD_SET_PNO_RANDOM_MAC_OUI,                  /* 0x100C */
    WIFI_SUBCMD_NODFS_SET,                               /* 0x100D */
    WIFI_SUBCMD_SET_COUNTRY_CODE,                             /* 0x100E */
    /* Add more sub commands here */
    GSCAN_SUBCMD_SET_EPNO_SSID,                          /* 0x100F */

    WIFI_SUBCMD_SET_SSID_WHITE_LIST,                    /* 0x1010 */
    WIFI_SUBCMD_SET_ROAM_PARAMS,                        /* 0x1011 */
    WIFI_SUBCMD_ENABLE_LAZY_ROAM,                       /* 0x1012 */
    WIFI_SUBCMD_SET_BSSID_PREF,                         /* 0x1013 */
    WIFI_SUBCMD_SET_BSSID_BLACKLIST,                     /* 0x1014 */

    GSCAN_SUBCMD_ANQPO_CONFIG,                          /* 0x1015 */
    WIFI_SUBCMD_SET_RSSI_MONITOR,                       /* 0x1016 */
    WIFI_SUBCMD_CONFIG_ND_OFFLOAD,                      /* 0x1017 */
    /* Add more sub commands here */

    GSCAN_SUBCMD_MAX,

	RTT_SUBCMD_SET_CONFIG = ANDROID_NL80211_SUBCMD_RTT_RANGE_START,
	RTT_SUBCMD_CANCEL_CONFIG,
	RTT_SUBCMD_GETCAPABILITY,

    APF_SUBCMD_GET_CAPABILITIES = ANDROID_NL80211_SUBCMD_PKT_FILTER_RANGE_START,
    APF_SUBCMD_SET_FILTER,

    LOGGER_START_LOGGING = ANDROID_NL80211_SUBCMD_DEBUG_RANGE_START,
    LOGGER_TRIGGER_MEM_DUMP,
    LOGGER_GET_MEM_DUMP,
    LOGGER_GET_VER,
    LOGGER_GET_RING_STATUS,
    LOGGER_GET_RING_DATA,
    LOGGER_GET_FEATURE,
    LOGGER_RESET_LOGGING,
    LOGGER_TRIGGER_DRIVER_MEM_DUMP,
    LOGGER_GET_DRIVER_MEM_DUMP,
    LOGGER_START_PKT_FATE_MONITORING,
    LOGGER_GET_TX_PKT_FATES,
    LOGGER_GET_RX_PKT_FATES,

	VENDOR_SUBCMD_MAX
};

typedef enum {
    WIFI_SUCCESS = 0,
    WIFI_ERROR_NONE = 0,
    WIFI_ERROR_UNKNOWN = -1,
    WIFI_ERROR_UNINITIALIZED = -2,
    WIFI_ERROR_NOT_SUPPORTED = -3,
    WIFI_ERROR_NOT_AVAILABLE = -4,              // Not available right now, but try later
    WIFI_ERROR_INVALID_ARGS = -5,
    WIFI_ERROR_INVALID_REQUEST_ID = -6,
    WIFI_ERROR_TIMED_OUT = -7,
    WIFI_ERROR_TOO_MANY_REQUESTS = -8,          // Too many instances of this request
    WIFI_ERROR_OUT_OF_MEMORY = -9,
    WIFI_ERROR_BUSY = -10,
} wifi_error;

enum _IFACE_ID {
	IFACE_ID0, /*PRIMARY_ADAPTER*/
	IFACE_ID1,
	IFACE_ID2,
	IFACE_ID3,
	IFACE_ID4,
	IFACE_ID5,
	IFACE_ID6,
	IFACE_ID7,
	IFACE_ID_MAX,
};

typedef struct dhd_pno_gscan_capabilities {
	int max_scan_cache_size;
	int max_scan_buckets;
	int max_ap_cache_per_scan;
	int max_rssi_sample_size;
	int max_scan_reporting_threshold;
	int max_hotlist_aps;
	int max_significant_wifi_change_aps;
	int max_epno_ssid_crc32;
	int max_epno_hidden_ssid;
	int max_white_list_ssid;
} dhd_pno_gscan_capabilities_t;

typedef struct gscan_batch_params {
	unsigned char bestn;
	unsigned char mscan;
	unsigned char buffer_threshold;
} gscan_batch_params_t;

void bes2600_reg_notifier(struct wiphy *wiphy, struct regulatory_request *request);
int bes2600_set_vendor_command(struct wiphy *wiphy);
int bes2600_vendor_command_detach(struct wiphy *wiphy);
#endif