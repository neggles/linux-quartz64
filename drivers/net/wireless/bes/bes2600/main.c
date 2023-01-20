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

/*Linux version 3.4.0 compilation*/
//#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0))
#include<linux/module.h>
//#endif
#include <linux/init.h>
#include <linux/firmware.h>
#include <linux/etherdevice.h>
#include <linux/vmalloc.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/rfkill.h>
#include <net/mac80211.h>

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
#include "bes2600_cfgvendor.h"
#include "bes2600_driver_mode.h"
#include "bes2600_factory.h"
#include "bes_chardev.h"
#include "txrx_opt.h"

MODULE_AUTHOR("Dmitry Tarnyagin <dmitry.tarnyagin@stericsson.com>");
MODULE_DESCRIPTION("Softmac BES2600 common code");
MODULE_LICENSE("GPL");
MODULE_ALIAS("bes2600");

static u8 bes2600_mac_template[ETH_ALEN] = {
#if (GET_MAC_ADDR_METHOD == 2)||(GET_MAC_ADDR_METHOD == 3)
	0x00, 0x12, 0x34, 0x00, 0x00, 0x00
#else
	0x02, 0x80, 0xe1, 0x00, 0x00, 0x00 /* To use macaddr of customers */
#endif
};

#if (GET_MAC_ADDR_METHOD == 2) /* To use macaddr and PS Mode of customers */
#ifndef PATH_WIFI_MACADDR
#define PATH_WIFI_MACADDR		"/efs/wifi/.mac.info"
#endif
#elif (GET_MAC_ADDR_METHOD == 3)
#define PATH_WIFI_MACADDR_TMP	"/data/.mac.info"
#endif

#ifdef CUSTOM_FEATURE
#define PATH_WIFI_PSM_INFO		"/data/.psm.info"
static int savedpsm = 0;
#endif

#if defined(CUSTOM_FEATURE) ||(GET_MAC_ADDR_METHOD == 2) || (GET_MAC_ADDR_METHOD == 3)
int access_file(char *path, char *buffer, int size, int isRead);
#endif

/* TODO: use rates and channels from the device */
#define RATETAB_ENT(_rate, _rateid, _flags)		\
	{						\
		.bitrate	= (_rate),		\
		.hw_value	= (_rateid),		\
		.flags		= (_flags),		\
	}

static struct ieee80211_rate bes2600_rates[] = {
	RATETAB_ENT(10,  0,   0),
	RATETAB_ENT(20,  1,   0),
	RATETAB_ENT(55,  2,   0),
	RATETAB_ENT(110, 3,   0),
	RATETAB_ENT(60,  6,  0),
	RATETAB_ENT(90,  7,  0),
	RATETAB_ENT(120, 8,  0),
	RATETAB_ENT(180, 9,  0),
	RATETAB_ENT(240, 10, 0),
	RATETAB_ENT(360, 11, 0),
	RATETAB_ENT(480, 12, 0),
	RATETAB_ENT(540, 13, 0),
};

static struct ieee80211_rate bes2600_mcs_rates[] = {
	RATETAB_ENT(65,  14, IEEE80211_TX_RC_MCS),
	RATETAB_ENT(130, 15, IEEE80211_TX_RC_MCS),
	RATETAB_ENT(195, 16, IEEE80211_TX_RC_MCS),
	RATETAB_ENT(260, 17, IEEE80211_TX_RC_MCS),
	RATETAB_ENT(390, 18, IEEE80211_TX_RC_MCS),
	RATETAB_ENT(520, 19, IEEE80211_TX_RC_MCS),
	RATETAB_ENT(585, 20, IEEE80211_TX_RC_MCS),
	RATETAB_ENT(650, 21, IEEE80211_TX_RC_MCS),
};

#define bes2600_a_rates		(bes2600_rates + 4)
#define bes2600_a_rates_size	(ARRAY_SIZE(bes2600_rates) - 4)
#define bes2600_g_rates		(bes2600_rates + 0)
#define bes2600_g_rates_size	(ARRAY_SIZE(bes2600_rates))
#define bes2600_n_rates		(bes2600_mcs_rates)
#define bes2600_n_rates_size	(ARRAY_SIZE(bes2600_mcs_rates))


#define CHAN2G(_channel, _freq, _flags) {			\
	.band			= NL80211_BAND_2GHZ,		\
	.center_freq		= (_freq),			\
	.hw_value		= (_channel),			\
	.flags			= (_flags),			\
	.max_antenna_gain	= 0,				\
	.max_power		= 30,				\
}

#define CHAN5G(_channel, _flags) {				\
	.band			= NL80211_BAND_5GHZ,		\
	.center_freq	= 5000 + (5 * (_channel)),		\
	.hw_value		= (_channel),			\
	.flags			= (_flags),			\
	.max_antenna_gain	= 0,				\
	.max_power		= 30,				\
}

static struct ieee80211_channel bes2600_2ghz_chantable[] = {
	CHAN2G(1, 2412, 0),
	CHAN2G(2, 2417, 0),
	CHAN2G(3, 2422, 0),
	CHAN2G(4, 2427, 0),
	CHAN2G(5, 2432, 0),
	CHAN2G(6, 2437, 0),
	CHAN2G(7, 2442, 0),
	CHAN2G(8, 2447, 0),
	CHAN2G(9, 2452, 0),
	CHAN2G(10, 2457, 0),
	CHAN2G(11, 2462, 0),
	CHAN2G(12, 2467, 0),
	CHAN2G(13, 2472, 0),
	CHAN2G(14, 2484, 0),
};

#ifdef CONFIG_BES2600_5GHZ_SUPPORT
#if 1
static struct ieee80211_channel bes2600_5ghz_chantable[] = {
	CHAN5G(34, 0),		CHAN5G(36, 0),
	CHAN5G(38, 0),		CHAN5G(40, 0),
	CHAN5G(42, 0),		CHAN5G(44, 0),
	CHAN5G(46, 0),		CHAN5G(48, 0),
	CHAN5G(52, 0),		CHAN5G(56, 0),
	CHAN5G(60, 0),		CHAN5G(64, 0),
	CHAN5G(100, 0),		CHAN5G(104, 0),
	CHAN5G(108, 0),		CHAN5G(112, 0),
	CHAN5G(116, 0),		CHAN5G(120, 0),
	CHAN5G(124, 0),		CHAN5G(128, 0),
	CHAN5G(132, 0),		CHAN5G(136, 0),
	CHAN5G(140, 0),		CHAN5G(149, 0),
	CHAN5G(153, 0),		CHAN5G(157, 0),
	CHAN5G(161, 0),		CHAN5G(165, 0),
	CHAN5G(184, 0),		CHAN5G(188, 0),
	CHAN5G(192, 0),		CHAN5G(196, 0),
	CHAN5G(200, 0),		CHAN5G(204, 0),
	CHAN5G(208, 0),		CHAN5G(212, 0),
	CHAN5G(216, 0),
};
#else
/* comply with china regulation on 5G */
static struct ieee80211_channel bes2600_5ghz_chantable[] = {
	CHAN5G(36, 0),
	CHAN5G(40, 0),
	CHAN5G(44, 0),
	CHAN5G(48, 0),
	CHAN5G(52, 0),
	CHAN5G(56, 0),
	CHAN5G(60, 0),
	CHAN5G(64, 0),
	CHAN5G(149, 0),
	CHAN5G(153, 0),
	CHAN5G(157, 0),
	CHAN5G(161, 0),
	CHAN5G(165, 0),
};
#endif
#endif

static struct ieee80211_supported_band bes2600_band_2ghz = {
	.channels = bes2600_2ghz_chantable,
	.n_channels = ARRAY_SIZE(bes2600_2ghz_chantable),
	.bitrates = bes2600_g_rates,
	.n_bitrates = bes2600_g_rates_size,
	.ht_cap = {
		.cap = IEEE80211_HT_CAP_GRN_FLD |
			(1 << IEEE80211_HT_CAP_RX_STBC_SHIFT) |
			IEEE80211_HT_CAP_SUP_WIDTH_20_40 |
			IEEE80211_HT_CAP_SGI_20 |
			IEEE80211_HT_CAP_SGI_40 |
			IEEE80211_HT_CAP_MAX_AMSDU,
		.ht_supported = 1,
		.ampdu_factor = IEEE80211_HT_MAX_AMPDU_32K,
		.ampdu_density = IEEE80211_HT_MPDU_DENSITY_NONE,
		.mcs = {
			.rx_mask[0] = 0xFF,
			.rx_highest = __cpu_to_le16(0),
			.tx_params = IEEE80211_HT_MCS_TX_DEFINED,
		},
	},
};

#ifdef CONFIG_BES2600_5GHZ_SUPPORT
static struct ieee80211_supported_band bes2600_band_5ghz = {
	.channels = bes2600_5ghz_chantable,
	.n_channels = ARRAY_SIZE(bes2600_5ghz_chantable),
	.bitrates = bes2600_a_rates,
	.n_bitrates = bes2600_a_rates_size,
	.ht_cap = {
		.cap = IEEE80211_HT_CAP_GRN_FLD |
			(1 << IEEE80211_HT_CAP_RX_STBC_SHIFT) |
			IEEE80211_HT_CAP_SUP_WIDTH_20_40 |
			IEEE80211_HT_CAP_SGI_20 |
			IEEE80211_HT_CAP_SGI_40 |
			IEEE80211_HT_CAP_MAX_AMSDU,
		.ht_supported = 1,
		.ampdu_factor = IEEE80211_HT_MAX_AMPDU_32K,
		.ampdu_density = IEEE80211_HT_MPDU_DENSITY_NONE,
		.mcs = {
			.rx_mask[0] = 0xFF,
			.rx_highest = __cpu_to_le16(0x41),
			.tx_params = IEEE80211_HT_MCS_TX_DEFINED,
		},
	},
};
#endif /* CONFIG_BES2600_5GHZ_SUPPORT */

static const unsigned long bes2600_ttl[] = {
	1 * HZ,	/* VO */
	2 * HZ,	/* VI */
	5 * HZ, /* BE */
	10 * HZ	/* BK */
};

static const struct ieee80211_iface_limit bes2600_if_limits[] = {
	{ .max = 2, .types = BIT(NL80211_IFTYPE_STATION) },
	{ .max = 1, .types = BIT(NL80211_IFTYPE_AP) |
			     BIT(NL80211_IFTYPE_P2P_CLIENT) |
			     BIT(NL80211_IFTYPE_P2P_GO) },
#ifdef P2P_MULTIVIF
	{ .max = 1, .types = BIT(NL80211_IFTYPE_P2P_DEVICE) },
#endif
};



static const struct ieee80211_iface_combination bes2600_if_comb[] = {
	{
		.limits = bes2600_if_limits,
		.n_limits = ARRAY_SIZE(bes2600_if_limits),
		.max_interfaces = CW12XX_MAX_VIFS,
		.num_different_channels = 1,
	},
};


static const struct ieee80211_ops bes2600_ops = {
	.start			= bes2600_start,
	.stop			= bes2600_stop,
	.add_interface		= bes2600_add_interface,
	.remove_interface	= bes2600_remove_interface,
	.change_interface	= bes2600_change_interface,
	.tx			= bes2600_tx,
	.wake_tx_queue		= ieee80211_handle_wake_tx_queue,
	.hw_scan		= bes2600_hw_scan,
	.cancel_hw_scan         = bes2600_cancel_hw_scan,
#ifdef ROAM_OFFLOAD
	.sched_scan_start	= bes2600_hw_sched_scan_start,
	.sched_scan_stop	= bes2600_hw_sched_scan_stop,
#endif /*ROAM_OFFLOAD*/
	.set_tim		= bes2600_set_tim,
	.sta_notify		= bes2600_sta_notify,
	.sta_add		= bes2600_sta_add,
	.sta_remove		= bes2600_sta_remove,
	.set_key		= bes2600_set_key,
	.set_rts_threshold	= bes2600_set_rts_threshold,
	.config			= bes2600_config,
	.bss_info_changed	= bes2600_bss_info_changed,
	.prepare_multicast	= bes2600_prepare_multicast,
	.configure_filter	= bes2600_configure_filter,
	.conf_tx		= bes2600_conf_tx,
	.get_stats		= bes2600_get_stats,
	.ampdu_action		= bes2600_ampdu_action,
	.flush			= bes2600_flush,
#ifdef CONFIG_PM
	.suspend		= bes2600_wow_suspend,
	.resume			= bes2600_wow_resume,
#endif
	/* Intentionally not offloaded:					*/
	/*.channel_switch	= bes2600_channel_switch,		*/
	.remain_on_channel	= bes2600_remain_on_channel,
	.cancel_remain_on_channel = bes2600_cancel_remain_on_channel,
#ifdef IPV6_FILTERING
	//.set_data_filter        = bes2600_set_data_filter,
#endif /*IPV6_FILTERING*/
#ifdef CONFIG_BES2600_TESTMODE
    .testmode_cmd  = bes2600_testmode_cmd,
#endif
};

#ifdef CONFIG_PM
static const struct wiphy_wowlan_support bes2600_wowlan_support = {
	/* Support only for limited wowlan functionalities */
	.flags = WIPHY_WOWLAN_ANY | WIPHY_WOWLAN_DISCONNECT,
};
#endif

#ifdef CONFIG_BES2600_WAPI_SUPPORT
static void bes2600_init_wapi_cipher(struct ieee80211_hw *hw)
{
	static struct ieee80211_cipher_scheme wapi_cs = {
		.cipher = WLAN_CIPHER_SUITE_SMS4,
		.iftype = BIT(NL80211_IFTYPE_STATION),
		.hdr_len = 18,
		.pn_len = 16,
		.pn_off = 2,
		.key_idx_off = 0,
		.key_idx_mask = 0x01,
		.key_idx_shift = 0,
		.mic_len = 16
	};

	hw->cipher_schemes = &wapi_cs;
	hw->n_cipher_schemes = 1;
}
#endif

static void bes2600_get_base_mac(struct bes2600_common *hw_priv)
{
#if (GET_MAC_ADDR_METHOD == 1)
	u8 fixed_mac[ETH_ALEN];
#endif
#if (GET_MAC_ADDR_METHOD == 2)||(GET_MAC_ADDR_METHOD == 3) /* To use macaddr of customers */
	char readmac[17+1]={0,};
#endif
	memcpy(hw_priv->addresses[0].addr, bes2600_mac_template, ETH_ALEN);

#if (GET_MAC_ADDR_METHOD == 1)
	rockchip_wifi_mac_addr(fixed_mac);
	memcpy(hw_priv->addresses[0].addr, fixed_mac, ETH_ALEN * sizeof(u8));
	bes2600_info(BES2600_DBG_INIT, "get fixed mac address from flash=[%02x:%02x:%02x:%02x:%02x:%02x]\n", fixed_mac[0], fixed_mac[1],
				fixed_mac[2], fixed_mac[3], fixed_mac[4], fixed_mac[5]);
	if(fixed_mac[0] & (0x01)){
		bes2600_warn(BES2600_DBG_INIT, "The MAC address is not suitable for unicast, change to random MAC\n");
		memcpy(hw_priv->addresses[0].addr, bes2600_mac_template, ETH_ALEN);
	}

#elif (GET_MAC_ADDR_METHOD == 2) /* To use macaddr of customers */
	if(access_file(PATH_WIFI_MACADDR,readmac,17,1) > 0) {
		sscanf(readmac,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
								(u8 *)&hw_priv->addresses[0].addr[0],
								(u8 *)&hw_priv->addresses[0].addr[1],
								(u8 *)&hw_priv->addresses[0].addr[2],
								(u8 *)&hw_priv->addresses[0].addr[3],
								(u8 *)&hw_priv->addresses[0].addr[4],
								(u8 *)&hw_priv->addresses[0].addr[5]);
	}
#elif (GET_MAC_ADDR_METHOD == 3)
	if(access_file(PATH_WIFI_MACADDR_TMP,readmac,17,1) > 0) {
		sscanf(readmac,"%02X:%02X:%02X:%02X:%02X:%02X",
								(u8 *)&hw_priv->addresses[0].addr[0],
								(u8 *)&hw_priv->addresses[0].addr[1],
								(u8 *)&hw_priv->addresses[0].addr[2],
								(u8 *)&hw_priv->addresses[0].addr[3],
								(u8 *)&hw_priv->addresses[0].addr[4],
								(u8 *)&hw_priv->addresses[0].addr[5]);
	}
#endif
	if (hw_priv->addresses[0].addr[3] == 0 &&
	    hw_priv->addresses[0].addr[4] == 0 &&
	    hw_priv->addresses[0].addr[5] == 0)
		get_random_bytes(&hw_priv->addresses[0].addr[3], 3);
}

static void bes2600_derive_mac(struct bes2600_common *hw_priv)
{
	memcpy(hw_priv->addresses[1].addr, hw_priv->addresses[0].addr, ETH_ALEN);
	hw_priv->addresses[1].addr[5] =
			hw_priv->addresses[0].addr[5] + 1;

#ifdef P2P_MULTIVIF
	memcpy(hw_priv->addresses[2].addr, hw_priv->addresses[1].addr,
	       ETH_ALEN);
	hw_priv->addresses[2].addr[4] ^= 0x80;
#endif
}

struct ieee80211_hw *bes2600_init_common(size_t hw_priv_data_len)
{
	int i;
	struct ieee80211_hw *hw;
	struct bes2600_common *hw_priv;
	struct ieee80211_supported_band *sband;
	int band;

	hw = ieee80211_alloc_hw(hw_priv_data_len, &bes2600_ops);
	if (!hw)
		return NULL;

	hw_priv = hw->priv;
	/* TODO:COMBO this debug message can be removed */
	bes2600_err(BES2600_DBG_INIT, "Allocated hw_priv @ %p\n", hw_priv);
	hw_priv->if_id_slot = 0;
	hw_priv->roc_if_id = -1;
	hw_priv->scan_switch_if_id = -1;
	atomic_set(&hw_priv->num_vifs, 0);
	atomic_set(&hw_priv->netdevice_start, 0);

	bes2600_get_base_mac(hw_priv);
	bes2600_derive_mac(hw_priv);

	hw_priv->hw = hw;
	hw_priv->rates = bes2600_rates; /* TODO: fetch from FW */
	hw_priv->mcs_rates = bes2600_n_rates;
#ifdef ROAM_OFFLOAD
	hw_priv->auto_scanning = 0;
	hw_priv->frame_rcvd = 0;
	hw_priv->num_scanchannels = 0;
	hw_priv->num_2g_channels = 0;
	hw_priv->num_5g_channels = 0;
#endif /*ROAM_OFFLOAD*/
#ifdef AP_AGGREGATE_FW_FIX
	/* Enable block ACK for 4 TID (BE,VI,VI,VO). */
	/*due to HW limitations*/
	hw_priv->ba_tid_mask = 0xB1;
#else
	/* Enable block ACK for every TID but voice. */
	hw_priv->ba_tid_mask = 0xFF;//0x3F;
#endif

	/* Init tx retry limit */
#ifdef BES2600_TX_RX_OPT
	hw_priv->long_frame_max_tx_count = 31;
	hw_priv->short_frame_max_tx_count = 31;
#else
	hw_priv->long_frame_max_tx_count = 7;
	hw_priv->short_frame_max_tx_count = 15;
#endif
	hw_priv->hw->max_rate_tries = hw_priv->short_frame_max_tx_count;

	ieee80211_hw_set(hw, SIGNAL_DBM);
	ieee80211_hw_set(hw, SUPPORTS_PS);
	ieee80211_hw_set(hw, SUPPORTS_DYNAMIC_PS);
	ieee80211_hw_set(hw, REPORTS_TX_ACK_STATUS);
	ieee80211_hw_set(hw, NEED_DTIM_BEFORE_ASSOC);
	ieee80211_hw_set(hw, TX_AMPDU_SETUP_IN_HW);
	ieee80211_hw_set(hw, AMPDU_AGGREGATION);
	ieee80211_hw_set(hw, CONNECTION_MONITOR);
	ieee80211_hw_set(hw, MFP_CAPABLE);

	hw->wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION) |
					  BIT(NL80211_IFTYPE_ADHOC) |
					  BIT(NL80211_IFTYPE_AP) |
					  BIT(NL80211_IFTYPE_MESH_POINT) |
					  BIT(NL80211_IFTYPE_P2P_CLIENT) |
					  BIT(NL80211_IFTYPE_P2P_GO);
#ifdef P2P_MULTIVIF
	hw->wiphy->interface_modes |= BIT(NL80211_IFTYPE_P2P_DEVICE);
#endif

	/* Support only for limited wowlan functionalities */
#ifdef CONFIG_PM
	hw->wiphy->wowlan = &bes2600_wowlan_support;
#endif

#if defined(CONFIG_BES2600_USE_STE_EXTENSIONS)
	hw->wiphy->flags |= WIPHY_FLAG_AP_UAPSD;
#endif /* CONFIG_BES2600_USE_STE_EXTENSIONS */

#if defined(CONFIG_BES2600_DISABLE_BEACON_HINTS)
	hw->wiphy->flags |= WIPHY_FLAG_DISABLE_BEACON_HINTS;
#endif
	hw->wiphy->n_addresses = CW12XX_MAX_VIFS;
	hw->wiphy->addresses = hw_priv->addresses;
	hw->wiphy->max_remain_on_channel_duration = 500;
	hw->wiphy->reg_notifier = bes2600_reg_notifier;
	//hw->channel_change_time = 500;	/* TODO: find actual value */
	/* hw_priv->beacon_req_id = cpu_to_le32(0); */
	hw->queues = 4;
	hw_priv->noise = -94;

	hw->max_rates = 8;
	hw->max_rate_tries = 15;
	hw->extra_tx_headroom = WSM_TX_EXTRA_HEADROOM +
		8  /* TKIP IV */ +
		12 /* TKIP ICV and MIC */;

	hw->sta_data_size = sizeof(struct bes2600_sta_priv);
	hw->vif_data_size = sizeof(struct bes2600_vif);

	hw->wiphy->bands[NL80211_BAND_2GHZ] = &bes2600_band_2ghz;
#ifdef CONFIG_BES2600_5GHZ_SUPPORT
	hw->wiphy->bands[NL80211_BAND_5GHZ] = &bes2600_band_5ghz;
#endif /* CONFIG_BES2600_5GHZ_SUPPORT */

	/* Channel params have to be cleared before registering wiphy again */
	for (band = 0; band < NUM_NL80211_BANDS; band++) {
		sband = hw->wiphy->bands[band];
		if (!sband)
			continue;
		for (i = 0; i < sband->n_channels; i++) {
			sband->channels[i].flags = 0;
			sband->channels[i].max_antenna_gain = 0;
			sband->channels[i].max_power = 30;
		}
	}

	hw->wiphy->max_scan_ssids = WSM_SCAN_MAX_NUM_OF_SSIDS;
	hw->wiphy->max_scan_ie_len = IEEE80211_MAX_DATA_LEN;

	hw->wiphy->iface_combinations = bes2600_if_comb;
	hw->wiphy->n_iface_combinations = ARRAY_SIZE(bes2600_if_comb);

#ifdef CONFIG_BES2600_WAPI_SUPPORT
	hw_priv->last_ins_wapi_usk_id = -1;
	hw_priv->last_del_wapi_usk_id = -1;
	bes2600_init_wapi_cipher(hw);
#endif

	SET_IEEE80211_PERM_ADDR(hw, hw_priv->addresses[0].addr);

	spin_lock_init(&hw_priv->vif_list_lock);
	sema_init(&hw_priv->wsm_cmd_sema, 1);
	sema_init(&hw_priv->conf_lock, 1);
	sema_init(&hw_priv->wsm_oper_lock, 1);
#ifdef CONFIG_BES2600_TESTMODE
	spin_lock_init(&hw_priv->tsm_lock);
#endif /*CONFIG_BES2600_TESTMODE*/
	hw_priv->workqueue = create_singlethread_workqueue("bes2600_wq");
	sema_init(&hw_priv->scan.lock, 1);
	INIT_WORK(&hw_priv->scan.work, bes2600_scan_work);
#ifdef ROAM_OFFLOAD
	INIT_WORK(&hw_priv->scan.swork, bes2600_sched_scan_work);
#endif /*ROAM_OFFLOAD*/
	INIT_DELAYED_WORK(&hw_priv->scan.probe_work, bes2600_probe_work);
	INIT_DELAYED_WORK(&hw_priv->scan.timeout, bes2600_scan_timeout);
#ifdef CONFIG_BES2600_TESTMODE
	INIT_DELAYED_WORK(&hw_priv->advance_scan_timeout,
		 bes2600_advance_scan_timeout);
#endif
	INIT_DELAYED_WORK(&hw_priv->rem_chan_timeout, bes2600_rem_chan_timeout);
	hw_priv->rtsvalue = 0;
	spin_lock_init(&hw_priv->rtsvalue_lock);
	INIT_WORK(&hw_priv->dynamic_opt_txrx_work, bes2600_dynamic_opt_txrx_work);
	INIT_WORK(&hw_priv->tx_policy_upload_work, tx_policy_upload_work);
	spin_lock_init(&hw_priv->event_queue_lock);
	INIT_LIST_HEAD(&hw_priv->event_queue);
	INIT_WORK(&hw_priv->event_handler, bes2600_event_handler);
	INIT_WORK(&hw_priv->ba_work, bes2600_ba_work);
	spin_lock_init(&hw_priv->ba_lock);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))
	timer_setup(&hw_priv->ba_timer, bes2600_ba_timer, 0);
#else
	setup_timer(&hw_priv->ba_timer, bes2600_ba_timer, (unsigned long)hw_priv);
#endif

	if (unlikely(bes2600_queue_stats_init(&hw_priv->tx_queue_stats,
			WLAN_LINK_ID_MAX,
			bes2600_skb_dtor,
			hw_priv))) {
		ieee80211_free_hw(hw);
		return NULL;
	}

	for (i = 0; i < 4; ++i) {
		if (unlikely(bes2600_queue_init(&hw_priv->tx_queue[i],
				&hw_priv->tx_queue_stats, i, CW12XX_MAX_QUEUE_SZ,
				bes2600_ttl[i]))) {
			for (; i > 0; i--)
				bes2600_queue_deinit(&hw_priv->tx_queue[i - 1]);
			bes2600_queue_stats_deinit(&hw_priv->tx_queue_stats);
			ieee80211_free_hw(hw);
			return NULL;
		}
	}

	init_waitqueue_head(&hw_priv->channel_switch_done);
	init_waitqueue_head(&hw_priv->wsm_cmd_wq);
	init_waitqueue_head(&hw_priv->wsm_startup_done);
	init_waitqueue_head(&hw_priv->offchannel_wq);
	hw_priv->offchannel_done = 0;
	wsm_buf_init(&hw_priv->wsm_cmd_buf);
	spin_lock_init(&hw_priv->wsm_cmd.lock);

	bes2600_tx_loop_init(hw_priv);

#ifdef CONFIG_BES2600_TESTMODE
	hw_priv->test_frame.data = NULL;
	hw_priv->test_frame.len = 0;
#endif /* CONFIG_BES2600_TESTMODE */

#ifdef CONFIG_BES2600_VENDOR_CMD
	bes2600_set_vendor_command(hw->wiphy);
#endif

#if defined(CONFIG_BES2600_WSM_DUMPS_SHORT)
	hw_priv->wsm_dump_max_size = 20;
#endif /* CONFIG_BES2600_WSM_DUMPS_SHORT */

	for (i = 0; i < CW12XX_MAX_VIFS; i++)
		hw_priv->hw_bufs_used_vif[i] = 0;

#ifdef MCAST_FWDING
       for (i = 0; i < WSM_MAX_BUF; i++)
               wsm_init_release_buffer_request(hw_priv, i);
       hw_priv->buf_released = 0;
#endif
	hw_priv->vif0_throttle = CW12XX_HOST_VIF0_11BG_THROTTLE;
	hw_priv->vif1_throttle = CW12XX_HOST_VIF1_11BG_THROTTLE;
	return hw;
}
EXPORT_SYMBOL_GPL(bes2600_init_common);


int bes2600_register_common(struct ieee80211_hw *dev)
{
	struct bes2600_common *hw_priv = dev->priv;
	int err;

	err = ieee80211_register_hw(dev);
	if (err) {
		bes2600_err(BES2600_DBG_INIT, "Cannot register device (%d).\n",
				err);
		return err;
	}

#ifdef CONFIG_BES2600_LEDS
	err = bes2600_init_leds(priv);
	if (err) {
		bes2600_pm_deinit(&hw_priv->pm_state);
		ieee80211_unregister_hw(dev);
		return err;
	}
#endif /* CONFIG_BES2600_LEDS */

	bes2600_debug_init_common(hw_priv);

	bes2600_info(BES2600_DBG_INIT, "is registered as '%s'\n",
			wiphy_name(dev->wiphy));
	return 0;
}
EXPORT_SYMBOL_GPL(bes2600_register_common);

void bes2600_free_common(struct ieee80211_hw *dev)
{
	/* struct bes2600_common *hw_priv = dev->priv; */
#ifdef CONFIG_BES2600_TESTMODE
	struct bes2600_common *hw_priv = dev->priv;
	kfree(hw_priv->test_frame.data);
#endif /* CONFIG_BES2600_TESTMODE */

#ifdef CONFIG_BES2600_VENDOR_CMD
	bes2600_vendor_command_detach(dev->wiphy);
#endif

	/* unsigned int i; */

	ieee80211_free_hw(dev);
}
EXPORT_SYMBOL_GPL(bes2600_free_common);

void bes2600_unregister_common(struct ieee80211_hw *dev)
{
	struct bes2600_common *hw_priv = dev->priv;
	int i;

	ieee80211_unregister_hw(dev);

	del_timer_sync(&hw_priv->ba_timer);

	hw_priv->sbus_ops->irq_unsubscribe(hw_priv->sbus_priv);
	bes2600_unregister_bh(hw_priv);

	bes2600_debug_release_common(hw_priv);

#ifdef CONFIG_BES2600_LEDS
	bes2600_unregister_leds(hw_priv);
#endif /* CONFIG_BES2600_LEDS */

	wsm_buf_deinit(&hw_priv->wsm_cmd_buf);
	destroy_workqueue(hw_priv->workqueue);
	hw_priv->workqueue = NULL;
	if (hw_priv->skb_cache) {
		dev_kfree_skb(hw_priv->skb_cache);
		hw_priv->skb_cache = NULL;
	}
	if (hw_priv->sdd) {
#ifndef CONFIG_BES2600_STATIC_SDD
		release_firmware(hw_priv->sdd);
#endif
		hw_priv->sdd = NULL;
	}
	for (i = 0; i < 4; ++i)
		bes2600_queue_deinit(&hw_priv->tx_queue[i]);
	bes2600_queue_stats_deinit(&hw_priv->tx_queue_stats);
	for (i = 0; i < CW12XX_MAX_VIFS; i++) {
		kfree(hw_priv->vif_list[i]);
		hw_priv->vif_list[i] = NULL;
	}

	bes2600_pwr_exit(hw_priv);
}
EXPORT_SYMBOL_GPL(bes2600_unregister_common);

#if 0
static void cw12xx_set_ifce_comb(struct bes2600_common *hw_priv,
				 struct ieee80211_hw *hw)
{
#ifdef P2P_MULTIVIF
	hw_priv->if_limits1[0].max = 2;
#else
	hw_priv->if_limits1[0].max = 1;
#endif

	hw_priv->if_limits1[0].types = BIT(NL80211_IFTYPE_STATION);
	hw_priv->if_limits1[1].max = 1;
	hw_priv->if_limits1[1].types = BIT(NL80211_IFTYPE_AP);

#ifdef P2P_MULTIVIF
	hw_priv->if_limits2[0].max = 3;
#else
	hw_priv->if_limits2[0].max = 2;
#endif
	hw_priv->if_limits2[0].types = BIT(NL80211_IFTYPE_STATION);

#ifdef P2P_MULTIVIF
       hw_priv->if_limits3[0].max = 2;
#else
	hw_priv->if_limits3[0].max = 1;
#endif

	hw_priv->if_limits3[0].types = BIT(NL80211_IFTYPE_STATION);
	hw_priv->if_limits3[1].max = 1;
	hw_priv->if_limits3[1].types = BIT(NL80211_IFTYPE_P2P_CLIENT) |
				      BIT(NL80211_IFTYPE_P2P_GO);

	/* TODO:COMBO: mac80211 doesn't yet support more than 1
	 * different channel */
	hw_priv->if_combs[0].num_different_channels = 1;
#ifdef P2P_MULTIVIF
        hw_priv->if_combs[0].max_interfaces = 3;
#else
	hw_priv->if_combs[0].max_interfaces = 2;
#endif
	hw_priv->if_combs[0].limits = hw_priv->if_limits1;
	hw_priv->if_combs[0].n_limits = 2;

	hw_priv->if_combs[1].num_different_channels = 1;

#ifdef P2P_MULTIVIF
        hw_priv->if_combs[1].max_interfaces = 3;
#else
	hw_priv->if_combs[1].max_interfaces = 2;
#endif
	hw_priv->if_combs[1].limits = hw_priv->if_limits2;
	hw_priv->if_combs[1].n_limits = 1;

	hw_priv->if_combs[2].num_different_channels = 1;
#ifdef P2P_MULTIVIF
        hw_priv->if_combs[2].max_interfaces = 3;
#else
	hw_priv->if_combs[2].max_interfaces = 2;
#endif
	hw_priv->if_combs[2].limits = hw_priv->if_limits3;
	hw_priv->if_combs[2].n_limits = 2;

	hw->wiphy->iface_combinations = &hw_priv->if_combs[0];
	hw->wiphy->n_iface_combinations = 3;

}
#endif
static int bes2600_sbus_comm_init(struct bes2600_common *hw_priv)
{
	int ret = 0;

#if defined(FW_DOWNLOAD_BY_USB)
	if (hw_priv->sbus_ops->reset)
		hw_priv->sbus_ops->reset(hw_priv->sbus_priv);
#endif

#ifndef CONFIG_BES2600_WLAN_SPI
	if (hw_priv->sbus_ops->init)
		hw_priv->sbus_ops->init(hw_priv->sbus_priv, hw_priv);
#endif

	/* Register Interrupt Handler */
	hw_priv->sbus_ops->irq_subscribe(hw_priv->sbus_priv,
	        (sbus_irq_handler)bes2600_irq_handler, hw_priv);
	hw_priv->hw_type = HIF_8601_SILICON;
	hw_priv->hw_revision = BES2600_HW_REV_CUT10;

	return ret;
}

int bes2600_core_probe(const struct sbus_ops *sbus_ops,
		      struct sbus_priv *sbus,
		      struct device *pdev,
		      struct bes2600_common **pself)
{
	int err = -ENOMEM;
	//u16 ctrl_reg;
	struct ieee80211_hw *dev;
	struct bes2600_common *hw_priv;

#if defined(CONFIG_BES2600_WLAN_USB)
	struct wsm_operational_mode mode = {
		.power_mode = wsm_power_mode_quiescent,
		.disableMoreFlagUsage = true,
	};
	int if_id;

#ifdef CUSTOM_FEATURE/* To control ps mode */
	char buffer[2];
    savedpsm = mode.power_mode;
	if(access_file(PATH_WIFI_PSM_INFO,buffer,2,1) > 0) {
		if(buffer[0] == 0x30) {
			mode.power_mode = wsm_power_mode_active;
		}
		else
		{
			if(savedpsm)
				mode.power_mode = savedpsm;
			else /* Set default */
				mode.power_mode = wsm_power_mode_quiescent;
		}
		bes2600_info(BES2600_DBG_INIT, "BES2600 : PSM changed to %d\n",mode.power_mode);
	}
	else {
		bes2600_info(BES2600_DBG_INIT, "BES2600 : Using default PSM %d\n",mode.power_mode);
	}
#endif
#endif

	dev = bes2600_init_common(sizeof(struct bes2600_common));
	if (!dev)
		goto err;

	hw_priv = dev->priv;
	hw_priv->sbus_ops = sbus_ops;
	hw_priv->sbus_priv = sbus;
	hw_priv->pdev = pdev;
	SET_IEEE80211_DEV(hw_priv->hw, pdev);

	/* WSM callbacks. */
	hw_priv->wsm_cbc.scan_complete = bes2600_scan_complete_cb;
	hw_priv->wsm_cbc.tx_confirm = bes2600_tx_confirm_cb;
	hw_priv->wsm_cbc.rx = bes2600_rx_cb;
	hw_priv->wsm_cbc.suspend_resume = bes2600_suspend_resume;
	/* hw_priv->wsm_cbc.set_pm_complete = bes2600_set_pm_complete_cb; */
	hw_priv->wsm_cbc.channel_switch = bes2600_channel_switch_cb;

	bes2600_pwr_init(hw_priv);

	err = bes2600_register_bh(hw_priv);
	if (err)
		goto err1;

	err = bes2600_sbus_comm_init(hw_priv);
	if (err)
		goto err2;

	if (bes2600_chrdev_get_fw_type() == BES2600_FW_TYPE_BT) {
	} else if (bes2600_chrdev_get_fw_type() == BES2600_FW_TYPE_WIFI_NO_SIGNAL) {
#ifdef CONFIG_BES2600_WLAN_BES
		*pself = dev->priv;
#endif
#if defined(CONFIG_BES2600_WLAN_SDIO) || defined(CONFIG_BES2600_WLAN_SPI)
		if (bes2600_wifi_start(hw_priv))
			goto err3;
#else
		mdelay(2000);
		if (wait_event_interruptible_timeout(hw_priv->wsm_startup_done,
				hw_priv->wsm_caps.firmwareReady, 10*HZ) <= 0) {
			bes2600_info(BES2600_DBG_INIT, "startup timeout!!!\n");
			err = -ENODEV;
			goto err3;
		}
#endif
#if defined(CONFIG_BES2600_WLAN_USB)
	} else {
		mdelay(2000);

	/*
		hw_priv->sbus_ops->lock(hw_priv->sbus_priv);
		WARN_ON(hw_priv->sbus_ops->set_block_size(hw_priv->sbus_priv,
				SDIO_BLOCK_SIZE));
		hw_priv->sbus_ops->unlock(hw_priv->sbus_priv);

		cw12xx_set_ifce_comb(hw_priv, dev);

		hw_priv->sbus_ops->lock(hw_priv->sbus_priv);
		WARN_ON(hw_priv->sbus_ops->set_block_size(hw_priv->sbus_priv,
			SDIO_BLOCK_SIZE));
		hw_priv->sbus_ops->unlock(hw_priv->sbus_priv);
	*/

		if (wait_event_interruptible_timeout(hw_priv->wsm_startup_done,
					hw_priv->wsm_caps.firmwareReady, 10*HZ) <= 0) {

			/* TODO: Needs to find how to reset device */
			/*       in QUEUE mode properly.           */
			bes2600_info(BES2600_DBG_INIT, "startup timeout!!!\n");
			err = -ENODEV;
			goto err3;
		}
	/*
		WARN_ON(bes2600_reg_write_16(hw_priv, ST90TDS_CONTROL_REG_ID,
						ST90TDS_CONT_WUP_BIT));

		if (bes2600_reg_read_16(hw_priv,ST90TDS_CONTROL_REG_ID, &ctrl_reg))
			WARN_ON(bes2600_reg_read_16(hw_priv,ST90TDS_CONTROL_REG_ID,
							&ctrl_reg));

		WARN_ON(!(ctrl_reg & ST90TDS_CONT_RDY_BIT));
	*/
		for (if_id = 0; if_id < 2; if_id++) {
			/* Set low-power mode. */
			/* Enable multi-TX confirmation */
			WARN_ON(wsm_use_multi_tx_conf(hw_priv, true, if_id));
		}
#endif
	}

	err = bes2600_register_common(dev);
	if (err) {
		goto err3;
	}

	*pself = dev->priv;
	return err;

err3:
	hw_priv->sbus_ops->irq_unsubscribe(hw_priv->sbus_priv);
	if (sbus_ops->reset)
		sbus_ops->reset(sbus);
err2:
	bes2600_unregister_bh(hw_priv);
err1:
	bes2600_free_common(dev);
err:
	return err;
}

void bes2600_core_release(struct bes2600_common *self)
{
	bes2600_unregister_common(self->hw);
	bes2600_free_common(self->hw);
	return;
}

#if defined(CUSTOM_FEATURE) ||(GET_MAC_ADDR_METHOD == 2) || (GET_MAC_ADDR_METHOD == 3) /* To use macaddr and ps mode of customers */
int access_file(char *path, char *buffer, int size, int isRead)
{
	int ret=0;
	struct file *fp;
	mm_segment_t old_fs = get_fs();

	if(isRead)
		fp = filp_open(path,O_RDONLY,S_IRUSR);
	else
		fp = filp_open(path,O_CREAT|O_WRONLY,S_IRUSR);

	if (IS_ERR(fp)) {
		bes2600_err(BES2600_DBG_INIT, "BES2600 : can't open %s\n",path);
		return -1;
	}

	if(isRead)
	{
			fp->f_pos = 0;
			set_fs(KERNEL_DS);
			ret = vfs_read(fp,buffer,size,&fp->f_pos);
			set_fs(old_fs);
	}
	else
	{
			fp->f_pos = 0;
			set_fs(KERNEL_DS);
			ret = vfs_write(fp,buffer,size,&fp->f_pos);
			set_fs(old_fs);
	}
	filp_close(fp,NULL);

	bes2600_info(BES2600_DBG_INIT, "BES2600 : access_file return code(%d)\n",ret);
	return ret;
}
#endif

#ifdef CONFIG_BES2600_WLAN_BES
int bes2600_wifi_start(struct bes2600_common *hw_priv)
{
	int ret, if_id;

	if(hw_priv->sbus_ops->gpio_wake) {
		hw_priv->sbus_ops->gpio_wake(hw_priv->sbus_priv, GPIO_WAKE_FLAG_WIFI_ON);
	}

	if (hw_priv->sbus_ops->sbus_active &&
		WARN_ON((ret = hw_priv->sbus_ops->sbus_active(hw_priv->sbus_priv, SUBSYSTEM_WIFI))))
		goto err;

	if (wait_event_interruptible_timeout(hw_priv->wsm_startup_done,
			hw_priv->wsm_caps.firmwareReady, 10*HZ) <= 0) {

		/* TODO: Needs to find how to reset device */
		/*       in QUEUE mode properly.           */
		bes2600_info(BES2600_DBG_INIT, "startup timeout!!!\n");
		ret = -ENODEV;
		goto err;
	}

	if (bes2600_chrdev_is_signal_mode()) {
		for (if_id = 0; if_id < 2; if_id++) {
			/* Enable multi-TX confirmation */
			if (WARN_ON((ret = wsm_use_multi_tx_conf(hw_priv, true, if_id)))) {
				goto err;
			}
		}
	}
	bes2600_pwr_start(hw_priv);

err:
	if(hw_priv->sbus_ops->gpio_sleep) {
		hw_priv->sbus_ops->gpio_sleep(hw_priv->sbus_priv, GPIO_WAKE_FLAG_WIFI_ON);
	}

	return ret;
}

int bes2600_wifi_stop(struct bes2600_common *hw_priv)
{
	// Segfault: what should ret be set to here?
	int ret = 0;
	unsigned long status = 0;

	status = wait_event_timeout(hw_priv->bh_evt_wq, (!hw_priv->hw_bufs_used), 3 * HZ);
	bes2600_err_with_cond((!status), BES2600_DBG_INIT, "communication exception!");

	if(hw_priv->sbus_ops->gpio_wake) {
		hw_priv->sbus_ops->gpio_wake(hw_priv->sbus_priv, GPIO_WAKE_FLAG_WIFI_OFF);
	}

	bes2600_pwr_stop(hw_priv);

	if (hw_priv->sbus_ops->sbus_deactive &&
		WARN_ON(ret = hw_priv->sbus_ops->sbus_deactive(hw_priv->sbus_priv, SUBSYSTEM_WIFI))) {
		goto err;
	}

	if(hw_priv->sbus_ops->gpio_sleep) {
		hw_priv->sbus_ops->gpio_sleep(hw_priv->sbus_priv, GPIO_WAKE_FLAG_WIFI_OFF);
	}

	memset(&hw_priv->wsm_caps, 0, sizeof(hw_priv->wsm_caps));
	hw_priv->wsm_rx_seq[0] = 0;
	hw_priv->wsm_rx_seq[1] = 0;
	hw_priv->wsm_tx_seq[0] = 0;
	hw_priv->wsm_tx_seq[1] = 0;
#ifdef CONFIG_BES2600_STATIC_SDD
	hw_priv->sdd = NULL;
#else
	#error "TO BE CONTINUED: release SDD file"
#endif
	return ret;

err:
	if(hw_priv->sbus_ops->gpio_sleep) {
		hw_priv->sbus_ops->gpio_sleep(hw_priv->sbus_priv, GPIO_WAKE_FLAG_WIFI_OFF);
	}

	return ret;
}
#endif
