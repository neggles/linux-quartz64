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
#include <linux/init.h>
#include <linux/firmware.h>
#include <linux/etherdevice.h>
#include <linux/vmalloc.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <net/mac80211.h>
#include <net/cfg80211.h>
#include <net/netlink.h>
#include <linux/ctype.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "bes2600_cfgvendor.h"

void bes2600_reg_notifier(struct wiphy *wiphy,
                              struct regulatory_request *request)
{
	const struct ieee80211_regdomain *tmp = NULL;

	/* If wiphy->regd is not cleared, reopening the SoftAP after the sta disconnects from an AP will fail */
	if(request->initiator == NL80211_REGDOM_SET_BY_CORE &&
	   !(wiphy->regulatory_flags & REGULATORY_CUSTOM_REG)) {
		tmp = rtnl_dereference(wiphy->regd);
		if(tmp) {
			rcu_assign_pointer(wiphy->regd, NULL);
			kfree_rcu((struct ieee80211_regdomain *)tmp, rcu_head);
			bes2600_info(BES2600_DBG_ANDROID, "clear regdom when sta disconnects from an ap.\n");
		}
	}
}

static int bes2600_set_country_code(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
#define CNTRY_BUF_SZ	4	/* Country string is 3 bytes + NUL */
	int rem, type;
	char country_code[CNTRY_BUF_SZ] = {0};
	const struct nlattr *iter;

	nla_for_each_attr(iter, data, len, rem) {
		type = nla_type(iter);
		switch (type) {
			case ANDR_WIFI_ATTRIBUTE_COUNTRY:
				memcpy(country_code, nla_data(iter),
					MIN(nla_len(iter), CNTRY_BUF_SZ));
				break;
			default:
				return -EINVAL;
		}
	}

	/* check whether the country is valid or not */
	if(!isalpha(country_code[0]) ||
	   !isalpha(country_code[1])) {
		return -EINVAL;
	}

	/* notify cfg80211 to update database */
	return regulatory_hint(wiphy, country_code);
}

#if 0
static int bes2600_cfgvendor_gscan_get_capabilities(struct wiphy *wiphy,
		struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	dhd_pno_gscan_capabilities_t *reply = NULL;
	unsigned int reply_len = 0;

    // TODO:do something

	if (unlikely(err))
	// TODO:do something

	kfree(reply);
	return err;
}


static int bes2600_cfgvendor_set_scan_cfg(struct wiphy *wiphy,
		     struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	// TODO:do something

}


static int bes2600_cfgvendor_set_batch_scan_cfg(struct wiphy *wiphy,
		struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0, tmp, type;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	gscan_batch_params_t batch_param;
	const struct nlattr *iter;

	batch_param.mscan = batch_param.bestn = 0;
	batch_param.buffer_threshold = GSCAN_BATCH_NO_THR_SET;

	nla_for_each_attr(iter, data, len, tmp) {
		type = nla_type(iter);


	}
	// TODO:do something
	return err;
}


static int bes2600_cfgvendor_initiate_gscan(struct wiphy *wiphy,
		       struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	int type, tmp = len;
	int run = 0xFF;
	int flush = 0;
	const struct nlattr *iter;

	nla_for_each_attr(iter, data, len, tmp) {
		type = nla_type(iter);
	}
	// TODO:do something
		return err;

}


static int bes2600_cfgvendor_enable_full_scan_result(struct wiphy *wiphy,
		struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	int type;
	bool real_time = FALSE;

	type = nla_type(data);

	// TODO:do something

	return err;
}


static int bes2600_cfgvendor_hotlist_cfg(struct wiphy *wiphy,
		    struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	// gscan_hotlist_scan_params_t *hotlist_params;
	int tmp, tmp1, tmp2, type, j = 0, dummy;
	const struct nlattr *outer, *inner, *iter;
	unsigned char flush = 0;
	struct bssid_t *pbssid;

	// TODO:do something

	nla_for_each_attr(iter, data, len, tmp2) {
		type = nla_type(iter);
		switch (type) {

	}
	// TODO:do something
		goto exit;
	}
exit:

	return err;
}


static int bes2600_cfgvendor_significant_change_cfg(struct wiphy *wiphy,
		struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	// gscan_swc_params_t *significant_params;
	int tmp, tmp1, tmp2, type, j = 0;
	const struct nlattr *outer, *inner, *iter;
	unsigned char flush = 0;
	// wl_pfn_significant_bssid_t *pbssid;

	// TODO:do something

	nla_for_each_attr(iter, data, len, tmp2) {
		type = nla_type(iter);

		switch (type) {

	}
}

	// TODO:do something
exit:

	return err;
}


static int bes2600_cfgvendor_gscan_get_batch_results(struct wiphy *wiphy,
		struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	// gscan_results_cache_t *results, *iter;
	unsigned int reply_len, complete = 0, num_results_iter;
	int mem_needed;
	// wifi_gscan_result_t *ptr;
	unsigned short num_scan_ids, num_results;
	struct sk_buff *skb;
	struct nlattr *scan_hdr;

	// TODO:do something
	num_scan_ids = reply_len & 0xFFFF;
	num_results = (reply_len & 0xFFFF0000) >> 16;

	 // TODO:do something
	 return err;
}


static int bes2600_cfgvendor_gscan_get_channel_list(struct wiphy *wiphy,
		struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0, type, band;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);
	unsigned short *reply = NULL;
	unsigned int reply_len = 0, num_channels, mem_needed;
	struct sk_buff *skb;

	type = nla_type(data);

	// TODO:do something

	if (!reply) {
	// TODO:do something
		err = -EINVAL;
		return err;
	}

	// TODO:do something
	if (unlikely(!skb)) {
	// TODO:do something
		err = -ENOMEM;
		goto exit;
	}

	// TODO:do something

	if (unlikely(err))
	// TODO:do something
exit:
	kfree(reply);
	return err;
}


static int bes2600_cfgvendor_rtt_set_config(struct wiphy *wiphy, struct wireless_dev *wdev,
				       const void *data, int len)
{
	int err = 0, rem, rem1, rem2, type;

	const struct nlattr *iter, *iter1, *iter2;

	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);

	if (err < 0) {
	// TODO:do something
		goto exit;
	}

	nla_for_each_attr(iter, data, len, rem) {
		type = nla_type(iter);
		switch (type) {
	// TODO:do something
		}
	}

exit:
	return err;
}


static int bes2600_cfgvendor_rtt_cancel_config(struct wiphy *wiphy, struct wireless_dev *wdev,
		const void *data, int len)
{
	int err = 0, rem, type, target_cnt = 0;
	const struct nlattr *iter;
	struct ether_addr *mac_list = NULL, *mac_addr = NULL;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);

	nla_for_each_attr(iter, data, len, rem) {
		type = nla_type(iter);
		switch (type) {

		}
	}
exit:
	if (mac_list)
		kfree(mac_list);
	return err;
}


static int bes2600_cfgvendor_rtt_get_capability(struct wiphy *wiphy, struct wireless_dev *wdev,
		const void *data, int len)
{
	int err = 0;
	struct bcm_cfg80211 *cfg = wiphy_priv(wiphy);

	if (unlikely(err)) {
	// TODO:do something
		goto exit;
	}
	// TODO:do something

	if (unlikely(err))
	// TODO:do something
exit:
	return err;
}


static int bes2600_cfgvendor_lstats_get_info(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0;

	char *output;

	// TODO:do something
	if (output == NULL) {
	// TODO:do something
	}

	return err;
}


static int bes2600_cfgvendor_lstats_set_info(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0;
	// TODO:do something
	return err;
}


static int bes2600_cfgvendor_lstats_clear_info(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0;
	// TODO:do something
	return err;
}


static int bes2600_cfgvendor_set_rssi_monitor(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
    // TODO:do something

	int err = 0, rem, type;
        const struct nlattr *iter;

    // TODO:do something

	nla_for_each_attr(iter, data, len, rem) {
		type = nla_type(iter);

		switch (type) {
    // TODO:do something
		}
	}

	return err;
}


static int bes2600_cfgvendor_logger_start_logging(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int ret = 0, rem, type;
	char ring_name[32] = {0};
	int log_level = 0, flags = 0, time_intval = 0, threshold = 0;
	const struct nlattr *iter;

	nla_for_each_attr(iter, data, len, rem) {
		type = nla_type(iter);
		switch (type) {
	// TODO:do something
		}
	}

exit:
	return ret;
}


static int bes2600_cfgvendor_logger_get_feature(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void *data, int len)
{
	int err = 0;
	u32 supported_features = 0;

	if (unlikely(err))
	// TODO:do something

	return err;
}


static int bes2600_cfgvendor_logger_get_version(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void *data, int len)
{

	int ret = 0, rem, type;
	int buf_len = 1024;
	char *buf_ptr;
	const struct nlattr *iter;
	gfp_t kflags;

	kflags = in_atomic() ? GFP_ATOMIC : GFP_KERNEL;
	buf_ptr = kzalloc(buf_len, kflags);
	if (!buf_ptr) {
	// TODO:do something
		ret = -ENOMEM;
		goto exit;
	}
	nla_for_each_attr(iter, data, len, rem) {
		type = nla_type(iter);
		switch (type) {
	// TODO:do something
		}
	}
	if (ret < 0) {
	// TODO:do something
		goto exit;
	}


	// TODO:do something
exit:
	kfree(buf_ptr);
	return ret;
}


static int bes2600_cfgvendor_logger_get_ring_status(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int ret = 0;
	int ring_id;
	char ring_buf_name[] = "bes2600_RING_BUFFER";

	struct sk_buff *skb;

	// TODO:do something
	/* Alloc the SKB for vendor_event */

	if (!skb) {
	// TODO:do something
		ret = FAIL;
		goto exit;
	}

	ret = cfg80211_vendor_cmd_reply(skb);

	if (ret) {
	// TODO:do something
	}
exit:
	return ret;
}


static int bes2600_cfgvendor_logger_get_ring_data(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int ret = 0, rem, type;
	char ring_name[32] = {0};
	const struct nlattr *iter;

	nla_for_each_attr(iter, data, len, rem) {
		type = nla_type(iter);
		switch (type) {

	// TODO:do something
				return ret;
		}
	}

	return ret;
}


static int bes2600_cfgvendor_logger_get_firmware_memory_dump(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int ret = WIFI_ERROR_NOT_SUPPORTED;

	return ret;
}


static int bes2600_cfgvendor_logger_start_pkt_fate_monitoring(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int ret = WIFI_SUCCESS;

	return ret;
}


static int bes2600_cfgvendor_logger_get_tx_pkt_fates(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int ret = WIFI_SUCCESS;

	return ret;
}


static int bes2600_cfgvendor_logger_get_rx_pkt_fates(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	int ret = WIFI_SUCCESS;

	return ret;
}


static int bes2600_cfgvendor_set_rand_mac_oui(struct wiphy *wiphy,
		struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0;

	void *devaddr;
	struct net_device *netdev;
	int type, mac_len;
	u8 pno_random_mac_oui[3];
	u8 mac_addr[ETH_ALEN] = {0};
	struct pwrctrl_priv *pwrctl;
	// TODO:do something

	type = nla_type(data);
	mac_len = nla_len(data);
	if (mac_len != 3) {
	// TODO:do something
		return -1;
	}

	if (type == ANDR_WIFI_ATTRIBUTE_RANDOM_MAC_OUI) {
		memcpy(pno_random_mac_oui, nla_data(data), 3);
		print_hex_dump(KERN_DEBUG, "pno_random_mac_oui: ",
			       DUMP_PREFIX_OFFSET, 16, 1, pno_random_mac_oui,
			       3, 1);

 	// TODO:do something
	} else {
	// TODO:do something
		err = -1;
	}


	return err;
}


static int bes2600_cfgvendor_set_nodfs_flag(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void *data, int len)
{
	int err = 0;
	int type;
	u32 nodfs = 0;

	// TODO:do something

	type = nla_type(data);
	if (type == ANDR_WIFI_ATTRIBUTE_NODFS_SET) {
		nodfs = nla_get_u32(data);

	} else {
		err = -EINVAL;
	}

	// TODO:do something

	return err;
}


static int bes2600_cfgvendor_set_nd_offload(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void *data, int len)
{
	int err = 0;
	int type;
	u8 nd_en = 0;

	// TODO:do something

	type = nla_type(data);
	if (type == ANDR_WIFI_ATTRIBUTE_ND_OFFLOAD_VALUE) {
		nd_en = nla_get_u8(data);
		/* ND has been enabled when wow is enabled */
	} else {
		err = -EINVAL;
	}

	return err;
}


static int bes2600_cfgvendor_get_feature_set(struct wiphy *wiphy,
		struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0;
	int reply;

	// TODO:do something
	if (unlikely(err))
	// TODO:do something

	return err;
}


static int bes2600_cfgvendor_get_feature_set_matrix(struct wiphy *wiphy,
		struct wireless_dev *wdev, const void  *data, int len)
{
	int err = 0;
	struct sk_buff *skb;
	int *reply;
	int num, mem_needed, i;

 	// TODO:do something

	if (!reply) {
	// TODO:do something
		err = -EINVAL;
		return err;
	}

	/* Alloc the SKB for vendor_event */
	// TODO:do something
	if (unlikely(!skb)) {
	// TODO:do something
		err = -ENOMEM;
		goto exit;
	}

	nla_put_u32(skb, ANDR_WIFI_ATTRIBUTE_NUM_FEATURE_SET, num);
	for (i = 0; i < num; i++)
		nla_put_u32(skb, ANDR_WIFI_ATTRIBUTE_FEATURE_SET, reply[i]);

	// TODO:do something

	if (unlikely(err))
	// TODO:do something
exit:
	// TODO:do something
	return err;
}
#endif

static const struct wiphy_vendor_command bes2600_own_commands[] = {
    {
        {
            .vendor_id = OUI_GOOGLE,
            .subcmd = WIFI_SUBCMD_SET_COUNTRY_CODE
        },
        .flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
	.policy = VENDOR_CMD_RAW_DATA,
        .doit = bes2600_set_country_code,
    },
	#if 0
    {
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = GSCAN_SUBCMD_GET_CAPABILITIES
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_gscan_get_capabilities
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = GSCAN_SUBCMD_SET_CONFIG
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_set_scan_cfg
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = GSCAN_SUBCMD_SET_SCAN_CONFIG
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_set_batch_scan_cfg
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = GSCAN_SUBCMD_ENABLE_GSCAN
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_initiate_gscan
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = GSCAN_SUBCMD_ENABLE_FULL_SCAN_RESULTS
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_enable_full_scan_result
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = GSCAN_SUBCMD_SET_HOTLIST
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_hotlist_cfg
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = GSCAN_SUBCMD_SET_SIGNIFICANT_CHANGE_CONFIG
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_significant_change_cfg
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = GSCAN_SUBCMD_GET_SCAN_RESULTS
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_gscan_get_batch_results
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = GSCAN_SUBCMD_GET_CHANNEL_LIST
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_gscan_get_channel_list
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = RTT_SUBCMD_SET_CONFIG
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_rtt_set_config
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = RTT_SUBCMD_CANCEL_CONFIG
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_rtt_cancel_config
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = RTT_SUBCMD_GETCAPABILITY
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_rtt_get_capability
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = LSTATS_SUBCMD_GET_INFO
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_lstats_get_info
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = LSTATS_SUBCMD_SET_INFO
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_lstats_set_info
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = LSTATS_SUBCMD_CLEAR_INFO
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_lstats_clear_info
	},
    {
        {
            .vendor_id = OUI_GOOGLE,
            .subcmd = WIFI_SUBCMD_SET_RSSI_MONITOR
        },
        .flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
        .doit = bes2600_cfgvendor_set_rssi_monitor
    },
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = LOGGER_START_LOGGING
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_logger_start_logging
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = LOGGER_GET_FEATURE
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_logger_get_feature
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = LOGGER_GET_VER
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_logger_get_version
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = LOGGER_GET_RING_STATUS
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_logger_get_ring_status
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = LOGGER_GET_RING_DATA
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_logger_get_ring_data
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = LOGGER_TRIGGER_MEM_DUMP
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_logger_get_firmware_memory_dump
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = LOGGER_START_PKT_FATE_MONITORING
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_logger_start_pkt_fate_monitoring
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = LOGGER_GET_TX_PKT_FATES
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_logger_get_tx_pkt_fates
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = LOGGER_GET_RX_PKT_FATES
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_logger_get_rx_pkt_fates
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = WIFI_SUBCMD_SET_PNO_RANDOM_MAC_OUI
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_set_rand_mac_oui
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = WIFI_SUBCMD_NODFS_SET
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_set_nodfs_flag

	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = WIFI_SUBCMD_CONFIG_ND_OFFLOAD
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_set_nd_offload
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = WIFI_SUBCMD_GET_FEATURE_SET
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_get_feature_set
	},
	{
		{
			.vendor_id = OUI_GOOGLE,
			.subcmd = WIFI_SUBCMD_GET_FEATURE_SET_MATRIX
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = bes2600_cfgvendor_get_feature_set_matrix
	}
	#endif
};

static const struct  nl80211_vendor_cmd_info bes2600_own_events[] = {
	{ OUI_GOOGLE, GSCAN_EVENT_SIGNIFICANT_CHANGE_RESULTS },
	{ OUI_GOOGLE, GSCAN_EVENT_HOTLIST_RESULTS_FOUND },
	{ OUI_GOOGLE, GSCAN_EVENT_SCAN_RESULTS_AVAILABLE },
	{ OUI_GOOGLE, GSCAN_EVENT_FULL_SCAN_RESULTS },
	{ OUI_GOOGLE, RTT_EVENT_COMPLETE },
	{ OUI_GOOGLE, GOOGLE_RSSI_MONITOR_EVENT },
	{ OUI_GOOGLE, GSCAN_EVENT_COMPLETE_SCAN },
	{ OUI_GOOGLE, GSCAN_EVENT_HOTLIST_RESULTS_LOST }

};


int bes2600_set_vendor_command(struct wiphy *wiphy)
{

	wiphy->vendor_commands = bes2600_own_commands;
	wiphy->n_vendor_commands = ARRAY_SIZE(bes2600_own_commands);
	wiphy->vendor_events	= bes2600_own_events;
	wiphy->n_vendor_events	= ARRAY_SIZE(bes2600_own_events);

	return 0;
}

int bes2600_vendor_command_detach(struct wiphy *wiphy)
{

	wiphy->vendor_commands  = NULL;
	wiphy->vendor_events    = NULL;
	wiphy->n_vendor_commands = 0;
	wiphy->n_vendor_events  = 0;

	return 0;
}




