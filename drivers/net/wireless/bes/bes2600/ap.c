/*
 * mac80211 STA and AP API for mac80211 BES2600 drivers
 *
 * Copyright (c) 2022, Bestechnic
 * Author:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "bes2600.h"
#include "sta.h"
#include "ap.h"
#include "bh.h"
#include "net/mac80211.h"
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))
#include <linux/umh.h>
#endif
#include "epta_request.h"
#include "epta_coex.h"
#include "txrx_opt.h"

#ifdef AP_HT_CAP_UPDATE
#define HT_INFO_OFFSET 4
#define HT_INFO_MASK 0x0011
#define HT_INFO_IE_LEN 22
#endif
#define BES2600_LINK_ID_GC_TIMEOUT ((unsigned long)(10 * HZ))

#define BES2600_ENABLE_ARP_FILTER_OFFLOAD	3

#define BES2600_KEEP_ALIVE_PERIOD	(20)

#ifndef ERP_INFO_BYTE_OFFSET
#define ERP_INFO_BYTE_OFFSET 2
#endif

#ifdef IPV6_FILTERING
#define BES2600_ENABLE_NDP_FILTER_OFFLOAD	3
#endif /*IPV6_FILTERING*/

static int bes2600_upload_beacon(struct bes2600_vif *priv);
#ifdef PROBE_RESP_EXTRA_IE
static int bes2600_upload_proberesp(struct bes2600_vif *priv);
#endif
static int bes2600_upload_pspoll(struct bes2600_vif *priv);
static int bes2600_upload_null(struct bes2600_vif *priv);
static int bes2600_upload_qosnull(struct bes2600_vif *priv);
static int bes2600_start_ap(struct bes2600_vif *priv);
static int bes2600_update_beaconing(struct bes2600_vif *priv);
/*
static int bes2600_enable_beaconing(struct bes2600_vif *priv,
				   bool enable);
*/
static void __bes2600_sta_notify(struct bes2600_vif *priv,
				enum sta_notify_cmd notify_cmd,
				int link_id);

/* ******************************************************************** */
/* AP API								*/

int bes2600_sta_add(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		   struct ieee80211_sta *sta)
{
	struct bes2600_sta_priv *sta_priv =
			(struct bes2600_sta_priv *)&sta->drv_priv;
	struct bes2600_vif *priv = cw12xx_get_vif_from_ieee80211(vif);
	struct bes2600_link_entry *entry;
	struct sk_buff *skb;
	struct bes2600_common *hw_priv = hw->priv;

#ifdef P2P_MULTIVIF
	WARN_ON(priv->if_id == CW12XX_GENERIC_IF_ID);
#endif

	bes2600_info(BES2600_DBG_AP, "%s mode:%u, MFP:%u\n",
		__FUNCTION__, priv->mode, sta->mfp);

	if (priv->mode == NL80211_IFTYPE_STATION)
		priv->pmf = sta->mfp;

	if (priv->mode != NL80211_IFTYPE_AP)
		return 0;

	sta_priv->priv = priv;
	sta_priv->link_id = bes2600_find_link_id(priv, sta->addr);
	if (WARN_ON(!sta_priv->link_id)) {
		/* Impossible error */
		wiphy_info(priv->hw->wiphy,
			"[AP] No more link IDs available.\n");
		return -ENOENT;
	}

	entry = &priv->link_id_db[sta_priv->link_id - 1];
	spin_lock_bh(&priv->ps_state_lock);
	if ((sta->uapsd_queues & IEEE80211_WMM_IE_STA_QOSINFO_AC_MASK) ==
					IEEE80211_WMM_IE_STA_QOSINFO_AC_MASK)
		priv->sta_asleep_mask |= BIT(sta_priv->link_id);
	entry->status = BES2600_LINK_HARD;
	while ((skb = skb_dequeue(&entry->rx_queue)))
		ieee80211_rx_irqsafe(priv->hw, skb);
	spin_unlock_bh(&priv->ps_state_lock);
#ifdef AP_AGGREGATE_FW_FIX
	hw_priv->connected_sta_cnt++;
	if(hw_priv->connected_sta_cnt>1) {
			wsm_lock_tx(hw_priv);
			WARN_ON(wsm_set_block_ack_policy(hw_priv,
					BES2600_TX_BLOCK_ACK_DISABLED_FOR_ALL_TID,
					BES2600_RX_BLOCK_ACK_DISABLED_FOR_ALL_TID,
					priv->if_id));
			wsm_unlock_tx(hw_priv);
	}
#endif

	return 0;
}

int bes2600_sta_remove(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		      struct ieee80211_sta *sta)
{
	struct bes2600_common *hw_priv = hw->priv;
	struct bes2600_sta_priv *sta_priv =
			(struct bes2600_sta_priv *)&sta->drv_priv;
	struct bes2600_vif *priv = cw12xx_get_vif_from_ieee80211(vif);
	struct bes2600_link_entry *entry;

#ifdef P2P_MULTIVIF
	WARN_ON(priv->if_id == CW12XX_GENERIC_IF_ID);
#endif

	bes2600_info(BES2600_DBG_AP, "%s mode:%u\n", __FUNCTION__, priv->mode);

	if (priv->mode == NL80211_IFTYPE_STATION)
		priv->pmf = false;

	if (priv->mode != NL80211_IFTYPE_AP || !sta_priv->link_id)
		return 0;

	entry = &priv->link_id_db[sta_priv->link_id - 1];
	spin_lock_bh(&priv->ps_state_lock);
	entry->status = BES2600_LINK_RESERVE;
	entry->timestamp = jiffies;
	wsm_lock_tx_async(hw_priv);
	if (queue_work(hw_priv->workqueue, &priv->link_id_work) <= 0)
		wsm_unlock_tx(hw_priv);
	spin_unlock_bh(&priv->ps_state_lock);
	flush_workqueue(hw_priv->workqueue);
#ifdef AP_AGGREGATE_FW_FIX
	hw_priv->connected_sta_cnt--;
	if(hw_priv->connected_sta_cnt <= 1) {
		if ((priv->if_id != 1) ||
			((priv->if_id == 1) && hw_priv->is_go_thru_go_neg)) {
			wsm_lock_tx(hw_priv);
			WARN_ON(wsm_set_block_ack_policy(hw_priv,
						BES2600_TX_BLOCK_ACK_ENABLED_FOR_ALL_TID,
						BES2600_RX_BLOCK_ACK_ENABLED_FOR_ALL_TID,
						priv->if_id));
			wsm_unlock_tx(hw_priv);
		}
	}
#endif

	return 0;
}

static void __bes2600_sta_notify(struct bes2600_vif *priv,
				enum sta_notify_cmd notify_cmd,
				int link_id)
{
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
	u32 bit, prev;

	/* Zero link id means "for all link IDs" */
	if (link_id)
		bit = BIT(link_id);
	else if (WARN_ON_ONCE(notify_cmd != STA_NOTIFY_AWAKE))
		bit = 0;
	else
		bit = priv->link_id_map;
	prev = priv->sta_asleep_mask & bit;

	switch (notify_cmd) {
	case STA_NOTIFY_SLEEP:
		if (!prev) {
			if (priv->buffered_multicasts &&
					!priv->sta_asleep_mask)
				queue_work(hw_priv->workqueue,
					&priv->multicast_start_work);
			priv->sta_asleep_mask |= bit;
		}
		break;
	case STA_NOTIFY_AWAKE:
		if (prev) {
			priv->sta_asleep_mask &= ~bit;
			priv->pspoll_mask &= ~bit;
			if (priv->tx_multicast && link_id &&
					!priv->sta_asleep_mask)
				queue_work(hw_priv->workqueue,
					&priv->multicast_stop_work);
			bes2600_bh_wakeup(hw_priv);
		}
		break;
	}
}

void bes2600_sta_notify(struct ieee80211_hw *dev,
		       struct ieee80211_vif *vif,
		       enum sta_notify_cmd notify_cmd,
		       struct ieee80211_sta *sta)
{
	struct bes2600_vif *priv = cw12xx_get_vif_from_ieee80211(vif);
	struct bes2600_sta_priv *sta_priv =
		(struct bes2600_sta_priv *)&sta->drv_priv;

#ifdef P2P_MULTIVIF
	WARN_ON(priv->if_id == CW12XX_GENERIC_IF_ID);
#endif
	spin_lock_bh(&priv->ps_state_lock);
	__bes2600_sta_notify(priv, notify_cmd, sta_priv->link_id);
	spin_unlock_bh(&priv->ps_state_lock);
}

static void bes2600_ps_notify(struct bes2600_vif *priv,
		      int link_id, bool ps)
{
	if (link_id > CW1250_MAX_STA_IN_AP_MODE)
		return;

	bes2600_dbg(BES2600_DBG_TXRX, "%s for LinkId: %d. STAs asleep: %.8X\n",
			ps ? "Stop" : "Start",
			link_id, priv->sta_asleep_mask);

	/* TODO:COMBO: __bes2600_sta_notify changed. */
	__bes2600_sta_notify(priv,
		ps ? STA_NOTIFY_SLEEP : STA_NOTIFY_AWAKE, link_id);
}

static int bes2600_set_tim_impl(struct bes2600_vif *priv, bool aid0_bit_set)
{
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
	struct sk_buff *skb;
	struct wsm_update_ie update_ie = {
		.what = WSM_UPDATE_IE_BEACON,
		.count = 1,
	};
	u16 tim_offset, tim_length;

	bes2600_dbg(BES2600_DBG_AP, "[AP] %s mcast: %s.\n",
		__func__, aid0_bit_set ? "ena" : "dis");

	skb = ieee80211_beacon_get_tim(priv->hw, priv->vif,
			&tim_offset, &tim_length, 0);
	if (!skb) {
		if (!__bes2600_flush(hw_priv, true, priv->if_id))
			wsm_unlock_tx(hw_priv);
		return -ENOENT;
	}

	if (tim_offset && tim_length >= 6) {
		/* Ignore DTIM count from mac80211:
		 * firmware handles DTIM internally. */
		skb->data[tim_offset + 2] = 0;

		/* Set/reset aid0 bit */
		if (aid0_bit_set)
			skb->data[tim_offset + 4] |= 1;
		else
			skb->data[tim_offset + 4] &= ~1;
	}

	update_ie.ies = &skb->data[tim_offset];
	update_ie.length = tim_length;
	WARN_ON(wsm_update_ie(hw_priv, &update_ie, priv->if_id));

	dev_kfree_skb(skb);

	return 0;
}

void bes2600_set_tim_work(struct work_struct *work)
{
	struct bes2600_vif *priv =
		container_of(work, struct bes2600_vif, set_tim_work);
	(void)bes2600_set_tim_impl(priv, priv->aid0_bit_set);
}

int bes2600_set_tim(struct ieee80211_hw *dev, struct ieee80211_sta *sta,
		   bool set)
{
	struct bes2600_sta_priv *sta_priv =
		(struct bes2600_sta_priv *)&sta->drv_priv;
	struct bes2600_vif *priv = sta_priv->priv;

#ifdef P2P_MULTIVIF
	WARN_ON(priv->if_id == CW12XX_GENERIC_IF_ID);
#endif
	WARN_ON(priv->mode != NL80211_IFTYPE_AP);
	queue_work(priv->hw_priv->workqueue, &priv->set_tim_work);
	return 0;
}

void bes2600_set_cts_work(struct work_struct *work)
{
	struct bes2600_vif *priv =
		container_of(work, struct bes2600_vif, set_cts_work.work);
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);

	u8 erp_ie[3] = {WLAN_EID_ERP_INFO, 0x1, 0};
	struct wsm_update_ie update_ie = {
		.what = WSM_UPDATE_IE_BEACON,
		.count = 1,
		.ies = erp_ie,
		.length = 3,
	};
	u32 erp_info;
	__le32 use_cts_prot;
	down(&hw_priv->conf_lock);
	erp_info = priv->erp_info;
	up(&hw_priv->conf_lock);
	use_cts_prot =
		erp_info & WLAN_ERP_USE_PROTECTION ?
		__cpu_to_le32(1) : 0;

	erp_ie[ERP_INFO_BYTE_OFFSET] = erp_info;

	bes2600_dbg(BES2600_DBG_AP, "[STA] ERP information 0x%x\n", erp_info);

	/* TODO:COMBO: If 2 interfaces are on the same channel they share
	the same ERP values */
	WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_NON_ERP_PROTECTION,
				&use_cts_prot, sizeof(use_cts_prot),
				priv->if_id));
	/* If STA Mode update_ie is not required */
	if (priv->mode != NL80211_IFTYPE_STATION) {
		WARN_ON(wsm_update_ie(hw_priv, &update_ie, priv->if_id));
	}

	return;
}

static int bes2600_set_btcoexinfo(struct bes2600_vif *priv)
{
	struct wsm_override_internal_txrate arg;
	int ret = 0;

	if (priv->mode == NL80211_IFTYPE_STATION) {
		/* Plumb PSPOLL and NULL template */
		WARN_ON(bes2600_upload_pspoll(priv));
		WARN_ON(bes2600_upload_null(priv));
	} else {
		return 0;
	}

	memset(&arg, 0, sizeof(struct wsm_override_internal_txrate));

	if (!priv->vif->p2p) {
		/* STATION mode */
		if (priv->bss_params.operationalRateSet & ~0xF) {
			bes2600_dbg(BES2600_DBG_AP, "[STA] STA has ERP rates\n");
			/* G or BG mode */
			arg.internalTxRate = (__ffs(
			priv->bss_params.operationalRateSet & ~0xF));
		} else {
			bes2600_dbg(BES2600_DBG_AP, "[STA] STA has non ERP rates\n");
			/* B only mode */
			arg.internalTxRate = (__ffs(
			priv->association_mode.basicRateSet));
		}
		arg.nonErpInternalTxRate = (__ffs(
			priv->association_mode.basicRateSet));
	} else {
		/* P2P mode */
		arg.internalTxRate = (__ffs(
			priv->bss_params.operationalRateSet & ~0xF));
		arg.nonErpInternalTxRate = (__ffs(
			priv->bss_params.operationalRateSet & ~0xF));
	}

	bes2600_dbg(BES2600_DBG_AP, "[STA] BTCOEX_INFO"
		"MODE %d, internalTxRate : %x, nonErpInternalTxRate: %x\n",
		priv->mode,
		arg.internalTxRate,
		arg.nonErpInternalTxRate);

	ret = WARN_ON(wsm_write_mib(cw12xx_vifpriv_to_hwpriv(priv),
		WSM_MIB_ID_OVERRIDE_INTERNAL_TX_RATE,
		&arg, sizeof(arg), priv->if_id));

	return ret;
}

void bes2600_bss_info_changed(struct ieee80211_hw *dev,
			     struct ieee80211_vif *vif,
			     struct ieee80211_bss_conf *info,
			     u64 changed)
{
	struct bes2600_common *hw_priv = dev->priv;
	struct bes2600_vif *priv = cw12xx_get_vif_from_ieee80211(vif);
	struct ieee80211_conf *conf = &dev->conf;

#ifdef P2P_MULTIVIF
	if (priv->if_id == CW12XX_GENERIC_IF_ID)
		return;
#endif
	bes2600_info(BES2600_DBG_AP, "BSS CHANGED:	%08llx\n", changed);
	down(&hw_priv->conf_lock);
	if (changed & BSS_CHANGED_BSSID) {
#ifdef CONFIG_BES2600_TESTMODE
		spin_lock_bh(&hw_priv->tsm_lock);
		if (hw_priv->tsm_info.sta_associated) {
			unsigned now = jiffies;
			hw_priv->tsm_info.sta_roamed = 1;
			if ((now - hw_priv->tsm_info.txconf_timestamp_vo) >
			    (now - hw_priv->tsm_info.rx_timestamp_vo))
				hw_priv->tsm_info.use_rx_roaming = 1;
		} else {
			hw_priv->tsm_info.sta_associated = 1;
		}
		spin_unlock_bh(&hw_priv->tsm_lock);
#endif /*CONFIG_BES2600_TESTMODE*/
		memcpy(priv->bssid, info->bssid, ETH_ALEN);
		bes2600_setup_mac_pvif(priv);
	}

	/* TODO: BSS_CHANGED_IBSS */
	if (changed & BSS_CHANGED_ARP_FILTER) {

		struct wsm_arp_ipv4_filter filter = {0};
		int i;
		bes2600_dbg(BES2600_DBG_AP, "[STA] BSS_CHANGED_ARP_FILTER cnt: %d",
				     vif->cfg.arp_addr_cnt);

#ifdef WIFI_BT_COEXIST_EPTA_ENABLE
		if (vif->cfg.arp_addr_cnt > 0) {
			bwifi_change_current_status(hw_priv, BWIFI_STATUS_GOT_IP);
		}
#endif
		/* Currently only one IP address is supported by firmware.
		 * In case of more IPs arp filtering will be disabled. */
		if (vif->cfg.arp_addr_cnt > 0 &&
		    vif->cfg.arp_addr_cnt <= WSM_MAX_ARP_IP_ADDRTABLE_ENTRIES) {
			for (i = 0; i < vif->cfg.arp_addr_cnt; i++) {
				filter.ipv4Address[i] = vif->cfg.arp_addr_list[i];
				bes2600_dbg(BES2600_DBG_AP, "[STA] addr[%d]: 0x%X\n",
					  i, filter.ipv4Address[i]);
			}
			if (vif->type == NL80211_IFTYPE_STATION)
			        filter.enable = (u32)BES2600_ENABLE_ARP_FILTER_OFFLOAD;
			else if (priv->join_status == BES2600_JOIN_STATUS_AP)
			        filter.enable = (u32)(1<<1);
			else
			        filter.enable = 0;
		} else
			filter.enable = 0;

		bes2600_dbg(BES2600_DBG_AP, "[STA] arp ip filter enable: %d\n",
			  __le32_to_cpu(filter.enable));

		if (filter.enable)
			bes2600_set_arpreply(dev, vif);

		priv->filter4 = filter;

		if (filter.enable &&
			(priv->join_status == BES2600_JOIN_STATUS_STA)) {
			/* Firmware requires that value for this 1-byte field must
			 * be specified in units of 500us. Values above the 128ms
			 * threshold are not supported. */
			if (conf->dynamic_ps_timeout >= 0x80)
				priv->powersave_mode.fastPsmIdlePeriod = 0xFF;
			else
				priv->powersave_mode.fastPsmIdlePeriod =
					conf->dynamic_ps_timeout << 1;

			if (priv->setbssparams_done) {
				if (priv->user_power_set_true)
					priv->powersave_mode.pmMode = priv->user_pm_mode;
				else if (!priv->power_set_true)
					priv->powersave_mode.pmMode = WSM_PSM_FAST_PS;
			} else
				priv->powersave_mode.pmMode = WSM_PSM_ACTIVE;
			priv->power_set_true = 0;
			priv->user_power_set_true = 0;

			if(!vif->cfg.ps) {
				bes2600_pwr_set_busy_event(priv->hw_priv, BES_PWR_LOCK_ON_PS_ACTIVE);
			}
		}

		bes2600_pwr_clear_busy_event(priv->hw_priv, BES_PWR_LOCK_ON_GET_IP);
	}

#ifdef IPV6_FILTERING
	if (changed & BSS_CHANGED_NDP_FILTER) {
		struct wsm_ndp_ipv6_filter filter = {0};
		int i;
		u16 *ipv6addr = NULL;

		bes2600_dbg(BES2600_DBG_AP, "[STA] BSS_CHANGED_NDP_FILTER "
				     "enabled: %d, cnt: %d\n",
				     info->ndp_filter_enabled,
				     info->ndp_addr_cnt);

		if (info->ndp_filter_enabled) {
			if (vif->type == NL80211_IFTYPE_STATION)
				filter.enable = (u32)BES2600_ENABLE_NDP_FILTER_OFFLOAD;
			else if ((vif->type == NL80211_IFTYPE_AP))
				filter.enable = (u32)(1<<1);
			else
				filter.enable = 0;
		}

		/* Currently only one IP address is supported by firmware.
		 * In case of more IPs ndp filtering will be disabled. */
		if (info->ndp_addr_cnt > 0 &&
		    info->ndp_addr_cnt <= WSM_MAX_NDP_IP_ADDRTABLE_ENTRIES) {
			for (i = 0; i < info->ndp_addr_cnt; i++) {
				priv->filter6.ipv6Address[i] = filter.ipv6Address[i] = info->ndp_addr_list[i];
				ipv6addr = (u16 *)(&filter.ipv6Address[i]);
				bes2600_dbg(BES2600_DBG_AP, "[STA] ipv6 addr[%d]: %x:%x:%x:%x:%x:%x:%x:%x\n", \
									i, cpu_to_be16(*(ipv6addr + 0)), cpu_to_be16(*(ipv6addr + 1)), \
									cpu_to_be16(*(ipv6addr + 2)), cpu_to_be16(*(ipv6addr + 3)), \
									cpu_to_be16(*(ipv6addr + 4)), cpu_to_be16(*(ipv6addr + 5)), \
									cpu_to_be16(*(ipv6addr + 6)), cpu_to_be16(*(ipv6addr + 7)));
			}
		} else {
			filter.enable = 0;
			for (i = 0; i < info->ndp_addr_cnt; i++) {
				ipv6addr = (u16 *)(&info->ndp_addr_list[i]);
				bes2600_dbg(BES2600_DBG_AP, "[STA] ipv6 addr[%d]: %x:%x:%x:%x:%x:%x:%x:%x\n", \
									i, cpu_to_be16(*(ipv6addr + 0)), cpu_to_be16(*(ipv6addr + 1)), \
									cpu_to_be16(*(ipv6addr + 2)), cpu_to_be16(*(ipv6addr + 3)), \
									cpu_to_be16(*(ipv6addr + 4)), cpu_to_be16(*(ipv6addr + 5)), \
									cpu_to_be16(*(ipv6addr + 6)), cpu_to_be16(*(ipv6addr + 7)));
			}
		}

		bes2600_dbg(BES2600_DBG_AP, "[STA] ndp ip filter enable: %d\n",
			  __le32_to_cpu(filter.enable));

		if (filter.enable)
			bes2600_set_na(dev, vif);

		priv->filter6.enable = filter.enable;

		if (wsm_set_ndp_ipv6_filter(hw_priv, &filter, priv->if_id))
			WARN_ON(1);
#if 0 /*Commented out to disable Power Save in IPv6*/
		if (filter.enable && (priv->join_status == BES2600_JOIN_STATUS_STA) && (priv->vif->p2p) &&
				!(priv->firmware_ps_mode.pmMode & WSM_PSM_FAST_PS)) {
			if(priv->setbssparams_done) {
				struct wsm_set_pm pm = priv->powersave_mode;
				int ret = 0;

				priv->powersave_mode.pmMode = WSM_PSM_FAST_PS;
				ret = bes2600_set_pm(priv, &priv->powersave_mode);
				if(ret) {
					priv->powersave_mode = pm;
				}
			} else {
				priv->powersave_mode.pmMode = WSM_PSM_FAST_PS;
			}
		}
#endif
	}
#endif /*IPV6_FILTERING*/

	if (changed & BSS_CHANGED_BEACON) {
		bes2600_dbg(BES2600_DBG_AP, "BSS_CHANGED_BEACON\n");
#ifdef HIDDEN_SSID
		if (priv->join_status != BES2600_JOIN_STATUS_AP)
		{
			priv->hidden_ssid = info->hidden_ssid;
			priv->ssid_length = info->ssid_len;
			memcpy(priv->ssid, info->ssid, info->ssid_len);
		}
		else
			bes2600_dbg(BES2600_DBG_AP, "priv->join_status=%d\n",priv->join_status);
#endif
		WARN_ON(bes2600_upload_beacon(priv));
		WARN_ON(bes2600_update_beaconing(priv));
	}

	if (changed & BSS_CHANGED_BEACON_ENABLED) {
		bes2600_dbg(BES2600_DBG_AP, "BSS_CHANGED_BEACON_ENABLED dummy\n");
		priv->enable_beacon = info->enable_beacon;
	}

	if (changed & BSS_CHANGED_BEACON_INT) {
		bes2600_dbg(BES2600_DBG_AP, "CHANGED_BEACON_INT\n");
		/* Restart AP only when connected */
		if (priv->join_status == BES2600_JOIN_STATUS_AP)
			WARN_ON(bes2600_update_beaconing(priv));
	}

	if (changed & BSS_CHANGED_ASSOC) {
		wsm_lock_tx(hw_priv);
		priv->wep_default_key_id = -1;
		wsm_unlock_tx(hw_priv);

		if (!vif->cfg.assoc /* && !info->ibss_joined */) {
			#ifdef P2P_STA_COEX
			priv->cqm_link_loss_count = 400;
			priv->cqm_beacon_loss_count = 200;
			#else
			priv->cqm_link_loss_count = 100;
			priv->cqm_beacon_loss_count = 50;
			#endif
			priv->cqm_tx_failure_thold = 0;
		}
		priv->cqm_tx_failure_count = 0;
	}

	if (changed &
	    (BSS_CHANGED_ASSOC |
	     BSS_CHANGED_BASIC_RATES |
	     BSS_CHANGED_ERP_PREAMBLE |
	     BSS_CHANGED_HT |
	     BSS_CHANGED_ERP_SLOT)) {
		int is_combo = 0;
		int i;
		struct bes2600_vif *tmp_priv;
		bes2600_info(BES2600_DBG_AP, "BSS_CHANGED_ASSOC assoc: %d.\n", vif->cfg.assoc);
		if (vif->cfg.assoc) { /* TODO: ibss_joined */
			struct ieee80211_sta *sta = NULL;
			if (info->dtim_period)
				priv->join_dtim_period = info->dtim_period;
			priv->beacon_int = info->beacon_int;

			/* Associated: kill join timeout */
			if(changed & BSS_CHANGED_ASSOC) {
				cancel_delayed_work_sync(&priv->join_timeout);
				bes2600_pwr_clear_busy_event(priv->hw_priv, BES_PWR_LOCK_ON_JOIN);
				bes2600_pwr_set_busy_event(priv->hw_priv, BES_PWR_LOCK_ON_GET_IP);
				txrx_opt_timer_init(priv->hw_priv);
			}

			rcu_read_lock();
			if (info->bssid)
				sta = ieee80211_find_sta(vif, info->bssid);
			if (sta) {
				/* TODO:COMBO:Change this once
				* mac80211 changes are available */
				enum nl80211_channel_type ch_type;
				BUG_ON(!hw_priv->channel);
				hw_priv->ht_info.ht_cap = sta->deflink.ht_cap;
				priv->bss_params.operationalRateSet =
					__cpu_to_le32(
					bes2600_rate_mask_to_wsm(hw_priv,
					sta->deflink.supp_rates[
						hw_priv->channel->band]));
				rcu_read_unlock();
				ch_type = cfg80211_get_chandef_type(&info->chandef);
				bes2600_dbg(BES2600_DBG_AP, "[STA] ch %d, type: %d, HT oper mode: %d\n",
					  hw_priv->channel->hw_value,
					  ch_type, info->ht_operation_mode);
				if ((changed & BSS_CHANGED_ASSOC) &&
					priv->join_status == BES2600_JOIN_STATUS_STA) {
					struct wsm_switch_channel channel;

					hw_priv->ht_info.channel_type = ch_type;
					channel.channelMode = hw_priv->ht_info.channel_type << 4;
					channel.channelSwitchCount = 0;
					channel.newChannelNumber = hw_priv->channel->hw_value;
					wsm_switch_channel(hw_priv, &channel, priv->if_id);
					bes2600_info(BES2600_DBG_AP, "channel type changed to %d !!!\n", hw_priv->ht_info.channel_type);
				}
				if (hw_priv->ht_info.operation_mode != info->ht_operation_mode)
					hw_priv->ht_info.operation_mode = info->ht_operation_mode;

#ifdef WIFI_BT_COEXIST_EPTA_ENABLE
				if (changed & BSS_CHANGED_ASSOC) {
					if (hw_priv->channel->band != NL80211_BAND_2GHZ)
						bwifi_change_current_status(hw_priv, BWIFI_STATUS_CONNECTED_5G);
					else
						bwifi_change_current_status(hw_priv, BWIFI_STATUS_CONNECTED);
				}
#endif
			} else {
				rcu_read_unlock();

				memset(&hw_priv->ht_info, 0,
					sizeof(hw_priv->ht_info));
				priv->bss_params.operationalRateSet = -1;
			}
			//rcu_read_unlock();
			priv->htcap = (sta && bes2600_is_ht(&hw_priv->ht_info));
			bes2600_for_each_vif(hw_priv, tmp_priv, i) {
#ifdef P2P_MULTIVIF
				if ((i == (CW12XX_MAX_VIFS - 1)) || !tmp_priv)
#else
				if (!tmp_priv)
#endif
					continue;
				if (tmp_priv->join_status >= BES2600_JOIN_STATUS_STA)
					is_combo++;
			}

			if (is_combo > 1) {
				hw_priv->vif0_throttle = CW12XX_HOST_VIF0_11BG_THROTTLE;
				hw_priv->vif1_throttle = CW12XX_HOST_VIF1_11BG_THROTTLE;
				bes2600_info(BES2600_DBG_AP, "ASSOC is_combo %d\n",hw_priv->vif0_throttle);
			} else if ((priv->join_status == BES2600_JOIN_STATUS_STA) &&
					priv->htcap) {
				hw_priv->vif0_throttle = CW12XX_HOST_VIF0_11N_THROTTLE;
				hw_priv->vif1_throttle = CW12XX_HOST_VIF1_11N_THROTTLE;
				bes2600_info(BES2600_DBG_AP, "ASSOC HTCAP 11N %d\n",hw_priv->vif0_throttle);
			} else {
				hw_priv->vif0_throttle = CW12XX_HOST_VIF0_11BG_THROTTLE;
				hw_priv->vif1_throttle = CW12XX_HOST_VIF1_11BG_THROTTLE;
				bes2600_info(BES2600_DBG_AP, "ASSOC not_combo 11BG %d\n",hw_priv->vif0_throttle);
			}

			if (sta) {
				__le32 val = 0;
				if (hw_priv->ht_info.operation_mode &
				IEEE80211_HT_OP_MODE_NON_GF_STA_PRSNT) {
					bes2600_info(BES2600_DBG_AP, "[STA]"
						" Non-GF STA present\n");
					/* Non Green field capable STA */
					val = __cpu_to_le32(BIT(1));
				}
				WARN_ON(wsm_write_mib(hw_priv,
					WSM_MID_ID_SET_HT_PROTECTION,
					&val, sizeof(val), priv->if_id));
			}

			priv->association_mode.greenfieldMode =
				bes2600_ht_greenfield(&hw_priv->ht_info);
			priv->association_mode.flags =
				WSM_ASSOCIATION_MODE_SNOOP_ASSOC_FRAMES |
				WSM_ASSOCIATION_MODE_USE_PREAMBLE_TYPE |
				WSM_ASSOCIATION_MODE_USE_HT_MODE |
				WSM_ASSOCIATION_MODE_USE_BASIC_RATE_SET |
				WSM_ASSOCIATION_MODE_USE_MPDU_START_SPACING;
			priv->association_mode.preambleType =
				info->use_short_preamble ?
				WSM_JOIN_PREAMBLE_SHORT :
				WSM_JOIN_PREAMBLE_LONG;
			priv->association_mode.basicRateSet = __cpu_to_le32(
				bes2600_rate_mask_to_wsm(hw_priv,
				info->basic_rates));
			priv->association_mode.mpduStartSpacing =
				bes2600_ht_ampdu_density(&hw_priv->ht_info);

#if defined(CONFIG_BES2600_USE_STE_EXTENSIONS)
			priv->cqm_beacon_loss_count =
					info->cqm_beacon_miss_thold;
			priv->cqm_tx_failure_thold =
					info->cqm_tx_fail_thold;
			priv->cqm_tx_failure_count = 0;
			cancel_delayed_work_sync(&priv->bss_loss_work);
			cancel_delayed_work_sync(&priv->connection_loss_work);
#endif /* CONFIG_BES2600_USE_STE_EXTENSIONS */

			priv->bss_params.beaconLostCount =
					priv->cqm_beacon_loss_count ?
					priv->cqm_beacon_loss_count :
					priv->cqm_link_loss_count;

			priv->bss_params.aid = vif->cfg.aid;

			if (priv->join_dtim_period < 1)
				priv->join_dtim_period = 1;

			bes2600_dbg(BES2600_DBG_AP, "[STA] DTIM %d, interval: %d\n",
				priv->join_dtim_period, priv->beacon_int);
			bes2600_dbg(BES2600_DBG_AP, "[STA] Preamble: %d, " \
				"Greenfield: %d, Aid: %d, " \
				"Rates: 0x%.8X, Basic: 0x%.8X\n",
				priv->association_mode.preambleType,
				priv->association_mode.greenfieldMode,
				priv->bss_params.aid,
				priv->bss_params.operationalRateSet,
				priv->association_mode.basicRateSet);
			WARN_ON(wsm_set_association_mode(hw_priv,
				&priv->association_mode, priv->if_id));
			WARN_ON(wsm_keep_alive_period(hw_priv,
				BES2600_KEEP_ALIVE_PERIOD /* sec */,
				priv->if_id));
			WARN_ON(wsm_set_bss_params(hw_priv, &priv->bss_params,
				priv->if_id));
			priv->setbssparams_done = true;
			WARN_ON(wsm_set_beacon_wakeup_period(hw_priv,
				    priv->beacon_int * priv->join_dtim_period >
				    MAX_BEACON_SKIP_TIME_MS ? 1 :
				    priv->join_dtim_period, 0, priv->if_id));
			if (priv->htcap) {
				wsm_lock_tx(hw_priv);
				/* Statically enabling block ack for TX/RX */
				WARN_ON(wsm_set_block_ack_policy(hw_priv,
					hw_priv->ba_tid_mask, hw_priv->ba_tid_mask,
						priv->if_id));
				wsm_unlock_tx(hw_priv);
			}

			if (priv->vif->p2p) {
				bes2600_dbg(BES2600_DBG_AP,
					"[STA] Setting p2p powersave "
					"configuration.\n");
				WARN_ON(wsm_set_p2p_ps_modeinfo(hw_priv,
					&priv->p2p_ps_modeinfo, priv->if_id));
#if defined(CONFIG_BES2600_USE_STE_EXTENSIONS)
				bes2600_notify_noa(priv, BES2600_NOA_NOTIFICATION_DELAY);
#endif
			}

			if (priv->mode == NL80211_IFTYPE_STATION)
				WARN_ON(bes2600_upload_qosnull(priv));

			if (hw_priv->is_BT_Present)
				WARN_ON(bes2600_set_btcoexinfo(priv));
#if 0
			/* It's better to override internal TX rete; otherwise
			 * device sends RTS at too high rate. However device
			 * can't receive CTS at 1 and 2 Mbps. Well, 5.5 is a
			 * good choice for RTS/CTS, but that means PS poll
			 * will be sent at the same rate - impact on link
			 * budget. Not sure what is better.. */

			/* Update: internal rate selection algorythm is not
			 * bad: if device is not receiving CTS at high rate,
			 * it drops RTS rate.
			 * So, conclusion: if-0 the code. Keep code just for
			 * information:
			 * Do not touch WSM_MIB_ID_OVERRIDE_INTERNAL_TX_RATE! */

			/* ~3 is a bug in device: RTS/CTS is not working at
			 * low rates */

			__le32 internal_tx_rate = __cpu_to_le32(__ffs(
				priv->association_mode.basicRateSet & ~3));
			WARN_ON(wsm_write_mib(priv,
				WSM_MIB_ID_OVERRIDE_INTERNAL_TX_RATE,
				&internal_tx_rate,
				sizeof(internal_tx_rate)));
#endif
		} else {
#ifdef WIFI_BT_COEXIST_EPTA_ENABLE
			if (changed & BSS_CHANGED_ASSOC)
				bwifi_change_current_status(hw_priv, BWIFI_STATUS_DISCONNECTED);
#endif
			memset(&hw_priv->ht_info, 0,
				sizeof(hw_priv->ht_info));
			memset(&priv->association_mode, 0,
				sizeof(priv->association_mode));
			memset(&priv->bss_params, 0, sizeof(priv->bss_params));
		}
	}

	if (changed & (BSS_CHANGED_ASSOC | BSS_CHANGED_ERP_CTS_PROT)) {
		u32 prev_erp_info = priv->erp_info;

		if (priv->join_status == BES2600_JOIN_STATUS_AP) {
			if (info->use_cts_prot)
				priv->erp_info |= WLAN_ERP_USE_PROTECTION;
			else if (!(prev_erp_info & WLAN_ERP_NON_ERP_PRESENT))
				priv->erp_info &= ~WLAN_ERP_USE_PROTECTION;

			if (prev_erp_info != priv->erp_info)
				queue_delayed_work(hw_priv->workqueue,
						&priv->set_cts_work, 0*HZ);
		}
	}

	if (changed & (BSS_CHANGED_ASSOC | BSS_CHANGED_ERP_SLOT)) {
		__le32 slot_time = info->use_short_slot ?
			__cpu_to_le32(9) : __cpu_to_le32(20);
		bes2600_dbg(BES2600_DBG_AP, "[STA] Slot time :%d us.\n",
			__le32_to_cpu(slot_time));
		WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_DOT11_SLOT_TIME,
			&slot_time, sizeof(slot_time), priv->if_id));
	}

	if (changed & (BSS_CHANGED_ASSOC | BSS_CHANGED_CQM)) {
		struct wsm_rcpi_rssi_threshold threshold = {
			.rollingAverageCount = 8,
		};

#if 0
		/* For verification purposes */
		info->cqm_rssi_thold = -50;
		info->cqm_rssi_hyst = 4;
#endif /* 0 */

		bes2600_dbg(BES2600_DBG_AP, "[CQM] RSSI threshold "
			"subscribe: %d +- %d\n",
			info->cqm_rssi_thold, info->cqm_rssi_hyst);
#if defined(CONFIG_BES2600_USE_STE_EXTENSIONS)
		bes2600_dbg(BES2600_DBG_AP, "[CQM] Beacon loss subscribe: %d\n",
			info->cqm_beacon_miss_thold);
		bes2600_dbg(BES2600_DBG_AP, "[CQM] TX failure subscribe: %d\n",
			info->cqm_tx_fail_thold);
		priv->cqm_rssi_thold = info->cqm_rssi_thold;
		priv->cqm_rssi_hyst = info->cqm_rssi_hyst;
#endif /* CONFIG_BES2600_USE_STE_EXTENSIONS */
		if (info->cqm_rssi_thold || info->cqm_rssi_hyst) {
			/* RSSI subscription enabled */
			/* TODO: It's not a correct way of setting threshold.
			 * Upper and lower must be set equal here and adjusted
			 * in callback. However current implementation is much
			 * more relaible and stable. */
			if (priv->cqm_use_rssi) {
				threshold.upperThreshold =
					info->cqm_rssi_thold +
					info->cqm_rssi_hyst;
				threshold.lowerThreshold =
					info->cqm_rssi_thold;
			} else {
				/* convert RSSI to RCPI
				 * RCPI = (RSSI + 110) * 2 */
				threshold.upperThreshold =
					(info->cqm_rssi_thold +
					 info->cqm_rssi_hyst + 110) * 2;
				threshold.lowerThreshold =
					(info->cqm_rssi_thold + 110) * 2;
			}
			threshold.rssiRcpiMode |=
				WSM_RCPI_RSSI_THRESHOLD_ENABLE;
		} else {
			/* There is a bug in FW, see sta.c. We have to enable
			 * dummy subscription to get correct RSSI values. */
			threshold.rssiRcpiMode |=
				WSM_RCPI_RSSI_THRESHOLD_ENABLE |
				WSM_RCPI_RSSI_DONT_USE_UPPER |
				WSM_RCPI_RSSI_DONT_USE_LOWER;
		}
		WARN_ON(wsm_set_rcpi_rssi_threshold(hw_priv, &threshold,
					priv->if_id));

#if defined(CONFIG_BES2600_USE_STE_EXTENSIONS)
		priv->cqm_tx_failure_thold = info->cqm_tx_fail_thold;
		priv->cqm_tx_failure_count = 0;

		if (priv->cqm_beacon_loss_count !=
				info->cqm_beacon_miss_thold) {
			priv->cqm_beacon_loss_count =
				info->cqm_beacon_miss_thold;
			priv->bss_params.beaconLostCount =
				priv->cqm_beacon_loss_count ?
				priv->cqm_beacon_loss_count :
				priv->cqm_link_loss_count;
			/* Make sure we are associated before sending
			 * set_bss_params to firmware */
			if (priv->bss_params.aid) {
				WARN_ON(wsm_set_bss_params(hw_priv,
							   &priv->bss_params,
							   priv->if_id));
				priv->setbssparams_done = true;
			}
		}
#endif /* CONFIG_BES2600_USE_STE_EXTENSIONS */
	}

	if (changed & BSS_CHANGED_BANDWIDTH) {
		enum nl80211_channel_type ch_type = cfg80211_get_chandef_type(&info->chandef);

		if (vif->cfg.assoc &&
		    hw_priv->ht_info.channel_type != ch_type &&
		    priv->join_status == BES2600_JOIN_STATUS_STA) {
			struct wsm_switch_channel channel;

			hw_priv->ht_info.channel_type = ch_type;
			channel.channelMode = hw_priv->ht_info.channel_type << 4;
			channel.channelSwitchCount = 0;
			channel.newChannelNumber = hw_priv->channel->hw_value;
			wsm_switch_channel(hw_priv, &channel, priv->if_id);
			bes2600_info(BES2600_DBG_AP, "channel type changed to %d !!!\n", hw_priv->ht_info.channel_type);
		}
	}

	if (changed & BSS_CHANGED_PS) {
		if (vif->cfg.ps == false)
			priv->powersave_mode.pmMode = WSM_PSM_ACTIVE;
		else if (conf->dynamic_ps_timeout <= 0)
			priv->powersave_mode.pmMode = WSM_PSM_PS;
		else
			priv->powersave_mode.pmMode = WSM_PSM_FAST_PS;

		/* set/clear ps active power busy event */
		if(priv->join_status == BES2600_JOIN_STATUS_STA) {
			if(!vif->cfg.ps) {
				bes2600_pwr_set_busy_event(priv->hw_priv, BES_PWR_LOCK_ON_PS_ACTIVE);
			} else {
				bes2600_pwr_clear_busy_event(priv->hw_priv, BES_PWR_LOCK_ON_PS_ACTIVE);
			}
		}

		bes2600_info(BES2600_DBG_AP, "[STA] Aid: %d, Joined: %s, Powersave: %s\n",
			priv->bss_params.aid,
			priv->join_status == BES2600_JOIN_STATUS_STA ? "yes" : "no",
			priv->powersave_mode.pmMode == WSM_PSM_ACTIVE ? "WSM_PSM_ACTIVE" :
			priv->powersave_mode.pmMode == WSM_PSM_PS ? "WSM_PSM_PS" :
			priv->powersave_mode.pmMode == WSM_PSM_FAST_PS ? "WSM_PSM_FAST_PS" :
			"UNKNOWN");

		/* Firmware requires that value for this 1-byte field must
		 * be specified in units of 500us. Values above the 128ms
		 * threshold are not supported. */
		if (conf->dynamic_ps_timeout >= 0x80)
			priv->powersave_mode.fastPsmIdlePeriod = 0xFF;
		else
			priv->powersave_mode.fastPsmIdlePeriod =
					conf->dynamic_ps_timeout << 1;

		if (priv->join_status == BES2600_JOIN_STATUS_STA &&
				priv->bss_params.aid &&
				priv->setbssparams_done &&
				priv->filter4.enable &&
				priv->powersave_mode.pmMode == WSM_PSM_ACTIVE) {
			bes2600_set_pm(priv, &priv->powersave_mode);
		} else {
			priv->power_set_true = 1;
		}
	}

#if defined(CONFIG_BES2600_USE_STE_EXTENSIONS)
	if (changed & BSS_CHANGED_P2P_PS) {
		struct wsm_p2p_ps_modeinfo *modeinfo;
		modeinfo = &priv->p2p_ps_modeinfo;
		bes2600_dbg(BES2600_DBG_AP, "[AP] BSS_CHANGED_P2P_PS\n");
		bes2600_dbg(BES2600_DBG_AP, "[AP] Legacy PS: %d for AID %d "
			"in %d mode.\n", info->p2p_ps.legacy_ps,
			priv->bss_params.aid, priv->join_status);

		if (info->p2p_ps.legacy_ps >= 0) {
			if (info->p2p_ps.legacy_ps > 0)
				priv->powersave_mode.pmMode = WSM_PSM_PS;
			else
				priv->powersave_mode.pmMode = WSM_PSM_ACTIVE;

			if(info->p2p_ps.ctwindow && info->p2p_ps.opp_ps)
				priv->powersave_mode.pmMode = WSM_PSM_PS;
			if (priv->join_status == BES2600_JOIN_STATUS_STA)
				bes2600_set_pm(priv, &priv->powersave_mode);
		}

		bes2600_dbg(BES2600_DBG_AP, "[AP] CTWindow: %d\n",
			info->p2p_ps.ctwindow);
		if (info->p2p_ps.ctwindow >= 128)
			modeinfo->oppPsCTWindow = 127;
		else if (info->p2p_ps.ctwindow >= 0)
			modeinfo->oppPsCTWindow = info->p2p_ps.ctwindow;

		bes2600_dbg(BES2600_DBG_AP, "[AP] Opportunistic: %d\n",
			info->p2p_ps.opp_ps);
		switch (info->p2p_ps.opp_ps) {
		case 0:
			modeinfo->oppPsCTWindow &= ~(BIT(7));
			break;
		case 1:
			modeinfo->oppPsCTWindow |= BIT(7);
			break;
		default:
			break;
		}

		bes2600_dbg(BES2600_DBG_AP, "[AP] NOA: %d, %d, %d, %d\n",
			info->p2p_ps.count,
			info->p2p_ps.start,
			info->p2p_ps.duration,
			info->p2p_ps.interval);
		/* Notice of Absence */
		modeinfo->count = info->p2p_ps.count;

		if (info->p2p_ps.count) {
			/* In case P2P_GO we need some extra time to be sure
			 * we will update beacon/probe_resp IEs correctly */
#define NOA_DELAY_START_MS	300
			if (priv->join_status == BES2600_JOIN_STATUS_AP)
				modeinfo->startTime =
					__cpu_to_le32(info->p2p_ps.start +
						      NOA_DELAY_START_MS);
			else
				modeinfo->startTime =
					__cpu_to_le32(info->p2p_ps.start);
			modeinfo->duration =
				__cpu_to_le32(info->p2p_ps.duration);
			modeinfo->interval =
				 __cpu_to_le32(info->p2p_ps.interval);
			modeinfo->dtimCount = 1;
			modeinfo->reserved = 0;
		} else {
			modeinfo->dtimCount = 0;
			modeinfo->startTime = 0;
			modeinfo->reserved = 0;
			modeinfo->duration = 0;
			modeinfo->interval = 0;
		}

#if defined(CONFIG_BES2600_STA_DEBUG)
		print_hex_dump_bytes("p2p_set_ps_modeinfo: ",
				     DUMP_PREFIX_NONE,
				     (u8 *)modeinfo,
				     sizeof(*modeinfo));
#endif /* CONFIG_BES2600_STA_DEBUG */
		if (priv->join_status == BES2600_JOIN_STATUS_STA ||
		    priv->join_status == BES2600_JOIN_STATUS_AP) {
			WARN_ON(wsm_set_p2p_ps_modeinfo(hw_priv, modeinfo,
				priv->if_id));
		}

		/* Temporary solution while firmware don't support NOA change
		 * notification yet */
		bes2600_notify_noa(priv, 10);
	}
#endif /* CONFIG_BES2600_USE_STE_EXTENSIONS */

	up(&hw_priv->conf_lock);
}

void bes2600_multicast_start_work(struct work_struct *work)
{
	struct bes2600_vif *priv =
		container_of(work, struct bes2600_vif, multicast_start_work);
	long tmo = priv->join_dtim_period *
			(priv->beacon_int + 20) * HZ / 1024;

	cancel_work_sync(&priv->multicast_stop_work);

	if (!priv->aid0_bit_set) {
		wsm_lock_tx(priv->hw_priv);
		bes2600_set_tim_impl(priv, true);
		priv->aid0_bit_set = true;
		mod_timer(&priv->mcast_timeout, jiffies + tmo);
		wsm_unlock_tx(priv->hw_priv);
	}
}

void bes2600_multicast_stop_work(struct work_struct *work)
{
	struct bes2600_vif *priv =
		container_of(work, struct bes2600_vif, multicast_stop_work);

	if (priv->aid0_bit_set) {
		del_timer_sync(&priv->mcast_timeout);
		wsm_lock_tx(priv->hw_priv);
		priv->aid0_bit_set = false;
		bes2600_set_tim_impl(priv, false);
		wsm_unlock_tx(priv->hw_priv);
	}
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))
void bes2600_mcast_timeout(struct timer_list *t)
{
	struct bes2600_vif *priv = from_timer(priv, t, mcast_timeout);

	wiphy_warn(priv->hw->wiphy,
		"Multicast delivery timeout.\n");
	spin_lock_bh(&priv->ps_state_lock);
	priv->tx_multicast = priv->aid0_bit_set &&
			priv->buffered_multicasts;
	if (priv->tx_multicast)
		bes2600_bh_wakeup(cw12xx_vifpriv_to_hwpriv(priv));
	spin_unlock_bh(&priv->ps_state_lock);
}
#else
void bes2600_mcast_timeout(unsigned long arg)
{
	struct bes2600_vif *priv = (struct bes2600_vif *)arg;

	wiphy_warn(priv->hw->wiphy,
		"Multicast delivery timeout.\n");
	spin_lock_bh(&priv->ps_state_lock);
	priv->tx_multicast = priv->aid0_bit_set &&
			priv->buffered_multicasts;
	if (priv->tx_multicast)
		bes2600_bh_wakeup(cw12xx_vifpriv_to_hwpriv(priv));
	spin_unlock_bh(&priv->ps_state_lock);
}
#endif

int bes2600_ampdu_action(struct ieee80211_hw *hw,
			struct ieee80211_vif *vif,
			struct ieee80211_ampdu_params *params)
{
	/* Aggregation is implemented fully in firmware,
	 * including block ack negotiation.
	 * In case of AMPDU aggregation in RX direction
	 * re-ordering of packets takes place on host. mac80211
	 * needs the ADDBA Request to setup reodering.mac80211 also
	 * sends ADDBA Response which is discarded in the driver as
	 * FW generates the ADDBA Response on its own.*/
	int ret;

	switch (params->action) {
	case IEEE80211_AMPDU_RX_START:
	case IEEE80211_AMPDU_RX_STOP:
		/* Just return OK to mac80211 */
		ret = 0;
		break;
	default:
		ret = -ENOTSUPP;
	}
	return ret;
}

/* ******************************************************************** */
/* WSM callback								*/
void bes2600_suspend_resume(struct bes2600_vif *priv,
			   struct wsm_suspend_resume *arg)
{
	struct bes2600_common *hw_priv =
		cw12xx_vifpriv_to_hwpriv(priv);

	bes2600_dbg(BES2600_DBG_AP, "[AP] %s: %s\n",
			arg->stop ? "stop" : "start",
			arg->multicast ? "broadcast" : "unicast");

	if (arg->multicast) {
		bool cancel_tmo = false;
		spin_lock_bh(&priv->ps_state_lock);
		if (arg->stop) {
			priv->tx_multicast = false;
		} else {
			/* Firmware sends this indication every DTIM if there
			 * is a STA in powersave connected. There is no reason
			 * to suspend, following wakeup will consume much more
			 * power than it could be saved. */
			u32 timeout = priv->join_dtim_period *
				(priv->beacon_int + 20) * HZ / 1024;
			timeout = jiffies_to_msecs(timeout);
			bes2600_pwr_set_busy_event_with_timeout_async(hw_priv,
				BES_PWR_LOCK_ON_MUL_REQ, timeout);

			priv->tx_multicast = priv->aid0_bit_set &&
					priv->buffered_multicasts;
			if (priv->tx_multicast) {
				cancel_tmo = true;
				bes2600_bh_wakeup(hw_priv);
			}
		}
		spin_unlock_bh(&priv->ps_state_lock);
		if (cancel_tmo)
			del_timer_sync(&priv->mcast_timeout);
	} else {
		spin_lock_bh(&priv->ps_state_lock);
		bes2600_ps_notify(priv, arg->link_id, arg->stop);
		spin_unlock_bh(&priv->ps_state_lock);
		if (!arg->stop)
			bes2600_bh_wakeup(hw_priv);
	}
	return;
}

/* ******************************************************************** */
/* AP privates								*/

static int bes2600_upload_beacon(struct bes2600_vif *priv)
{
	int ret = 0;
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
	struct wsm_template_frame frame = {
		.frame_type = WSM_FRAME_TYPE_BEACON,
	};
	struct ieee80211_mgmt *mgmt;
	u8 *erp_inf, *ies, *ht_info;
	u32 ies_len;

	if (priv->vif->p2p ||
			hw_priv->channel->band == NL80211_BAND_5GHZ)
		frame.rate = WSM_TRANSMIT_RATE_6;

	frame.skb = ieee80211_beacon_get(priv->hw, priv->vif, 0);
	if (WARN_ON(!frame.skb))
		return -ENOMEM;

	mgmt = (void *)frame.skb->data;
	ies = mgmt->u.beacon.variable;
	ies_len = frame.skb->len - (u32)(ies - (u8 *)mgmt);

	ht_info = (u8 *)cfg80211_find_ie( WLAN_EID_HT_OPERATION, ies, ies_len);
        if (ht_info) {
		/* Enable RIFS*/
		ht_info[3] |= 8;
        }

	erp_inf = (u8 *)cfg80211_find_ie(WLAN_EID_ERP_INFO, ies, ies_len);
	if (erp_inf) {
		if (erp_inf[ERP_INFO_BYTE_OFFSET]
				& WLAN_ERP_BARKER_PREAMBLE)
			priv->erp_info |= WLAN_ERP_BARKER_PREAMBLE;
		else
			priv->erp_info &= ~WLAN_ERP_BARKER_PREAMBLE;

		if (erp_inf[ERP_INFO_BYTE_OFFSET]
				& WLAN_ERP_NON_ERP_PRESENT) {
			priv->erp_info |= WLAN_ERP_USE_PROTECTION;
			priv->erp_info |= WLAN_ERP_NON_ERP_PRESENT;
		} else {
			priv->erp_info &= ~WLAN_ERP_USE_PROTECTION;
			priv->erp_info &= ~WLAN_ERP_NON_ERP_PRESENT;
		}
	}

#ifdef HIDDEN_SSID
	if (priv->hidden_ssid) {
		u8 *ssid_ie;
		u8 ssid_len;

		bes2600_dbg(BES2600_DBG_AP, "%s: hidden_ssid set\n", __func__);
		ssid_ie = (u8 *)cfg80211_find_ie(WLAN_EID_SSID, ies, ies_len);
		WARN_ON(!ssid_ie);
		ssid_len = ssid_ie[1];
		if (ssid_len) {
			bes2600_dbg(BES2600_DBG_AP, "%s: hidden_ssid with zero content "
					"ssid\n", __func__);
			ssid_ie[1] = 0;
			memmove(ssid_ie + 2, ssid_ie + 2 + ssid_len,
					(ies + ies_len -
					 (ssid_ie + 2 + ssid_len)));
			frame.skb->len -= ssid_len;
		} else {
			pbes2600_dbg(BES2600_DBG_AP, "%s: hidden ssid with ssid len 0"
					" not supported", __func__);
			dev_kfree_skb(frame.skb);
			return -1;
		}
	}
#endif

	ret = wsm_set_template_frame(hw_priv, &frame, priv->if_id);
	if (!ret) {
#ifdef PROBE_RESP_EXTRA_IE
		ret = bes2600_upload_proberesp(priv);
#else
		/* TODO: Distille probe resp; remove TIM
		 * and other beacon-specific IEs */
		*(__le16 *)frame.skb->data =
			__cpu_to_le16(IEEE80211_FTYPE_MGMT |
				      IEEE80211_STYPE_PROBE_RESP);
		frame.frame_type = WSM_FRAME_TYPE_PROBE_RESPONSE;
		/* TODO: Ideally probe response template should separately
		   configured by supplicant through openmac. This is a
		   temporary work-around known to fail p2p group info
		   attribute related tests
		   */
		if (0 /* priv->vif->p2p */)
			ret = wsm_set_probe_responder(priv, true);
		else {
			ret = wsm_set_template_frame(hw_priv, &frame,
					priv->if_id);
			WARN_ON(wsm_set_probe_responder(priv, false));
		}
#endif
	}
	dev_kfree_skb(frame.skb);

	return ret;
}

#ifdef PROBE_RESP_EXTRA_IE
static int bes2600_upload_proberesp(struct bes2600_vif *priv)
{
	int ret = 0;
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
	struct wsm_template_frame frame = {
		.frame_type = WSM_FRAME_TYPE_PROBE_RESPONSE,
	};
#ifdef HIDDEN_SSID
	u8 *ssid_ie;
#endif
	if (priv->vif->p2p || hw_priv->channel->band == NL80211_BAND_5GHZ)
		frame.rate = WSM_TRANSMIT_RATE_6;

	frame.skb = ieee80211_proberesp_get(priv->hw, priv->vif);
	if (WARN_ON(!frame.skb))
		return -ENOMEM;

#ifdef HIDDEN_SSID
	if (priv->hidden_ssid) {
		int offset;
		u8 ssid_len;
		/* we are assuming beacon from upper layer will always contain
		   zero filled ssid for hidden ap. The beacon shall never have
		   ssid len = 0.
		  */

		offset = offsetof(struct ieee80211_mgmt, u.probe_resp.variable);
		ssid_ie = (u8 *)cfg80211_find_ie(WLAN_EID_SSID,
				frame.skb->data + offset,
				frame.skb->len - offset);
		ssid_len = ssid_ie[1];
		if (ssid_len && (ssid_len == priv->ssid_length)) {
			memcpy(ssid_ie + 2, priv->ssid, ssid_len);
		} else {
			bes2600_dbg(BES2600_DBG_AP, "%s: hidden ssid with mismatched ssid_len %d\n",
					__func__, ssid_len);
			dev_kfree_skb(frame.skb);
			return -1;
		}
	}
#endif
	ret = wsm_set_template_frame(hw_priv, &frame,  priv->if_id);
	WARN_ON(wsm_set_probe_responder(priv, false));

	dev_kfree_skb(frame.skb);

	return ret;
}
#endif

static int bes2600_upload_pspoll(struct bes2600_vif *priv)
{
	int ret = 0;
	struct wsm_template_frame frame = {
		.frame_type = WSM_FRAME_TYPE_PS_POLL,
		.rate = 0xFF,
	};


	frame.skb = ieee80211_pspoll_get(priv->hw, priv->vif);
	if (WARN_ON(!frame.skb))
		return -ENOMEM;

	ret = wsm_set_template_frame(cw12xx_vifpriv_to_hwpriv(priv), &frame,
				priv->if_id);

	dev_kfree_skb(frame.skb);

	return ret;
}

static int bes2600_upload_null(struct bes2600_vif *priv)
{
	int ret = 0;
	struct wsm_template_frame frame = {
		.frame_type = WSM_FRAME_TYPE_NULL,
		.rate = 0xFF,
	};

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))
	frame.skb = ieee80211_nullfunc_get(priv->hw, priv->vif, 0, false);
#else
	frame.skb = ieee80211_nullfunc_get(priv->hw, priv->vif);
#endif
	if (WARN_ON(!frame.skb))
		return -ENOMEM;

	ret = wsm_set_template_frame(cw12xx_vifpriv_to_hwpriv(priv),
				&frame, priv->if_id);

	dev_kfree_skb(frame.skb);

	return ret;
}

static int bes2600_upload_qosnull(struct bes2600_vif *priv)
{
	int ret = 0;
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
	struct wsm_template_frame frame = {
		.frame_type = WSM_FRAME_TYPE_QOS_NULL,
		.rate = 0xFF,
	};

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))
	frame.skb = ieee80211_nullfunc_get(priv->hw, priv->vif, 0, true);
#else
	frame.skb = ieee80211_nullfunc_get(priv->hw, priv->vif);
#endif

	if (WARN_ON(!frame.skb))
		return -ENOMEM;

	ret = wsm_set_template_frame(hw_priv, &frame, priv->if_id);

	dev_kfree_skb(frame.skb);

	return ret;
}

/* This API is nolonegr present in WSC */
#if 0
static int bes2600_enable_beaconing(struct bes2600_vif *priv,
				   bool enable)
{
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
	struct wsm_beacon_transmit transmit = {
		.enableBeaconing = enable,
	};

	return wsm_beacon_transmit(hw_priv, &transmit, priv->if_id);
}
#endif

static int start_dhcpd(void)
{
#if 0
	volatile int result=0;
	char cmdPath[]="/bin/bash";
	char cmdText[128];
	char* cmdArgv[]={cmdPath, "-c", cmdText, NULL};
	char* cmdArgv2[]={cmdPath, "-c", "/usr/sbin/dhcpd >> /tmp/log", NULL};
	char* cmdEnvp[]={"HOME=/", "PATH=/sbin:/bin:/usr/bin:/usr/sbin", NULL};
	static int ifname_id = 0;

	snprintf(cmdText, 128, "/sbin/ifconfig p2p-wlan0-%d 192.168.50.1/24 up >> /tmp/log2", ifname_id);
	ifname_id++;

	result=call_usermodehelper(cmdPath,cmdArgv,cmdEnvp, UMH_WAIT_EXEC);
	msleep(100);
	result=call_usermodehelper(cmdPath,cmdArgv2,cmdEnvp, UMH_WAIT_EXEC);
	//msleep(100);
	//result=call_usermodehelper(cmdPath,cmdArgv3,cmdEnvp, UMH_WAIT_EXEC);
#else
	volatile int result=0;
	char cmdPath[]="/bin/bash";
	char* cmdArgv[]={cmdPath, "-c", "/usr/bin/start_dhcpd > /tmp/log", NULL};
	char* cmdEnvp[]={"HOME=/", "PATH=/sbin:/bin:/usr/bin:/usr/sbin", NULL};

	result=call_usermodehelper(cmdPath,cmdArgv,cmdEnvp, UMH_WAIT_EXEC);
#endif
	bes2600_info(BES2600_DBG_AP, "testDriver1 _init exec! The result of call_usermodehelper is %d\n",result);
	bes2600_info(BES2600_DBG_AP, "testDriver1 _init exec! The process is \"%s\",pid is %d\n",current->comm,current->pid);

	return 0;
}


static int bes2600_start_ap(struct bes2600_vif *priv)
{
	int ret;
#ifndef HIDDEN_SSID
	const u8 *ssidie;
	struct sk_buff *skb;
	int offset;
#endif
	struct ieee80211_bss_conf *conf = &priv->vif->bss_conf;
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
	struct wsm_start start = {
		.mode = priv->vif->p2p ?
				WSM_START_MODE_P2P_GO : WSM_START_MODE_AP,
		/* TODO:COMBO:Change once mac80211 support is available */
		.band = (hw_priv->channel->band == NL80211_BAND_5GHZ) ?
				WSM_PHY_BAND_5G : WSM_PHY_BAND_2_4G,
		.channelNumber = hw_priv->channel->hw_value,
		.beaconInterval = conf->beacon_int,
		.DTIMPeriod = conf->dtim_period,
		.preambleType = conf->use_short_preamble ?
				WSM_JOIN_PREAMBLE_SHORT :
				WSM_JOIN_PREAMBLE_LONG,
		.probeDelay = 100,
		.basicRateSet = bes2600_rate_mask_to_wsm(hw_priv,
				conf->basic_rates),
#ifdef P2P_MULTIVIF
		.CTWindow = priv->if_id ? 0xFFFFFFFF : 0, /* it makes addr1's byte4 ^0x80 in firmware,
			which matches with driver's addr2 */
#endif
	};

	struct wsm_switch_channel channel = {
		.channelMode = (cfg80211_get_chandef_type(&conf->chandef)) << 4,
		.channelSwitchCount = 0,
		.newChannelNumber = hw_priv->channel->hw_value,
	};

	struct wsm_inactivity inactivity = {
		.min_inactivity = 9,
		.max_inactivity = 1,
	};

	if (priv->vif->p2p) {
		start_dhcpd();
		hw_priv->ht_info.channel_type = cfg80211_get_chandef_type(&conf->chandef);
	}

	if (priv->if_id)
		start.mode |= WSM_FLAG_MAC_INSTANCE_1;
	else
		start.mode &= ~WSM_FLAG_MAC_INSTANCE_1;

	hw_priv->connected_sta_cnt = 0;

#ifndef HIDDEN_SSID
	/* Get SSID */
	skb = ieee80211_beacon_get(priv->hw, priv->vif, 0);
	if (WARN_ON(!skb))
		return -ENOMEM;

	offset = offsetof(struct ieee80211_mgmt, u.beacon.variable);
	ssidie = cfg80211_find_ie(WLAN_EID_SSID, skb->data + offset,
				  skb->len - offset);

	memset(priv->ssid, 0, sizeof(priv->ssid));
	if (ssidie) {
		priv->ssid_length = ssidie[1];
		if (WARN_ON(priv->ssid_length > sizeof(priv->ssid)))
			priv->ssid_length = sizeof(priv->ssid);
		memcpy(priv->ssid, &ssidie[2], priv->ssid_length);
	} else {
		priv->ssid_length = 0;
	}
	dev_kfree_skb(skb);
#endif

	priv->beacon_int = conf->beacon_int;
	priv->join_dtim_period = conf->dtim_period;

	start.ssidLength = priv->ssid_length;
	memcpy(&start.ssid[0], priv->ssid, start.ssidLength);

	memset(&priv->link_id_db, 0, sizeof(priv->link_id_db));

	bes2600_info(BES2600_DBG_AP, "[AP] ch: %d(%d), bcn: %d(%d), "
		"brt: 0x%.8X, ssid: %.*s.\n",
		start.channelNumber, start.band,
		start.beaconInterval, start.DTIMPeriod,
		start.basicRateSet,
		start.ssidLength, start.ssid);
	ret = WARN_ON(wsm_start(hw_priv, &start, priv->if_id));
	if (!ret)
		ret = wsm_switch_channel(hw_priv, &channel, priv->if_id);

	if (!ret && priv->vif->p2p) {
		bes2600_dbg(BES2600_DBG_AP, "[AP] Setting p2p powersave "
			"configuration.\n");
		WARN_ON(wsm_set_p2p_ps_modeinfo(hw_priv,
			&priv->p2p_ps_modeinfo, priv->if_id));
#if defined(CONFIG_BES2600_USE_STE_EXTENSIONS)
		bes2600_notify_noa(priv, BES2600_NOA_NOTIFICATION_DELAY);
#endif
	}

	/*Set Inactivity time*/
	if (!(strstr(&start.ssid[0], "6.1.12"))) {
		wsm_set_inactivity(hw_priv, &inactivity, priv->if_id);
	}
	if (!ret) {
#ifndef AP_AGGREGATE_FW_FIX
		WARN_ON(wsm_set_block_ack_policy(hw_priv,
			BES2600_TX_BLOCK_ACK_DISABLED_FOR_ALL_TID,
			BES2600_RX_BLOCK_ACK_DISABLED_FOR_ALL_TID, priv->if_id));
#else
		if ((priv->if_id ==2) && !hw_priv->is_go_thru_go_neg)
			WARN_ON(wsm_set_block_ack_policy(hw_priv,
				BES2600_TX_BLOCK_ACK_DISABLED_FOR_ALL_TID,
				BES2600_RX_BLOCK_ACK_DISABLED_FOR_ALL_TID,
				priv->if_id));
		else
		WARN_ON(wsm_set_block_ack_policy(hw_priv,
			BES2600_TX_BLOCK_ACK_ENABLED_FOR_ALL_TID,
			BES2600_RX_BLOCK_ACK_ENABLED_FOR_ALL_TID,
			priv->if_id));
#endif
		priv->join_status = BES2600_JOIN_STATUS_AP;
		bes2600_pwr_set_busy_event(hw_priv, BES_PWR_LOCK_ON_AP);
		/* bes2600_update_filtering(priv); */
	}
	hw_priv->vif0_throttle = CW12XX_HOST_VIF0_11BG_THROTTLE;
	hw_priv->vif1_throttle = CW12XX_HOST_VIF1_11BG_THROTTLE;
	bes2600_info(BES2600_DBG_AP, "AP/GO mode BG THROTTLE %d\n", hw_priv->vif0_throttle);
	return ret;
}

static int bes2600_update_beaconing(struct bes2600_vif *priv)
{
	struct ieee80211_bss_conf *conf = &priv->vif->bss_conf;
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
	struct wsm_reset reset = {
		.link_id = 0,
		.reset_statistics = true,
	};

	if (priv->mode == NL80211_IFTYPE_AP) {
		/* TODO: check if changed channel, band */
		if (priv->join_status != BES2600_JOIN_STATUS_AP ||
		    priv->beacon_int != conf->beacon_int) {
			bes2600_dbg(BES2600_DBG_AP, "ap restarting\n");
			wsm_lock_tx(hw_priv);
			if (priv->join_status != BES2600_JOIN_STATUS_PASSIVE)
				WARN_ON(wsm_reset(hw_priv, &reset,
						  priv->if_id));
			priv->join_status = BES2600_JOIN_STATUS_PASSIVE;
			WARN_ON(bes2600_start_ap(priv));
			wsm_unlock_tx(hw_priv);
		} else
			bes2600_dbg(BES2600_DBG_AP, "ap started join_status: %d\n",
				  priv->join_status);
	}
	return 0;
}

int bes2600_find_link_id(struct bes2600_vif *priv, const u8 *mac)
{
	int i, ret = 0;
	spin_lock_bh(&priv->ps_state_lock);

	for (i = 0; i < CW1250_MAX_STA_IN_AP_MODE; ++i) {
		if (!memcmp(mac, priv->link_id_db[i].mac, ETH_ALEN) &&
				priv->link_id_db[i].status) {
			priv->link_id_db[i].timestamp = jiffies;
			ret = i + 1;
			break;
		}
	}
	spin_unlock_bh(&priv->ps_state_lock);
	return ret;
}

int bes2600_alloc_link_id(struct bes2600_vif *priv, const u8 *mac)
{
	int i, ret = 0;
	unsigned long max_inactivity = 0;
	unsigned long now = jiffies;
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);

	spin_lock_bh(&priv->ps_state_lock);
	for (i = 0; i < CW1250_MAX_STA_IN_AP_MODE; ++i) {
		if (!priv->link_id_db[i].status) {
			ret = i + 1;
			break;
		} else if (priv->link_id_db[i].status != BES2600_LINK_HARD &&
			!hw_priv->tx_queue_stats.link_map_cache[i + 1]) {

			unsigned long inactivity =
					now - priv->link_id_db[i].timestamp;
			if (inactivity < max_inactivity)
				continue;
			max_inactivity = inactivity;
			ret = i + 1;
		}
	}
	if (ret) {
		struct bes2600_link_entry *entry = &priv->link_id_db[ret - 1];
		bes2600_dbg(BES2600_DBG_AP, "[AP] STA added, link_id: %d\n",
			ret);
		entry->status = BES2600_LINK_RESERVE;
		memcpy(&entry->mac, mac, ETH_ALEN);
		memset(&entry->buffered, 0, BES2600_MAX_TID);
		skb_queue_head_init(&entry->rx_queue);
		wsm_lock_tx_async(hw_priv);
		if (queue_work(hw_priv->workqueue, &priv->link_id_work) <= 0)
			wsm_unlock_tx(hw_priv);
	} else {
		wiphy_info(priv->hw->wiphy,
			"[AP] Early: no more link IDs available.\n");
	}

	spin_unlock_bh(&priv->ps_state_lock);
	return ret;
}

void bes2600_link_id_work(struct work_struct *work)
{
	struct bes2600_vif *priv =
		container_of(work, struct bes2600_vif, link_id_work);
	struct bes2600_common *hw_priv = priv->hw_priv;

	wsm_flush_tx(hw_priv);
	bes2600_link_id_gc_work(&priv->link_id_gc_work.work);
	wsm_unlock_tx(hw_priv);
}

void bes2600_link_id_gc_work(struct work_struct *work)
{
	struct bes2600_vif *priv =
		container_of(work, struct bes2600_vif, link_id_gc_work.work);
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
	struct wsm_map_link map_link = {
		.link_id = 0,
	};
	unsigned long now = jiffies;
	unsigned long next_gc = -1;
	long ttl;
	bool need_reset;
	u32 mask;
	int i;

	if (priv->join_status != BES2600_JOIN_STATUS_AP)
		return;

	wsm_lock_tx(hw_priv);
	spin_lock_bh(&priv->ps_state_lock);
	for (i = 0; i < CW1250_MAX_STA_IN_AP_MODE; ++i) {
		need_reset = false;
		mask = BIT(i + 1);
		if (priv->link_id_db[i].status == BES2600_LINK_RESERVE ||
			(priv->link_id_db[i].status == BES2600_LINK_HARD &&
			 !(priv->link_id_map & mask))) {
			if (priv->link_id_map & mask) {
				priv->sta_asleep_mask &= ~mask;
				priv->pspoll_mask &= ~mask;
				need_reset = true;
			}
			priv->link_id_map |= mask;
			if (priv->link_id_db[i].status != BES2600_LINK_HARD)
				priv->link_id_db[i].status = BES2600_LINK_SOFT;
			memcpy(map_link.mac_addr, priv->link_id_db[i].mac,
					ETH_ALEN);
			spin_unlock_bh(&priv->ps_state_lock);
			if (need_reset) {
				WARN_ON(cw12xx_unmap_link(priv, i + 1));
			}
			map_link.link_id = i + 1;
			WARN_ON(wsm_map_link(hw_priv, &map_link, priv->if_id));
			next_gc = min(next_gc, BES2600_LINK_ID_GC_TIMEOUT);
			spin_lock_bh(&priv->ps_state_lock);
		} else if (priv->link_id_db[i].status == BES2600_LINK_SOFT) {
			ttl = priv->link_id_db[i].timestamp - now +
					BES2600_LINK_ID_GC_TIMEOUT;
			if (ttl <= 0) {
				need_reset = true;
				priv->link_id_db[i].status = BES2600_LINK_OFF;
				priv->link_id_map &= ~mask;
				priv->sta_asleep_mask &= ~mask;
				priv->pspoll_mask &= ~mask;
				memset(map_link.mac_addr, 0, ETH_ALEN);
				spin_unlock_bh(&priv->ps_state_lock);
				WARN_ON(cw12xx_unmap_link(priv, i + 1));
				spin_lock_bh(&priv->ps_state_lock);
			} else {
				next_gc = min_t(unsigned long, next_gc, ttl);
			}
#if defined(CONFIG_BES2600_USE_STE_EXTENSIONS)
		} else if (priv->link_id_db[i].status == BES2600_LINK_RESET ||
				priv->link_id_db[i].status ==
				BES2600_LINK_RESET_REMAP) {
			int status = priv->link_id_db[i].status;
			priv->link_id_db[i].status = BES2600_LINK_OFF;
			priv->link_id_db[i].timestamp = now;
			spin_unlock_bh(&priv->ps_state_lock);
			WARN_ON(cw12xx_unmap_link(priv, i + 1));
			if (status == BES2600_LINK_RESET_REMAP) {
				memcpy(map_link.mac_addr,
						priv->link_id_db[i].mac,
						ETH_ALEN);
				map_link.link_id = i + 1;
				WARN_ON(wsm_map_link(hw_priv, &map_link,
						     priv->if_id));
				next_gc = min(next_gc,
					      BES2600_LINK_ID_GC_TIMEOUT);
				priv->link_id_db[i].status =
						priv->link_id_db[i].prev_status;
			}
			spin_lock_bh(&priv->ps_state_lock);
#endif
		}
		if (need_reset) {
			skb_queue_purge(&priv->link_id_db[i].rx_queue);
			bes2600_dbg(BES2600_DBG_AP, "[AP] STA removed, link_id: %d\n",
					i + 1);
		}
	}
	spin_unlock_bh(&priv->ps_state_lock);
	if (next_gc != -1)
		queue_delayed_work(hw_priv->workqueue,
				&priv->link_id_gc_work, next_gc);
	wsm_unlock_tx(hw_priv);
}

#if defined(CONFIG_BES2600_USE_STE_EXTENSIONS)
void bes2600_notify_noa(struct bes2600_vif *priv, int delay)
{
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
	struct cfg80211_p2p_ps p2p_ps = {0};
	struct wsm_p2p_ps_modeinfo *modeinfo;
	modeinfo = &priv->p2p_ps_modeinfo;

	bes2600_dbg(BES2600_DBG_AP, "[AP]: %s called\n", __func__);

	if (priv->join_status != BES2600_JOIN_STATUS_AP)
		return;

	if (delay)
		msleep(delay);

	if (!WARN_ON(wsm_get_p2p_ps_modeinfo(hw_priv, modeinfo))) {
#if defined(CONFIG_BES2600_STA_DEBUG)
		print_hex_dump_bytes("[AP] p2p_get_ps_modeinfo: ",
				     DUMP_PREFIX_NONE,
				     (u8 *)modeinfo,
				     sizeof(*modeinfo));
#endif /* CONFIG_BES2600_STA_DEBUG */
		p2p_ps.opp_ps = !!(modeinfo->oppPsCTWindow & BIT(7));
		p2p_ps.ctwindow = modeinfo->oppPsCTWindow & (~BIT(7));
		p2p_ps.count = modeinfo->count;
		p2p_ps.start = __le32_to_cpu(modeinfo->startTime);
		p2p_ps.duration = __le32_to_cpu(modeinfo->duration);
		p2p_ps.interval = __le32_to_cpu(modeinfo->interval);
		p2p_ps.index = modeinfo->reserved;

		ieee80211_p2p_noa_notify(priv->vif,
					 &p2p_ps,
					 GFP_KERNEL);
	}
}
#endif

int cw12xx_unmap_link(struct bes2600_vif *priv, int link_id)
{
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
	int ret = 0;

	if (is_hardware_cw1250(hw_priv) || is_hardware_cw1260(hw_priv)) {
		struct wsm_map_link maplink = {
			.link_id = link_id,
			.unmap = true,
		};
		if (link_id)
			memcpy(&maplink.mac_addr[0],
				priv->link_id_db[link_id - 1].mac, ETH_ALEN);
		return wsm_map_link(hw_priv, &maplink, priv->if_id);
	} else {
		struct wsm_reset reset = {
			.link_id = link_id,
			.reset_statistics = true,
		};
		ret = wsm_reset(hw_priv, &reset, priv->if_id);
		return ret;
	}
}
#ifdef AP_HT_CAP_UPDATE
void bes2600_ht_info_update_work(struct work_struct *work)
{
        struct sk_buff *skb;
        struct ieee80211_mgmt *mgmt;
        u8 *ht_info, *ies;
        u32 ies_len;
        struct bes2600_vif *priv =
                container_of(work, struct bes2600_vif, ht_info_update_work);
        struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
        struct wsm_update_ie update_ie = {
                .what = WSM_UPDATE_IE_BEACON,
                .count = 1,
        };

        skb = ieee80211_beacon_get(priv->hw, priv->vif, 0);
	if (WARN_ON(!skb))
		return;

        mgmt = (void *)skb->data;
        ies = mgmt->u.beacon.variable;
        ies_len = skb->len - (u32)(ies - (u8 *)mgmt);
        ht_info= (u8 *)cfg80211_find_ie( WLAN_EID_HT_OPERATION, ies, ies_len);
        if(ht_info && priv->ht_info == HT_INFO_MASK) {

        ht_info[HT_INFO_OFFSET] |= 0x11;
        update_ie.ies = ht_info;
        update_ie.length = HT_INFO_IE_LEN;

        WARN_ON(wsm_update_ie(hw_priv, &update_ie, priv->if_id));


        }
	dev_kfree_skb(skb);
}
#endif

