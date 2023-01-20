/*
 * Scan implementation for BES2600 mac80211 drivers
 *
 * Copyright (c) 2022, Bestechnic
 * Author:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/sched.h>
#include "bes2600.h"
#include "scan.h"
#include "sta.h"
#include "pm.h"
#include "epta_request.h"
#include "bes_pwr.h"

static void bes2600_scan_restart_delayed(struct bes2600_vif *priv);

#ifdef CONFIG_BES2600_TESTMODE
static int bes2600_advance_scan_start(struct bes2600_common *hw_priv)
{
	int tmo = 0;
	tmo += hw_priv->advanceScanElems.duration;
	bes2600_pwr_set_busy_event_with_timeout(hw_priv, BES_PWR_LOCK_ON_ADV_SCAN, tmo);
	/* Invoke Advance Scan Duration Timeout Handler */
	queue_delayed_work(hw_priv->workqueue,
		&hw_priv->advance_scan_timeout, tmo * HZ / 1000);
	return 0;
}
#endif

static void bes2600_remove_wps_p2p_ie(struct wsm_template_frame *frame)
{
	u8 *ies;
	u32 ies_len;
	u32 ie_len;
	u32 p2p_ie_len = 0;
	u32 wps_ie_len = 0;

	ies = &frame->skb->data[sizeof(struct ieee80211_hdr_3addr)];
	ies_len = frame->skb->len - sizeof(struct ieee80211_hdr_3addr);

	while (ies_len >= 6) {
		ie_len = ies[1] + 2;
		if ((ies[0] == WLAN_EID_VENDOR_SPECIFIC)
			&& (ies[2] == 0x00 && ies[3] == 0x50 && ies[4] == 0xf2 && ies[5] == 0x04)) {
			wps_ie_len = ie_len;
			memmove(ies, ies + ie_len, ies_len);
			ies_len -= ie_len;

		}
		else if ((ies[0] == WLAN_EID_VENDOR_SPECIFIC) &&
			(ies[2] == 0x50 && ies[3] == 0x6f && ies[4] == 0x9a && ies[5] == 0x09)) {
			p2p_ie_len = ie_len;
			memmove(ies, ies + ie_len, ies_len);
			ies_len -= ie_len;
		} else {
			ies += ie_len;
			ies_len -= ie_len;
		}
	}

	if (p2p_ie_len || wps_ie_len) {
		skb_trim(frame->skb, frame->skb->len - (p2p_ie_len + wps_ie_len));
	}
}

#ifdef CONFIG_BES2600_TESTMODE
static int bes2600_disable_filtering(struct bes2600_vif *priv)
{
	int ret = 0;
	bool bssid_filtering = 0;
	struct wsm_rx_filter rx_filter;
	struct wsm_beacon_filter_control bf_control;
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);

	/* RX Filter Disable */
	rx_filter.promiscuous = 0;
	rx_filter.bssid = 0;
	rx_filter.fcs = 0;
	rx_filter.probeResponder = 0;
	rx_filter.keepalive = 0;
	ret = wsm_set_rx_filter(hw_priv, &rx_filter,
			priv->if_id);

	/* Beacon Filter Disable */
	bf_control.enabled = 0;
	bf_control.bcn_count = 1;
	if (!ret)
		ret = wsm_beacon_filter_control(hw_priv, &bf_control,
					priv->if_id);

	/* BSSID Filter Disable */
	if (!ret)
		ret = wsm_set_bssid_filtering(hw_priv, bssid_filtering,
					 priv->if_id);

	return ret;
}
#endif

static int bes2600_scan_get_first_active_if(struct bes2600_common *hw_priv)
{
	int i = 0;
	struct bes2600_vif *vif;

	bes2600_for_each_vif(hw_priv, vif, i) {
		if (vif->join_status > BES2600_JOIN_STATUS_PASSIVE)
			return i;
	}

	return -1;
}

static int bes2600_scan_start(struct bes2600_vif *priv, struct wsm_scan *scan)
{
	int ret, i;
#ifdef FPGA_SETUP
	int tmo = 5000;
#else
	int tmo = 5000;
#endif
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);


	if (hw_priv->scan_switch_if_id == -1 &&
		hw_priv->ht_info.channel_type > NL80211_CHAN_HT20 &&
		priv->if_id >= 0) {
		hw_priv->scan_switch_if_id = bes2600_scan_get_first_active_if(hw_priv);
		if(hw_priv->scan_switch_if_id >= 0) {
			struct wsm_switch_channel channel;
			channel.channelMode = 0 << 4;
			channel.channelSwitchCount = 0;
			channel.newChannelNumber = hw_priv->channel->hw_value;
			wsm_switch_channel(hw_priv, &channel, hw_priv->scan_switch_if_id);
			bes2600_info(BES2600_DBG_SCAN, "scan start channel type %d num %d\n", hw_priv->ht_info.channel_type, channel.newChannelNumber);
		}
	}
	for (i = 0; i < scan->numOfChannels; ++i)
		tmo += scan->ch[i].maxChannelTime + 10;
	atomic_set(&hw_priv->scan.in_progress, 1);
	atomic_set(&hw_priv->recent_scan, 1);
	queue_delayed_work(hw_priv->workqueue, &hw_priv->scan.timeout,
		tmo * HZ / 1000);
#ifdef P2P_MULTIVIF
	ret = wsm_scan(hw_priv, scan, 0);
#else
	ret = wsm_scan(hw_priv, scan, priv->if_id);
#endif
	if (unlikely(ret)) {
		atomic_set(&hw_priv->scan.in_progress, 0);
		cancel_delayed_work_sync(&hw_priv->scan.timeout);
		bes2600_scan_restart_delayed(priv);
	}
	return ret;
}

#ifdef ROAM_OFFLOAD
static int bes2600_sched_scan_start(struct bes2600_vif *priv, struct wsm_scan *scan)
{
	int ret;
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);

	ret = wsm_scan(hw_priv, scan, priv->if_id);
	if (unlikely(ret)) {
		atomic_set(&hw_priv->scan.in_progress, 0);
	}
	return ret;
}
#endif /*ROAM_OFFLOAD*/

int bes2600_hw_scan(struct ieee80211_hw *hw,
		   struct ieee80211_vif *vif,
		   struct ieee80211_scan_request *hw_req)
{
	struct bes2600_common *hw_priv = hw->priv;
	struct bes2600_vif *priv = cw12xx_get_vif_from_ieee80211(vif);
	struct cfg80211_scan_request *req = &hw_req->req;
	struct wsm_template_frame frame = {
		.frame_type = WSM_FRAME_TYPE_PROBE_REQUEST,
	};
	int i;
	/* Scan when P2P_GO corrupt firmware MiniAP mode */
	if (priv->join_status == BES2600_JOIN_STATUS_AP)
		return -EOPNOTSUPP;
#if 0
	if (work_pending(&priv->offchannel_work) ||
			(hw_priv->roc_if_id != -1)) {
		wiphy_dbg(hw_priv->hw->wiphy, "[SCAN] Offchannel work pending, "
				"ignoring scan work %d\n",  hw_priv->roc_if_id);
		return -EBUSY;
	}
#endif
	if (req->n_ssids == 1 && !req->ssids[0].ssid_len)
		req->n_ssids = 0;

	wiphy_dbg(hw->wiphy, "[SCAN] Scan request for %d SSIDs.\n",
		req->n_ssids);

	if (req->n_ssids > hw->wiphy->max_scan_ssids)
		return -EINVAL;

	bes2600_pwr_set_busy_event(hw_priv, BES_PWR_LOCK_ON_SCAN);

	frame.skb = ieee80211_probereq_get(hw, priv->vif->addr, NULL, 0,
		req->ie_len);
	if (!frame.skb)
		return -ENOMEM;

	if (req->ie_len)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))
		skb_put_data(frame.skb, req->ie, req->ie_len);
#else
		memcpy(skb_put(frame.skb, req->ie_len), req->ie, req->ie_len);
#endif

	/* will be unlocked in bes2600_scan_work() */
	down(&hw_priv->scan.lock);
	down(&hw_priv->conf_lock);

	if (frame.skb) {
		int ret;
		//if (priv->if_id == 0)
		//	bes2600_remove_wps_p2p_ie(&frame);
#ifdef P2P_MULTIVIF
		ret = wsm_set_template_frame(hw_priv, &frame, 0);
#else
		ret = wsm_set_template_frame(hw_priv, &frame,
				priv->if_id);
#endif
#if 0
		if (!ret) {
		/* Host want to be the probe responder. */
				ret = wsm_set_probe_responder(priv, true);
		}
#endif
		if (ret) {
			up(&hw_priv->conf_lock);
			up(&hw_priv->scan.lock);
			dev_kfree_skb(frame.skb);
			return ret;
		}
	}

	wsm_vif_lock_tx(priv);

	BUG_ON(hw_priv->scan.req);
	hw_priv->scan.req = req;
	hw_priv->scan.n_ssids = 0;
	hw_priv->scan.status = 0;
	hw_priv->scan.begin = &req->channels[0];
	hw_priv->scan.curr = hw_priv->scan.begin;
	hw_priv->scan.end = &req->channels[req->n_channels];
	hw_priv->scan.output_power = hw_priv->output_power;
	hw_priv->scan.if_id = priv->if_id;
	/* TODO:COMBO: Populate BIT4 in scanflags to decide on which MAC
	 * address the SCAN request will be sent */
	bes2600_info(BES2600_DBG_SCAN, "%s %d if_id:%d,num_channel:%d.\n", __func__, __LINE__, priv->if_id, req->n_channels);

	for (i = 0; i < req->n_ssids; ++i) {
		struct wsm_ssid *dst =
			&hw_priv->scan.ssids[hw_priv->scan.n_ssids];
		BUG_ON(req->ssids[i].ssid_len > sizeof(dst->ssid));
		memcpy(&dst->ssid[0], req->ssids[i].ssid,
			sizeof(dst->ssid));
		dst->length = req->ssids[i].ssid_len;
		++hw_priv->scan.n_ssids;
	}

	up(&hw_priv->conf_lock);

	if (frame.skb)
		dev_kfree_skb(frame.skb);
#ifdef WIFI_BT_COEXIST_EPTA_ENABLE
	bwifi_change_current_status(hw_priv, BWIFI_STATUS_SCANNING);
#endif
	queue_work(hw_priv->workqueue, &hw_priv->scan.work);

	return 0;
}

#ifdef ROAM_OFFLOAD
int bes2600_hw_sched_scan_start(struct ieee80211_hw *hw,
		   struct ieee80211_vif *vif,
		   struct cfg80211_sched_scan_request *req,
		   struct ieee80211_sched_scan_ies *ies)
{
	struct bes2600_common *hw_priv = hw->priv;
	struct bes2600_vif *priv = cw12xx_get_vif_from_ieee80211(vif);
	struct wsm_template_frame frame = {
		.frame_type = WSM_FRAME_TYPE_PROBE_REQUEST,
	};
	int i;

	wiphy_warn(hw->wiphy, "[SCAN] Scheduled scan request-->.\n");

	if (!priv->vif)
		return -EINVAL;

	/* Scan when P2P_GO corrupt firmware MiniAP mode */
	if (priv->join_status == BES2600_JOIN_STATUS_AP)
		return -EOPNOTSUPP;

	wiphy_warn(hw->wiphy, "[SCAN] Scheduled scan: n_ssids %d, ssid[0].len = %d\n", req->n_ssids, req->ssids[0].ssid_len);
	if (req->n_ssids == 1 && !req->ssids[0].ssid_len)
		req->n_ssids = 0;

	wiphy_dbg(hw->wiphy, "[SCAN] Scan request for %d SSIDs.\n",
		req->n_ssids);

	if (req->n_ssids > hw->wiphy->max_scan_ssids)
		return -EINVAL;

	frame.skb = ieee80211_probereq_get(hw, priv->vif->addr, NULL, 0,
		req->ie_len);
	if (!frame.skb)
		return -ENOMEM;

	/* will be unlocked in bes2600_scan_work() */
	down(&hw_priv->scan.lock);
	down(&hw_priv->conf_lock);
	if (frame.skb) {
		int ret;
		if (priv->if_id == 0)
			bes2600_remove_wps_p2p_ie(&frame);
		ret = wsm_set_template_frame(hw_priv, &frame, priv->if_id);
		if (0 == ret) {
			/* Host want to be the probe responder. */
			ret = wsm_set_probe_responder(priv, true);
		}
		if (ret) {
			up(&hw_priv->conf_lock);
			up(&hw_priv->scan.lock);
			dev_kfree_skb(frame.skb);
			return ret;
		}
	}

	wsm_lock_tx(hw_priv);

	BUG_ON(hw_priv->scan.req);
	hw_priv->scan.sched_req = req;
	hw_priv->scan.n_ssids = 0;
	hw_priv->scan.status = 0;
	hw_priv->scan.begin = &req->channels[0];
	hw_priv->scan.curr = hw_priv->scan.begin;
	hw_priv->scan.end = &req->channels[req->n_channels];
	hw_priv->scan.output_power = hw_priv->output_power;

	for (i = 0; i < req->n_ssids; ++i) {
		struct wsm_ssid *dst =
			&hw_priv->scan.ssids[hw_priv->scan.n_ssids];
		BUG_ON(req->ssids[i].ssid_len > sizeof(dst->ssid));
		memcpy(&dst->ssid[0], req->ssids[i].ssid,
			sizeof(dst->ssid));
		dst->length = req->ssids[i].ssid_len;
		++hw_priv->scan.n_ssids;
		{
			u8 j;
			wiphy_warn(hw->wiphy, "[SCAN] SSID %d\n",i);
			for(j=0; j<req->ssids[i].ssid_len; j++)
				wiphy_warn(priv->hw->wiphy, "[SCAN] 0x%x\n", req->ssids[i].ssid[j]);
		}
	}

	up(&hw_priv->conf_lock);

	if (frame.skb)
		dev_kfree_skb(frame.skb);
	queue_work(hw_priv->workqueue, &hw_priv->scan.swork);
	wiphy_warn(hw->wiphy, "<--[SCAN] Scheduled scan request.\n");
	return 0;
}
#endif /*ROAM_OFFLOAD*/
void bes2600_scan_work(struct work_struct *work)
{
	struct bes2600_common *hw_priv = container_of(work,
						struct bes2600_common,
						scan.work);
	struct bes2600_vif *priv, *vif;
	struct ieee80211_channel **it;
	struct wsm_scan scan = {
		.scanType = WSM_SCAN_TYPE_FOREGROUND,
		.scanFlags = 0, /* TODO:COMBO */
		//.scanFlags = WSM_SCAN_FLAG_SPLIT_METHOD, /* TODO:COMBO */
	};
	bool first_run;
	int i;
	const u32 ProbeRequestTime  = 2;
	const u32 ChannelRemainTime = 15;
#ifdef WIFI_BT_COEXIST_EPTA_ENABLE
	u32 minChannelTime;
#endif
	u32 maxChannelTime;
#ifdef CONFIG_BES2600_TESTMODE
	int ret = 0;
	u16 advance_scan_req_channel = hw_priv->scan.begin[0]->hw_value;
#endif
	priv = __cw12xx_hwpriv_to_vifpriv(hw_priv, hw_priv->scan.if_id);

	/*TODO: COMBO: introduce locking so vif is not removed in meanwhile */
	if (!priv) {
		wiphy_warn(hw_priv->hw->wiphy, "[SCAN] interface removed, "
			   "ignoring scan work\n");
		return;
	}

	if (priv->if_id)
		scan.scanFlags |= WSM_FLAG_MAC_INSTANCE_1;
	else
		scan.scanFlags &= ~WSM_FLAG_MAC_INSTANCE_1;

	bes2600_for_each_vif(hw_priv, vif, i) {
#ifdef P2P_MULTIVIF
		if ((i == (CW12XX_MAX_VIFS - 1)) || !vif)
#else
		if (!vif)
#endif
			continue;
		if (vif->bss_loss_status > BES2600_BSS_LOSS_NONE)
			scan.scanFlags |= WSM_SCAN_FLAG_FORCE_BACKGROUND;
	}
	first_run = hw_priv->scan.begin == hw_priv->scan.curr &&
			hw_priv->scan.begin != hw_priv->scan.end;

	if (first_run) {
		/* Firmware gets crazy if scan request is sent
		 * when STA is joined but not yet associated.
		 * Force unjoin in this case. */
		if (cancel_delayed_work_sync(&priv->join_timeout) > 0) {
			bes2600_join_timeout(&priv->join_timeout.work);
		}
	}
	down(&hw_priv->conf_lock);
	if (first_run) {
#ifdef CONFIG_BES2600_TESTMODE
		/* Passive Scan - Serving Channel Request Handling */
		if (hw_priv->enable_advance_scan &&
			(hw_priv->advanceScanElems.scanMode ==
				BES2600_SCAN_MEASUREMENT_PASSIVE) &&
			(priv->join_status == BES2600_JOIN_STATUS_STA) &&
			(hw_priv->channel->hw_value ==
				advance_scan_req_channel)) {
			/* If Advance Scan Request is for Serving Channel Device
			 * should be Active and Filtering Should be Disable */
			if (priv->powersave_mode.pmMode & WSM_PSM_PS) {
				struct wsm_set_pm pm = priv->powersave_mode;
				pm.pmMode = WSM_PSM_ACTIVE;
				wsm_set_pm(hw_priv, &pm, priv->if_id);
			}
			/* Disable Rx Beacon and Bssid filter */
			ret = bes2600_disable_filtering(priv);
			if (ret)
				wiphy_err(hw_priv->hw->wiphy,
				"%s: Disable BSSID or Beacon filtering failed: %d.\n",
				__func__, ret);
		} else if (hw_priv->enable_advance_scan &&
			(hw_priv->advanceScanElems.scanMode ==
				BES2600_SCAN_MEASUREMENT_PASSIVE) &&
			(priv->join_status == BES2600_JOIN_STATUS_STA)) {
				if (priv->join_status == BES2600_JOIN_STATUS_STA &&
					!(priv->powersave_mode.pmMode & WSM_PSM_PS)) {
					struct wsm_set_pm pm = priv->powersave_mode;
					pm.pmMode = WSM_PSM_PS;
					bes2600_set_pm(priv, &pm);
				}
		} else {
#endif
#if 0
			if (priv->join_status == BES2600_JOIN_STATUS_STA &&
					!(priv->powersave_mode.pmMode & WSM_PSM_PS)) {
				struct wsm_set_pm pm = priv->powersave_mode;
				pm.pmMode = WSM_PSM_PS;
				bes2600_set_pm(priv, &pm);
			} else
#endif
			if (priv->join_status == BES2600_JOIN_STATUS_MONITOR) {
				/* FW bug: driver has to restart p2p-dev mode
				 * after scan */
				bes2600_disable_listening(priv);
			}
#ifdef CONFIG_BES2600_TESTMODE
		}
#endif
	}

	if (!hw_priv->scan.req || (hw_priv->scan.curr == hw_priv->scan.end)) {
		struct cfg80211_scan_info info = {
			.aborted = hw_priv->scan.status ? 1 : 0,
		};

#ifdef CONFIG_BES2600_TESTMODE
		if (hw_priv->enable_advance_scan &&
			(hw_priv->advanceScanElems.scanMode ==
				BES2600_SCAN_MEASUREMENT_PASSIVE) &&
			(priv->join_status == BES2600_JOIN_STATUS_STA) &&
			(hw_priv->channel->hw_value ==
				advance_scan_req_channel)) {
			/* WSM Lock should be held here for WSM APIs */
			wsm_vif_lock_tx(priv);
			/* wsm_lock_tx(priv); */
			/* Once Duration is Over, enable filtering
			 * and Revert Back Power Save */
			if (priv->powersave_mode.pmMode & WSM_PSM_PS)
				wsm_set_pm(hw_priv, &priv->powersave_mode,
					priv->if_id);
			bes2600_update_filtering(priv);
		} else {
			if (!hw_priv->enable_advance_scan) {
#endif
				if (hw_priv->scan.output_power != hw_priv->output_power)
				/* TODO:COMBO: Change when mac80211 implementation
				 * is available for output power also */
#ifdef P2P_MULTIVIF
					WARN_ON(wsm_set_output_power(hw_priv,
						hw_priv->output_power * 10,
						priv->if_id ? 0 : 0));
#else
					WARN_ON(wsm_set_output_power(hw_priv,
						hw_priv->output_power * 10,
						priv->if_id));
#endif
#ifdef CONFIG_BES2600_TESTMODE
			}
		}
#endif
#if 0
		if (priv->join_status == BES2600_JOIN_STATUS_STA &&
				!(priv->powersave_mode.pmMode & WSM_PSM_PS))
			bes2600_set_pm(priv, &priv->powersave_mode);
#endif
		if (hw_priv->scan.status < 0)
			wiphy_info(priv->hw->wiphy,
					"[SCAN] Scan failed (%d).\n",
					hw_priv->scan.status);
		else if (hw_priv->scan.req)
			wiphy_info(priv->hw->wiphy,
					"[SCAN] Scan completed.\n");
		else
			wiphy_info(priv->hw->wiphy,
					"[SCAN] Scan canceled.\n");

#ifdef WIFI_BT_COEXIST_EPTA_ENABLE
		if (priv->join_status == BES2600_JOIN_STATUS_STA) {
			if (hw_priv->channel->band != NL80211_BAND_2GHZ)
				bwifi_change_current_status(hw_priv, BWIFI_STATUS_GOT_IP_5G);
			else
				bwifi_change_current_status(hw_priv, BWIFI_STATUS_GOT_IP);
		} else {
			bwifi_change_current_status(hw_priv, BWIFI_STATUS_IDLE);
		}
#endif
		bes2600_info(BES2600_DBG_SCAN, "%s %d %d.", __func__, __LINE__, hw_priv->ht_info.channel_type);
		/* switch to previous channel and bw mode after scan done */
		if (hw_priv->scan_switch_if_id >= 0) {
			struct wsm_switch_channel channel;
			channel.channelMode = hw_priv->ht_info.channel_type << 4;
			channel.channelSwitchCount = 0;
			channel.newChannelNumber = hw_priv->channel->hw_value;
			wsm_switch_channel(hw_priv, &channel, hw_priv->scan_switch_if_id);
			hw_priv->scan_switch_if_id = -1;
			bes2600_info(BES2600_DBG_SCAN, "scan done channel type %d num %d\n", hw_priv->ht_info.channel_type, channel.newChannelNumber);
		}

		hw_priv->scan.req = NULL;
		bes2600_scan_restart_delayed(priv);
#ifdef CONFIG_BES2600_TESTMODE
		hw_priv->enable_advance_scan = false;
#endif /* CONFIG_BES2600_TESTMODE */
		wsm_unlock_tx(hw_priv);
		up(&hw_priv->conf_lock);
		bes2600_pwr_clear_busy_event(hw_priv, BES_PWR_LOCK_ON_SCAN);
		ieee80211_scan_completed(hw_priv->hw, &info);
		up(&hw_priv->scan.lock);
		return;
	} else {
		struct ieee80211_channel *first = *hw_priv->scan.curr;
		for (it = hw_priv->scan.curr + 1, i = 1;
		     it != hw_priv->scan.end &&
				i < WSM_SCAN_MAX_NUM_OF_CHANNELS;
		     ++it, ++i) {
			if ((*it)->band != first->band)
				break;
			// Doen't split scan req in case of EPTA error after scan req
			if (((*it)->flags ^ first->flags) &
					IEEE80211_CHAN_NO_IR)
				break;
			if (!(first->flags & IEEE80211_CHAN_NO_IR) &&
			    (*it)->max_power != first->max_power)
				break;
		}
		scan.band = first->band;

		if (hw_priv->scan.req->no_cck)
			scan.maxTransmitRate = WSM_TRANSMIT_RATE_6;
		else
			scan.maxTransmitRate = WSM_TRANSMIT_RATE_1;
#ifdef CONFIG_BES2600_TESTMODE
		if (hw_priv->enable_advance_scan) {
			if (hw_priv->advanceScanElems.scanMode ==
				BES2600_SCAN_MEASUREMENT_PASSIVE)
				scan.numOfProbeRequests = 0;
			else
				scan.numOfProbeRequests = 2;
		} else {
#endif
			/* TODO: Is it optimal? */
			scan.numOfProbeRequests =
				(first->flags & IEEE80211_CHAN_NO_IR) ? 0 : 2;
#ifdef CONFIG_BES2600_TESTMODE
		}
#endif /* CONFIG_BES2600_TESTMODE */
		scan.numOfSSIDs = hw_priv->scan.n_ssids;
		scan.ssids = &hw_priv->scan.ssids[0];
		scan.numOfChannels = it - hw_priv->scan.curr;
		/* TODO: Is it optimal? */
		scan.probeDelay = 100;
		/* It is not stated in WSM specification, however
		 * FW team says that driver may not use FG scan
		 * when joined. */
		if (priv->join_status == BES2600_JOIN_STATUS_STA) {
			scan.scanType = WSM_SCAN_TYPE_BACKGROUND;
			scan.scanFlags = WSM_SCAN_FLAG_FORCE_BACKGROUND;
		}
		scan.ch = kzalloc((it - hw_priv->scan.curr) *
			sizeof(struct wsm_scan_ch), GFP_KERNEL);
		if (!scan.ch) {
			hw_priv->scan.status = -ENOMEM;
			goto fail;
		}
		maxChannelTime = (scan.numOfSSIDs * scan.numOfProbeRequests *
			ProbeRequestTime) + ChannelRemainTime;
		maxChannelTime = (maxChannelTime < 35) ? 35 : maxChannelTime;

#ifdef WIFI_BT_COEXIST_EPTA_ENABLE
		if (scan.band == NL80211_BAND_2GHZ) {
			coex_calc_wifi_scan_time(&minChannelTime, &maxChannelTime);
		} else {
			minChannelTime = 110;
			maxChannelTime = 110;
		}
#endif

		for (i = 0; i < scan.numOfChannels; ++i) {
			scan.ch[i].number = hw_priv->scan.curr[i]->hw_value;
#ifdef CONFIG_BES2600_TESTMODE
			if (hw_priv->enable_advance_scan) {
				scan.ch[i].minChannelTime =
					hw_priv->advanceScanElems.duration;
				scan.ch[i].maxChannelTime =
					hw_priv->advanceScanElems.duration;
			} else {
#endif

#ifndef WIFI_BT_COEXIST_EPTA_ENABLE
				if (hw_priv->scan.curr[i]->flags & IEEE80211_CHAN_NO_IR) {
					scan.ch[i].minChannelTime = 40;
					scan.ch[i].maxChannelTime = 100;
				}
				else {
					//TODO: modify maxChannelTime
					scan.ch[i].minChannelTime = 15;
					scan.ch[i].maxChannelTime = maxChannelTime;
				}
#else
				scan.ch[i].minChannelTime = minChannelTime;
				scan.ch[i].maxChannelTime = maxChannelTime;
#endif

#ifdef CONFIG_BES2600_TESTMODE
			}
#endif
		}
#ifdef CONFIG_BES2600_TESTMODE
		if (!hw_priv->enable_advance_scan) {
#endif
			if (!(first->flags & IEEE80211_CHAN_NO_IR) &&
			    hw_priv->scan.output_power != first->max_power) {
				hw_priv->scan.output_power = first->max_power;
				/* TODO:COMBO: Change after mac80211 implementation
			 	* complete */
#ifdef P2P_MULTIVIF
				WARN_ON(wsm_set_output_power(hw_priv,
						hw_priv->scan.output_power * 10,
						priv->if_id ? 0 : 0));
#else
				WARN_ON(wsm_set_output_power(hw_priv,
						hw_priv->scan.output_power * 10,
						priv->if_id));
#endif
			}
#ifdef CONFIG_BES2600_TESTMODE
		}
#endif
#ifdef CONFIG_BES2600_TESTMODE
		if (hw_priv->enable_advance_scan &&
			(hw_priv->advanceScanElems.scanMode ==
				BES2600_SCAN_MEASUREMENT_PASSIVE) &&
			(priv->join_status == BES2600_JOIN_STATUS_STA) &&
			(hw_priv->channel->hw_value == advance_scan_req_channel)) {
				/* Start Advance Scan Timer */
				hw_priv->scan.status = bes2600_advance_scan_start(hw_priv);
				wsm_unlock_tx(hw_priv);
		} else
#endif
			hw_priv->scan.status = bes2600_scan_start(priv, &scan);
		kfree(scan.ch);
		if (WARN_ON(hw_priv->scan.status))
			goto fail;
		hw_priv->scan.curr = it;
	}
	up(&hw_priv->conf_lock);
	return;

fail:
	hw_priv->scan.curr = hw_priv->scan.end;
	up(&hw_priv->conf_lock);
	queue_work(hw_priv->workqueue, &hw_priv->scan.work);
	return;
}

#ifdef ROAM_OFFLOAD
void bes2600_sched_scan_work(struct work_struct *work)
{
	struct bes2600_common *hw_priv = container_of(work, struct bes2600_common,
		scan.swork);
	struct wsm_scan scan;
	struct wsm_ssid scan_ssid;
	int i;
	struct bes2600_vif *priv = cw12xx_hwpriv_to_vifpriv(hw_priv,
					hw_priv->scan.if_id);
	if (unlikely(!priv)) {
		WARN_ON(1);
		return;
	}

	spin_unlock(&priv->vif_lock);

	/* Firmware gets crazy if scan request is sent
	 * when STA is joined but not yet associated.
	 * Force unjoin in this case. */
	if (cancel_delayed_work_sync(&priv->join_timeout) > 0) {
		bes2600_join_timeout(&priv->join_timeout.work);
	}
	down(&hw_priv->conf_lock);
	hw_priv->auto_scanning = 1;

	scan.band = 0;

	if (priv->join_status == BES2600_JOIN_STATUS_STA)
		scan.scanType = 3; /* auto background */
	else
		scan.scanType = 2; /* auto foreground */

	scan.scanFlags = 0x01; /* bit 0 set => forced background scan */
	scan.maxTransmitRate = WSM_TRANSMIT_RATE_6;
	scan.autoScanInterval = (0xba << 24)|(30 * 1024); /* 30 seconds, -70 rssi */
	scan.numOfProbeRequests = 2;
	//scan.numOfChannels = 11;
	scan.numOfChannels = hw_priv->num_scanchannels;
	scan.numOfSSIDs = 1;
	scan.probeDelay = 100;
	scan_ssid.length = priv->ssid_length;
	memcpy(scan_ssid.ssid, priv->ssid, priv->ssid_length);
	scan.ssids = &scan_ssid;

	scan.ch = kzalloc(
		sizeof(struct wsm_scan_ch[scan.numOfChannels]),
		GFP_KERNEL);
	if (!scan.ch) {
		hw_priv->scan.status = -ENOMEM;
		goto fail;
	}

	for (i = 0; i < scan.numOfChannels; i++) {
		scan.ch[i].number = hw_priv->scan_channels[i].number;
		scan.ch[i].minChannelTime = hw_priv->scan_channels[i].minChannelTime;
		scan.ch[i].maxChannelTime = hw_priv->scan_channels[i].maxChannelTime;
		scan.ch[i].txPowerLevel = hw_priv->scan_channels[i].txPowerLevel;
	}

#if 0
	for (i = 1; i <= scan.numOfChannels; i++) {
		scan.ch[i-1].number = i;
		scan.ch[i-1].minChannelTime = 10;
		scan.ch[i-1].maxChannelTime = 40;
	}
#endif

	hw_priv->scan.status = bes2600_sched_scan_start(priv, &scan);
	kfree(scan.ch);
	if (hw_priv->scan.status)
		goto fail;
	up(&hw_priv->conf_lock);
	return;

fail:
	up(&hw_priv->conf_lock);
	queue_work(hw_priv->workqueue, &hw_priv->scan.swork);
	return;
}

void bes2600_hw_sched_scan_stop(struct bes2600_common *hw_priv)
{
	struct bes2600_vif *priv = cw12xx_hwpriv_to_vifpriv(hw_priv,
					hw_priv->scan.if_id);
	if (unlikely(!priv))
		return;
	spin_unlock(&priv->vif_lock);

	wsm_stop_scan(hw_priv, priv->if_id);

	return;
}
#endif /*ROAM_OFFLOAD*/


static void bes2600_scan_restart_delayed(struct bes2600_vif *priv)
{
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);

	if (priv->delayed_link_loss) {
		int tmo = priv->cqm_beacon_loss_count;

		if (hw_priv->scan.direct_probe)
			tmo = 0;

		priv->delayed_link_loss = 0;
		/* Restart beacon loss timer and requeue
		   BSS loss work. */
		wiphy_dbg(priv->hw->wiphy,
				"[CQM] Requeue BSS loss in %d "
				"beacons.\n", tmo);
		spin_lock(&priv->bss_loss_lock);
		priv->bss_loss_status = BES2600_BSS_LOSS_NONE;
		spin_unlock(&priv->bss_loss_lock);
		cancel_delayed_work_sync(&priv->bss_loss_work);
		queue_delayed_work(hw_priv->workqueue,
				&priv->bss_loss_work,
				tmo * HZ / 10);
	}

	/* FW bug: driver has to restart p2p-dev mode after scan. */
	if (priv->join_status == BES2600_JOIN_STATUS_MONITOR) {
		/*bes2600_enable_listening(priv);*/
		// WARN_ON(1);
		bes2600_dbg(BES2600_DBG_SCAN, "scan complete join_status is monitor");
		bes2600_update_filtering(priv);
	}

	if (priv->delayed_unjoin) {
		priv->delayed_unjoin = false;
		if (queue_work(hw_priv->workqueue, &priv->unjoin_work) <= 0)
			wsm_unlock_tx(hw_priv);
	}
}

static void bes2600_scan_complete(struct bes2600_common *hw_priv, int if_id)
{
	struct bes2600_vif *priv;
	atomic_xchg(&hw_priv->recent_scan, 0);

	if (hw_priv->scan.direct_probe) {
		down(&hw_priv->conf_lock);
		priv = __cw12xx_hwpriv_to_vifpriv(hw_priv, if_id);
		if (priv) {
			wiphy_dbg(priv->hw->wiphy, "[SCAN] Direct probe "
				  "complete.\n");
			bes2600_scan_restart_delayed(priv);
		} else {
			wiphy_dbg(priv->hw->wiphy, "[SCAN] Direct probe "
				  "complete without interface!\n");
		}
		up(&hw_priv->conf_lock);
		hw_priv->scan.direct_probe = 0;
		up(&hw_priv->scan.lock);
		wsm_unlock_tx(hw_priv);
	} else {
		bes2600_scan_work(&hw_priv->scan.work);
	}
}

void bes2600_scan_complete_cb(struct bes2600_common *hw_priv,
				struct wsm_scan_complete *arg)
{
	struct bes2600_vif *priv = cw12xx_hwpriv_to_vifpriv(hw_priv,
					hw_priv->scan.if_id);

	if (unlikely(!priv))
		return;

#ifdef ROAM_OFFLOAD
	if (hw_priv->auto_scanning)
		queue_delayed_work(hw_priv->workqueue,
				&hw_priv->scan.timeout, 0);
#endif /*ROAM_OFFLOAD*/

	if (unlikely(priv->mode == NL80211_IFTYPE_UNSPECIFIED)) {
		/* STA is stopped. */
		spin_unlock(&priv->vif_lock);
		return;
	}
	spin_unlock(&priv->vif_lock);

#ifdef WIFI_BT_COEXIST_EPTA_ENABLE
	// recover EPTA timer after scan wsm msg complete, in case of epta state error
	// bwifi_change_current_status(hw_priv, BWIFI_STATUS_SCANNING_COMP);
#endif
	wiphy_info(hw_priv->hw->wiphy, "bes2600_scan_complete_cb status: %u", arg->status);

	if(hw_priv->scan.status == -ETIMEDOUT)
		wiphy_warn(hw_priv->hw->wiphy,
			"Scan timeout already occured. Don't cancel work");
	if ((hw_priv->scan.status != -ETIMEDOUT) &&
		(cancel_delayed_work_sync(&hw_priv->scan.timeout) > 0)) {
		hw_priv->scan.status = 1;
		queue_delayed_work(hw_priv->workqueue,
				&hw_priv->scan.timeout, 0);
	}
}

void bes2600_scan_timeout(struct work_struct *work)
{
	struct bes2600_common *hw_priv =
		container_of(work, struct bes2600_common, scan.timeout.work);

	if (likely(atomic_xchg(&hw_priv->scan.in_progress, 0))) {
		if (hw_priv->scan.status > 0)
			hw_priv->scan.status = 0;
		else if (!hw_priv->scan.status) {
			wiphy_warn(hw_priv->hw->wiphy,
				"Timeout waiting for scan "
				"complete notification.\n");
			hw_priv->scan.status = -ETIMEDOUT;
			hw_priv->scan.curr = hw_priv->scan.end;
			WARN_ON(wsm_stop_scan(hw_priv,
						hw_priv->scan.if_id ? 1 : 0));
		}
		bes2600_scan_complete(hw_priv, hw_priv->scan.if_id);
#ifdef ROAM_OFFLOAD
	} else if (hw_priv->auto_scanning) {
		hw_priv->auto_scanning = 0;
		ieee80211_sched_scan_results(hw_priv->hw);
#endif /*ROAM_OFFLOAD*/
	}
}

#ifdef CONFIG_BES2600_TESTMODE
void bes2600_advance_scan_timeout(struct work_struct *work)
{
	struct bes2600_common *hw_priv =
		container_of(work, struct bes2600_common, advance_scan_timeout.work);

	struct bes2600_vif *priv = cw12xx_hwpriv_to_vifpriv(hw_priv,
					hw_priv->scan.if_id);
	if (WARN_ON(!priv))
		return;
	spin_unlock(&priv->vif_lock);

	hw_priv->scan.status = 0;
	if (hw_priv->advanceScanElems.scanMode ==
		BES2600_SCAN_MEASUREMENT_PASSIVE) {
		/* Passive Scan on Serving Channel
		 * Timer Expire */
		bes2600_scan_complete(hw_priv, hw_priv->scan.if_id);
	} else {
		struct cfg80211_scan_info info = {
			.aborted = hw_priv->scan.status ? 1 : 0,
		};
		/* Active Scan on Serving Channel
		 * Timer Expire */
		down(&hw_priv->conf_lock);
		//wsm_lock_tx(priv);
		wsm_vif_lock_tx(priv);
		/* Once Duration is Over, enable filtering
		 * and Revert Back Power Save */
		if ((priv->powersave_mode.pmMode & WSM_PSM_PS))
			wsm_set_pm(hw_priv, &priv->powersave_mode,
				priv->if_id);
		hw_priv->scan.req = NULL;
		bes2600_update_filtering(priv);
		hw_priv->enable_advance_scan = false;
		wsm_unlock_tx(hw_priv);
		up(&hw_priv->conf_lock);
		ieee80211_scan_completed(hw_priv->hw, &info);
		up(&hw_priv->scan.lock);
	}
}
#endif

void bes2600_cancel_hw_scan(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	struct bes2600_vif *priv = cw12xx_get_vif_from_ieee80211(vif);
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);

	if(hw_priv->scan.if_id == priv->if_id) {
		bes2600_dbg(BES2600_DBG_SCAN, "cancel hw_scan on intf:%d\n", priv->if_id);

		down(&hw_priv->conf_lock);
		hw_priv->scan.req = NULL;
		up(&hw_priv->conf_lock);

		/* cancel scan operation */
		wsm_stop_scan(hw_priv, priv->if_id);

		/* wait scan operation end */
		down(&hw_priv->scan.lock);
		up(&hw_priv->scan.lock);
	}
}

void bes2600_probe_work(struct work_struct *work)
{
	struct bes2600_common *hw_priv =
		container_of(work, struct bes2600_common, scan.probe_work.work);
	struct bes2600_vif *priv, *vif;
	u8 queueId = bes2600_queue_get_queue_id(hw_priv->pending_frame_id);
	struct bes2600_queue *queue = &hw_priv->tx_queue[queueId];
	const struct bes2600_txpriv *txpriv;
	struct wsm_tx *wsm;
	struct wsm_template_frame frame = {
		.frame_type = WSM_FRAME_TYPE_PROBE_REQUEST,
	};
	struct wsm_ssid ssids[1] = {{
		.length = 0,
	} };
	struct wsm_scan_ch ch[1] = {{
		.minChannelTime = 0,
		.maxChannelTime = 10,
	} };
	struct wsm_scan scan = {
		.scanType = WSM_SCAN_TYPE_FOREGROUND,
		.numOfProbeRequests = 2,
		.probeDelay = 0,
		.numOfChannels = 1,
		.ssids = ssids,
		.ch = ch,
	};
	u8 *ies;
	size_t ies_len;
	int ret = 1;
	int i;
	wiphy_info(hw_priv->hw->wiphy, "[SCAN] Direct probe work.\n");

	BUG_ON(queueId >= 4);
	BUG_ON(!hw_priv->channel);

	down(&hw_priv->conf_lock);
	if (unlikely(down_trylock(&hw_priv->scan.lock))) {
		/* Scan is already in progress. Requeue self. */
		schedule();
		queue_delayed_work(hw_priv->workqueue,
					&hw_priv->scan.probe_work, HZ / 10);
		up(&hw_priv->conf_lock);
		return;
	}

	if (bes2600_queue_get_skb(queue,	hw_priv->pending_frame_id,
			&frame.skb, &txpriv)) {
		up(&hw_priv->scan.lock);
		up(&hw_priv->conf_lock);
		wsm_unlock_tx(hw_priv);
		return;
	}
	priv = __cw12xx_hwpriv_to_vifpriv(hw_priv, txpriv->if_id);
	if (!priv) {
		up(&hw_priv->scan.lock);
		up(&hw_priv->conf_lock);
		return;
	}
	wsm = (struct wsm_tx *)frame.skb->data;
	scan.maxTransmitRate = wsm->maxTxRate;
	scan.band = (hw_priv->channel->band == NL80211_BAND_5GHZ) ?
		WSM_PHY_BAND_5G : WSM_PHY_BAND_2_4G;
	if (priv->join_status == BES2600_JOIN_STATUS_STA) {
		scan.scanType = WSM_SCAN_TYPE_BACKGROUND;
		scan.scanFlags = WSM_SCAN_FLAG_FORCE_BACKGROUND;
		if (priv->if_id)
			scan.scanFlags |= WSM_FLAG_MAC_INSTANCE_1;
		else
			scan.scanFlags &= ~WSM_FLAG_MAC_INSTANCE_1;
	}
	bes2600_for_each_vif(hw_priv, vif, i) {
		if (!vif)
			continue;
		if (vif->bss_loss_status > BES2600_BSS_LOSS_NONE)
			scan.scanFlags |= WSM_SCAN_FLAG_FORCE_BACKGROUND;
	}
	ch[0].number = hw_priv->channel->hw_value;

	skb_pull(frame.skb, txpriv->offset);

	ies = &frame.skb->data[sizeof(struct ieee80211_hdr_3addr)];
	ies_len = frame.skb->len - sizeof(struct ieee80211_hdr_3addr);

	if (ies_len) {
		u8 *ssidie =
			(u8 *)cfg80211_find_ie(WLAN_EID_SSID, ies, ies_len);
		if (ssidie && ssidie[1] && ssidie[1] <= sizeof(ssids[0].ssid)) {
			u8 *nextie = &ssidie[2 + ssidie[1]];
			/* Remove SSID from the IE list. It has to be provided
			 * as a separate argument in bes2600_scan_start call */

			/* Store SSID localy */
			ssids[0].length = ssidie[1];
			memcpy(ssids[0].ssid, &ssidie[2], ssids[0].length);
			scan.numOfSSIDs = 1;

			/* Remove SSID from IE list */
			ssidie[1] = 0;
			memmove(&ssidie[2], nextie, &ies[ies_len] - nextie);
			skb_trim(frame.skb, frame.skb->len - ssids[0].length);
		}
	}

	if (priv->if_id == 0)
		bes2600_remove_wps_p2p_ie(&frame);

	/* FW bug: driver has to restart p2p-dev mode after scan */
	if (priv->join_status == BES2600_JOIN_STATUS_MONITOR) {
		WARN_ON(1);
		/*bes2600_disable_listening(priv);*/
	}
	ret = WARN_ON(wsm_set_template_frame(hw_priv, &frame,
				priv->if_id));

	hw_priv->scan.direct_probe = 1;
	hw_priv->scan.if_id = priv->if_id;
	if (!ret) {
		wsm_flush_tx(hw_priv);
		ret = WARN_ON(bes2600_scan_start(priv, &scan));
	}
	up(&hw_priv->conf_lock);

	skb_push(frame.skb, txpriv->offset);
	if (!ret)
		IEEE80211_SKB_CB(frame.skb)->flags |= IEEE80211_TX_STAT_ACK;
#ifdef CONFIG_BES2600_TESTMODE
		BUG_ON(bes2600_queue_remove(hw_priv, queue,
				hw_priv->pending_frame_id));
#else
		BUG_ON(bes2600_queue_remove(queue, hw_priv->pending_frame_id));
#endif

	if (ret) {
		hw_priv->scan.direct_probe = 0;
		up(&hw_priv->scan.lock);
		wsm_unlock_tx(hw_priv);
	}

	return;
}

