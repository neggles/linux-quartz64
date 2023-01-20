/*
 * Mac80211 power management API for BES2600 drivers
 *
 * Copyright (c) 2011, Bestechnic
 * Author:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/platform_device.h>
#include <linux/if_ether.h>
#include "bes2600.h"
#include "pm.h"
#include "sta.h"
#include "bh.h"
#include "sbus.h"
#include "bes2600_driver_mode.h"
#include "bes_chardev.h"

#define BES2600_BEACON_SKIPPING_MULTIPLIER 3

struct bes2600_udp_port_filter {
	struct wsm_udp_port_filter_hdr hdr;
	struct wsm_udp_port_filter dhcp;
	struct wsm_udp_port_filter upnp;
} __packed;

struct bes2600_ether_type_filter {
	struct wsm_ether_type_filter_hdr hdr;
	struct wsm_ether_type_filter ip;
	struct wsm_ether_type_filter pae;
	struct wsm_ether_type_filter wapi;
} __packed;

static struct bes2600_udp_port_filter bes2600_udp_port_filter_on = {
	.hdr.nrFilters = 2,
	.dhcp = {
		.filterAction = WSM_FILTER_ACTION_FILTER_OUT,
		.portType = WSM_FILTER_PORT_TYPE_DST,
		.udpPort = __cpu_to_le16(67),
	},
	.upnp = {
		.filterAction = WSM_FILTER_ACTION_FILTER_OUT,
		.portType = WSM_FILTER_PORT_TYPE_DST,
		.udpPort = __cpu_to_le16(1900),
	},
	/* Please add other known ports to be filtered out here and
	 * update nrFilters field in the header.
	 * Up to 4 filters are allowed. */
};

static struct wsm_udp_port_filter_hdr bes2600_udp_port_filter_off = {
	.nrFilters = 0,
};

#ifndef ETH_P_WAPI
#define ETH_P_WAPI     0x88B4
#endif

static struct bes2600_ether_type_filter bes2600_ether_type_filter_on = {
	.hdr.nrFilters = 3,
	.ip = {
		.filterAction = WSM_FILTER_ACTION_FILTER_IN,
		.etherType = __cpu_to_le16(ETH_P_IP),
	},
	.pae = {
		.filterAction = WSM_FILTER_ACTION_FILTER_IN,
		.etherType = __cpu_to_le16(ETH_P_PAE),
	},
	.wapi = {
		.filterAction = WSM_FILTER_ACTION_FILTER_IN,
		.etherType = __cpu_to_le16(ETH_P_WAPI),
	},
	/* Please add other known ether types to be filtered out here and
	 * update nrFilters field in the header.
	 * Up to 4 filters are allowed. */
};

static struct wsm_ether_type_filter_hdr bes2600_ether_type_filter_off = {
	.nrFilters = 0,
};

static int __bes2600_wow_suspend(struct bes2600_vif *priv,
				struct cfg80211_wowlan *wowlan);
static int __bes2600_wow_resume(struct bes2600_vif *priv);


/* private */
struct bes2600_suspend_state {
	unsigned long bss_loss_tmo;
	unsigned long connection_loss_tmo;
	unsigned long join_tmo;
	unsigned long direct_probe;
	unsigned long link_id_gc;
};

static long bes2600_suspend_work(struct delayed_work *work)
{
	int ret = cancel_delayed_work(work);
	long tmo;
	if (ret > 0) {
		/* Timer is pending */
		tmo = work->timer.expires - jiffies;
		if (tmo < 0)
			tmo = 0;
	} else {
		tmo = -1;
	}
	return tmo;
}

static int bes2600_resume_work(struct bes2600_common *hw_priv,
			       struct delayed_work *work,
			       unsigned long tmo)
{
	if ((long)tmo < 0)
		return 1;

	return queue_delayed_work(hw_priv->workqueue, work, tmo);
}

int bes2600_can_suspend(struct bes2600_common *priv)
{
	if (atomic_read(&priv->bh_rx)) {
		wiphy_dbg(priv->hw->wiphy, "Suspend interrupted.\n");
		return 0;
	}
	return 1;
}
EXPORT_SYMBOL_GPL(bes2600_can_suspend);

int bes2600_wow_suspend(struct ieee80211_hw *hw, struct cfg80211_wowlan *wowlan)
{
	struct bes2600_common *hw_priv = hw->priv;
	struct bes2600_vif *priv;
	int i, ret = 0;

	bes2600_info(BES2600_DBG_PM, "bes2600_wow_suspend enter\n");

	WARN_ON(!atomic_read(&hw_priv->num_vifs));

#ifdef ROAM_OFFLOAD
	bes2600_for_each_vif(hw_priv, priv, i) {
#ifdef P2P_MULTIVIF
		if ((i == (CW12XX_MAX_VIFS - 1)) || !priv)
#else
		if (!priv)
#endif
			continue;
		if((priv->vif->type == NL80211_IFTYPE_STATION)
		&& (priv->join_status == BES2600_JOIN_STATUS_STA)) {
			down(&hw_priv->scan.lock);
			hw_priv->scan.if_id = priv->if_id;
			bes2600_sched_scan_work(&hw_priv->scan.swork);
		}
	}
#endif /*ROAM_OFFLOAD*/

	/* Do not suspend when device is doing work */
	if(!bes2600_pwr_device_is_idle(hw_priv))
		return -EBUSY;

	/* Do not suspend when datapath is not idle */
	if (hw_priv->tx_queue_stats.num_queued[0]
			+ hw_priv->tx_queue_stats.num_queued[1])
		return -EBUSY;
		

	/* Make sure there is no configuration requests in progress. */
	if (down_trylock(&hw_priv->conf_lock))
		return -EBUSY;


	/* Do not suspend when scanning or ROC*/
	if (down_trylock(&hw_priv->scan.lock))
		goto revert1;

	if (delayed_work_pending(&hw_priv->scan.probe_work))
		goto revert2;

	/* Lock TX. */
	wsm_lock_tx_async(hw_priv);

	/* Wait to avoid possible race with bh code.
	 * But do not wait too long... */
	if (wait_event_timeout(hw_priv->bh_evt_wq,
			!hw_priv->hw_bufs_used, HZ / 10) <= 0)
		goto revert3;

	/* mark suspend start to avoid device to exit ps mode when setting device */
	bes2600_pwr_suspend_start(hw_priv);

	/* set filters and offload based on interface */
	bes2600_for_each_vif(hw_priv, priv, i) {
#ifdef P2P_MULTIVIF
		if ((i == (CW12XX_MAX_VIFS - 1)) || !priv)
#else
		if (!priv)
#endif
			continue;

		ret = __bes2600_wow_suspend(priv,
						wowlan);
		if (ret) {
			for (; i >= 0; i--) {
				if (!hw_priv->vif_list[i])
					continue;
				priv = (struct bes2600_vif *)
					hw_priv->vif_list[i]->drv_priv;
				__bes2600_wow_resume(priv);
			}
			goto revert3;
		}
	}

	/* mark suspend end */
	bes2600_pwr_suspend_end(hw_priv);

	/* Stop serving thread */
	if (bes2600_bh_suspend(hw_priv)) {
		bes2600_err(BES2600_DBG_PM, "%s: bes2600_bh_suspend failed\n",
				__func__);
		bes2600_wow_resume(hw);
		return -EBUSY;
	}

	/* Force resume if event is coming from the device. */
	if (atomic_read(&hw_priv->bh_rx)) {
		bes2600_info(BES2600_DBG_PM, "%s: incoming event present - resume\n",
				__func__);
		bes2600_wow_resume(hw);
		return -EAGAIN;
	}

	return 0;
revert3:
	bes2600_pwr_suspend_end(hw_priv);
	wsm_unlock_tx(hw_priv);
revert2:
	up(&hw_priv->scan.lock);
revert1:
	up(&hw_priv->conf_lock);
	return -EBUSY;
}

static int __bes2600_wow_suspend(struct bes2600_vif *priv,
				struct cfg80211_wowlan *wowlan)
{
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
	struct bes2600_pm_state_vif *pm_state_vif = &priv->pm_state_vif;
	struct bes2600_suspend_state *state;
	int ret;

#ifdef MCAST_FWDING
        struct wsm_forwarding_offload fwdoffload = {
                .fwenable = 0x1,
                .flags = 0x1,
        };
#endif

	/* Do not suspend when join work is scheduled */
	if (work_pending(&priv->join_work))
		goto revert1;

	/* Set UDP filter */
	wsm_set_udp_port_filter(hw_priv, &bes2600_udp_port_filter_on.hdr,
				priv->if_id);

	/* Set ethernet frame type filter */
	wsm_set_ether_type_filter(hw_priv, &bes2600_ether_type_filter_on.hdr,
				  priv->if_id);

        if (priv->join_status == BES2600_JOIN_STATUS_AP)
                WARN_ON(wsm_set_keepalive_filter(priv, true));

#ifdef BES2600_SUSPEND_RESUME_FILTER_ENABLE
       /* Set Multicast Address Filter */
       if (priv->multicast_filter.numOfAddresses) {
               priv->multicast_filter.enable = 1;
               wsm_set_multicast_filter(hw_priv, &priv->multicast_filter, priv->if_id);
       }

       /* Set Enable Broadcast Address Filter */

       priv->broadcast_filter.action_mode = WSM_FILTER_ACTION_FILTER_OUT;
       if (priv->join_status == BES2600_JOIN_STATUS_AP)
                priv->broadcast_filter.address_mode = WSM_FILTER_ADDR_MODE_A3;

       bes2600_set_macaddrfilter(hw_priv, priv, (u8 *)&priv->broadcast_filter);

#endif

#ifdef MCAST_FWDING
        if (priv->join_status == BES2600_JOIN_STATUS_AP)
                WARN_ON(wsm_set_forwarding_offlad(hw_priv,
				&fwdoffload,priv->if_id));
#endif

	/* Allocate state */
	state = kzalloc(sizeof(struct bes2600_suspend_state), GFP_KERNEL);
	if (!state)
		goto revert2;

	/* Store delayed work states. */
	state->bss_loss_tmo =
		bes2600_suspend_work(&priv->bss_loss_work);
	state->connection_loss_tmo =
		bes2600_suspend_work(&priv->connection_loss_work);
	state->join_tmo =
		bes2600_suspend_work(&priv->join_timeout);
	state->link_id_gc =
		bes2600_suspend_work(&priv->link_id_gc_work);

	ret = timer_pending(&priv->mcast_timeout);
	if (ret)
		goto revert3;

	/* Store suspend state */
	pm_state_vif->suspend_state = state;

	return 0;

revert3:
	bes2600_resume_work(hw_priv, &priv->bss_loss_work,
			state->bss_loss_tmo);
	bes2600_resume_work(hw_priv, &priv->connection_loss_work,
			state->connection_loss_tmo);
	bes2600_resume_work(hw_priv, &priv->join_timeout,
			state->join_tmo);
	bes2600_resume_work(hw_priv, &priv->link_id_gc_work,
			state->link_id_gc);
	kfree(state);
revert2:
	wsm_set_udp_port_filter(hw_priv, &bes2600_udp_port_filter_off,
				priv->if_id);
	wsm_set_ether_type_filter(hw_priv, &bes2600_ether_type_filter_off,
				  priv->if_id);

        if (priv->join_status == BES2600_JOIN_STATUS_AP)
                WARN_ON(wsm_set_keepalive_filter(priv, false));

#ifdef BES2600_SUSPEND_RESUME_FILTER_ENABLE
       /* Set Multicast Address Filter */
       if (priv->multicast_filter.numOfAddresses) {
               priv->multicast_filter.enable = 0;
               wsm_set_multicast_filter(hw_priv, &priv->multicast_filter, priv->if_id);
       }

       /* Set Enable Broadcast Address Filter */

       priv->broadcast_filter.action_mode = WSM_FILTER_ACTION_IGNORE;
        if (priv->join_status == BES2600_JOIN_STATUS_AP)
                priv->broadcast_filter.address_mode = WSM_FILTER_ADDR_MODE_NONE;
       bes2600_set_macaddrfilter(hw_priv, priv, (u8 *)&priv->broadcast_filter);

#endif

#ifdef MCAST_FWDING
	fwdoffload.flags = 0x0;
        if (priv->join_status == BES2600_JOIN_STATUS_AP)
                WARN_ON(wsm_set_forwarding_offlad(hw_priv, &fwdoffload,priv->if_id));
#endif
revert1:
	up(&hw_priv->conf_lock);
	return -EBUSY;
}

int bes2600_wow_resume(struct ieee80211_hw *hw)
{
	struct bes2600_common *hw_priv = hw->priv;
	struct bes2600_vif *priv;
	int i, ret = 0;

	bes2600_info(BES2600_DBG_PM, "bes2600_wow_resume enter\n");
	WARN_ON(!atomic_read(&hw_priv->num_vifs));

	up(&hw_priv->scan.lock);

	/* Resume BH thread */
	WARN_ON(bes2600_bh_resume(hw_priv));

	/* mark resume start to avoid device to exit ps mode when setting device */
	bes2600_pwr_resume_start(hw_priv);

	/* set filters and offload based on interface */
	bes2600_for_each_vif(hw_priv, priv, i) {
#ifdef P2P_MULTIVIF
		if ((i == (CW12XX_MAX_VIFS - 1)) || !priv)
#else
		if (!priv)
#endif
			continue;
		ret = __bes2600_wow_resume(priv);
		if (ret)
			break;
	}

	/* mark resume end */
	bes2600_pwr_resume_end(hw_priv);

	wsm_unlock_tx(hw_priv);
	/* Unlock configuration mutex */
	up(&hw_priv->conf_lock);

	return ret;
}

static int __bes2600_wow_resume(struct bes2600_vif *priv)
{
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
	struct bes2600_pm_state_vif *pm_state_vif = &priv->pm_state_vif;
	struct bes2600_suspend_state *state;

#ifdef MCAST_FWDING
        struct wsm_forwarding_offload fwdoffload = {
                .fwenable = 0x1,
                .flags = 0x0,
        };
#endif
	state = pm_state_vif->suspend_state;
	pm_state_vif->suspend_state = NULL;

#ifdef ROAM_OFFLOAD
	if((priv->vif->type == NL80211_IFTYPE_STATION)
	&& (priv->join_status == BES2600_JOIN_STATUS_STA))
		bes2600_hw_sched_scan_stop(hw_priv);
#endif /*ROAM_OFFLOAD*/

        if (priv->join_status == BES2600_JOIN_STATUS_AP)
                WARN_ON(wsm_set_keepalive_filter(priv, false));

#ifdef BES2600_SUSPEND_RESUME_FILTER_ENABLE
       /* Set Multicast Address Filter */
       if (priv->multicast_filter.numOfAddresses) {
               priv->multicast_filter.enable = 0;
               wsm_set_multicast_filter(hw_priv, &priv->multicast_filter, priv->if_id);
       }

       /* Set Enable Broadcast Address Filter */

       priv->broadcast_filter.action_mode = WSM_FILTER_ACTION_IGNORE;
        if (priv->join_status == BES2600_JOIN_STATUS_AP)
                priv->broadcast_filter.address_mode = WSM_FILTER_ADDR_MODE_NONE;

       bes2600_set_macaddrfilter(hw_priv, priv, (u8 *)&priv->broadcast_filter);

#endif

#ifdef MCAST_FWDING
        if (priv->join_status == BES2600_JOIN_STATUS_AP)
                WARN_ON(wsm_set_forwarding_offlad(hw_priv, &fwdoffload,priv->if_id));
#endif

	/* Resume delayed work */
	bes2600_resume_work(hw_priv, &priv->bss_loss_work,
			state->bss_loss_tmo);
	bes2600_resume_work(hw_priv, &priv->connection_loss_work,
			state->connection_loss_tmo);
	bes2600_resume_work(hw_priv, &priv->join_timeout,
			state->join_tmo);
	bes2600_resume_work(hw_priv, &priv->link_id_gc_work,
			state->link_id_gc);

	/* Remove UDP port filter */
	wsm_set_udp_port_filter(hw_priv, &bes2600_udp_port_filter_off,
				priv->if_id);

	/* Remove ethernet frame type filter */
	wsm_set_ether_type_filter(hw_priv, &bes2600_ether_type_filter_off,
				  priv->if_id);
	/* Free memory */
	kfree(state);

	return 0;
}
