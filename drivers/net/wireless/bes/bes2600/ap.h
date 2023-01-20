/*
 * mac80211 STA and AP API for mac80211 BES2600 drivers
 *
 * Copyright (c) 2010, Bestechnic
 * Author:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/version.h>
#ifndef AP_H_INCLUDED
#define AP_H_INCLUDED

#define BES2600_NOA_NOTIFICATION_DELAY 10

int bes2600_set_tim(struct ieee80211_hw *dev, struct ieee80211_sta *sta,
		   bool set);
int bes2600_sta_add(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		   struct ieee80211_sta *sta);
int bes2600_sta_remove(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		      struct ieee80211_sta *sta);
void bes2600_sta_notify(struct ieee80211_hw *dev, struct ieee80211_vif *vif,
		       enum sta_notify_cmd notify_cmd,
		       struct ieee80211_sta *sta);
void bes2600_bss_info_changed(struct ieee80211_hw *dev,
			     struct ieee80211_vif *vif,
			     struct ieee80211_bss_conf *info,
			     u64 changed);

int bes2600_ampdu_action(struct ieee80211_hw *hw,
			struct ieee80211_vif *vif,
			struct ieee80211_ampdu_params *params);

void bes2600_suspend_resume(struct bes2600_vif *priv,
			  struct wsm_suspend_resume *arg);
void bes2600_set_tim_work(struct work_struct *work);
void bes2600_set_cts_work(struct work_struct *work);
void bes2600_multicast_start_work(struct work_struct *work);
void bes2600_multicast_stop_work(struct work_struct *work);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))
void bes2600_mcast_timeout(struct timer_list *t);
#else
void bes2600_mcast_timeout(unsigned long arg);
#endif
int bes2600_find_link_id(struct bes2600_vif *priv, const u8 *mac);
int bes2600_alloc_link_id(struct bes2600_vif *priv, const u8 *mac);
void bes2600_link_id_work(struct work_struct *work);
void bes2600_link_id_gc_work(struct work_struct *work);
#if defined(CONFIG_BES2600_USE_STE_EXTENSIONS)
void bes2600_notify_noa(struct bes2600_vif *priv, int delay);
#endif
int cw12xx_unmap_link(struct bes2600_vif *priv, int link_id);
#ifdef AP_HT_CAP_UPDATE
void bes2600_ht_info_update_work(struct work_struct *work);
#endif

#endif
