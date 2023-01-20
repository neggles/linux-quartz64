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
#include <linux/list.h>
#include <linux/pm.h>
#include "bes2600.h"
#include "sbus.h"
#include "bes_pwr.h"
#include "sta.h"
#include "bes_chardev.h"

static void bes2600_add_power_delay_event(struct bes2600_pwr_t *bes_pwr, u32 event, u32 timeout);

#if (BES2600_DBG_PWR_LVL >= BES2600_LOG_DBG)
static void bes2600_dump_power_busy_event(struct bes2600_pwr_t *bes_pwr, char* location)
{
        struct bes2600_pwr_event_t *item = NULL;
        char *async_dump_str = NULL;
        char *pending_dump_str = NULL;
        char *free_dump_str = NULL;
        int used_len = 0;
        bool dump_async_ok = true;
        bool dump_pending_ok = true;
        bool dump_free_ok = true;
        bool async_have = false;
        bool pending_have = false;
        bool free_have = false;
        const int single_buffer_len = 4096;
        const int all_bufer_len = single_buffer_len * 3;

        bes2600_dbg(BES2600_DBG_PWR, "power busy event dump at %s\n", location);

        async_dump_str = kzalloc(all_bufer_len, GFP_KERNEL);
        if(async_dump_str == NULL) {
                bes2600_err(BES2600_DBG_PWR, "%s alloc buffer failed\n", __func__);
                return;
        }

        used_len = snprintf(async_dump_str, single_buffer_len, "async list[");
        if(!list_empty(&bes_pwr->async_timeout_list)) {
                list_for_each_entry(item, &bes_pwr->async_timeout_list, link) {
                        if(used_len + 10 < single_buffer_len) {
                                async_have = true;
                                used_len += snprintf(async_dump_str + used_len, 10, "%d(%d) ",
                                        BES_PWR_EVENT_NUMBER(item->event), (item->event >> 31));
                        } else {
                                dump_async_ok = false;
                                goto out;
                        }
                }
        }
        if(used_len + 3 < single_buffer_len) {
                used_len = async_have ? used_len  - 1 : used_len;
                used_len += sprintf(async_dump_str + used_len, "]\n");
        } else {
                dump_async_ok = false;
                goto out;
        }

        pending_dump_str = async_dump_str + single_buffer_len;
        used_len = snprintf(pending_dump_str, single_buffer_len, "pending list[");
        if(!list_empty(&bes_pwr->pending_event_list)) {
                list_for_each_entry(item, &bes_pwr->pending_event_list, link) {
                        if(used_len + 10 < single_buffer_len) {
                                pending_have = true;
                                used_len += snprintf(pending_dump_str + used_len, 10, "%d(%d) ",
                                        BES_PWR_EVENT_NUMBER(item->event), (item->event >> 31));
                        } else {
                                dump_pending_ok = false;
                                goto out;
                        }
                }
        }
        if(used_len + 3 < single_buffer_len) {
                used_len = pending_have ? used_len  - 1 : used_len;
                used_len += sprintf(pending_dump_str + used_len, "]\n");
        } else {
                dump_pending_ok = false;
                goto out;
        }

        free_dump_str = pending_dump_str + single_buffer_len;
        used_len = snprintf(free_dump_str, single_buffer_len, "free list[");
        if(!list_empty(&bes_pwr->free_event_list)) {
                list_for_each_entry(item, &bes_pwr->free_event_list, link) {
                        if(used_len + 10 < single_buffer_len) {
                                free_have = true;
                                used_len += snprintf(free_dump_str + used_len, 10, "%d(%d) ",
                                        BES_PWR_EVENT_NUMBER(item->event), (item->event >> 31));
                        } else {
                                dump_free_ok = false;
                                goto out;
                        }
                }
        }
        if(used_len + 3 < single_buffer_len) {
                used_len = free_have ? used_len  - 1 : used_len;
                used_len += sprintf(free_dump_str + used_len, "]\n");
        } else {
                dump_free_ok = false;
                goto out;
        }
out:
        if(!dump_async_ok) {
                bes2600_err(BES2600_DBG_PWR, "buffer is not enough for dumping async event\n");
        } else {
                bes2600_dbg(BES2600_DBG_PWR, "%s", async_dump_str);
        }

        if(!dump_pending_ok) {
                bes2600_err(BES2600_DBG_PWR, "buffer is not enough for dumping pending event\n");
        } else {
                bes2600_dbg(BES2600_DBG_PWR, "%s", pending_dump_str);
        }

        if(!dump_free_ok) {
                bes2600_err(BES2600_DBG_PWR, "buffer is not enough for dumping free event\n");
        } else {
                bes2600_dbg(BES2600_DBG_PWR, "%s", free_dump_str);
        }

        kfree(async_dump_str);
}
#else
static void bes2600_dump_power_busy_event(struct bes2600_pwr_t *bes_pwr, char* location) { }
#endif

static char *bes2600_get_ps_mode_str(u8 mode)
{
        char *ps_mode_str = NULL;

        ps_mode_str = (mode == WSM_PSM_ACTIVE ? "WSM_PSM_ACTIVE" :
                mode == WSM_PSM_PS ? "WSM_PSM_PS" :
                mode == WSM_PSM_FAST_PS ? "WSM_PSM_FAST_PS" :
                "UNKNOWN");

        return ps_mode_str;
}

static char *bes2600_get_mac_str(char *buffer, u32 ip)
{
        sprintf(buffer, "%d.%d.%d.%d",
                        (ip & 0xff),((ip >> 8) & 0xff),
                        ((ip >> 16) & 0xff), ((ip >> 24) & 0xff));

        return buffer;
}

static char *bes2600_get_pwr_busy_event_name(struct bes2600_pwr_event_t *item)
{
        char *name = NULL;

        switch(BES_PWR_EVENT_NUMBER(item->event)) {
                case BES_PWR_LOCK_ON_SCAN:      name = "SCAN";          break;
                case BES_PWR_LOCK_ON_JOIN:      name = "JOIN";          break;
                case BES_PWR_LOCK_ON_TX:        name = "TX";            break;
                case BES_PWR_LOCK_ON_RX:        name = "RX";            break;
                case BES_PWR_LOCK_ON_FLUSH:     name = "FLUSH";         break;
                case BES_PWR_LOCK_ON_ROC:       name = "ROC";           break;
                case BES_PWR_LOCK_ON_WSM_TX:    name = "WSM_TX";        break;
                case BES_PWR_LOCK_ON_WSM_OPER:  name = "WSM_OPER";      break;
                case BES_PWR_LOCK_ON_BSS_LOST:  name = "BSS_LOST";      break;
                case BES_PWR_LOCK_ON_GET_IP:    name = "GET_IP";        break;
                case BES_PWR_LOCK_ON_PS_ACTIVE: name = "PS_ACTIVE";     break;
                case BES_PWR_LOCK_ON_LMAC_RSP:  name = "LMAC_RSP";      break;
                case BES_PWR_LOCK_ON_AP:        name = "AP";            break;
                case BES_PWR_LOCK_ON_TEST_CMD:  name = "TEST_CMD";      break;
                case BES_PWR_LOCK_ON_MUL_REQ:   name = "MUL_REQ";       break;
                case BES_PWR_LOCK_ON_ADV_SCAN:  name = "ADV_SCAN";      break;
                case BES_PWR_LOCK_ON_DISCON:    name = "DISCON";        break;
                case BES_PWR_LOCK_ON_QUEUE_GC:  name = "QUEUE_GC";      break;
                case BES_PWR_LOCK_ON_AP_LP_BAD: name = "AP_LP_BAD";     break;
                default:                        name = "UNKNOW";        break;
        }

        return name;
}

static unsigned long bes2600_get_pwr_busy_event_timeout(struct bes2600_pwr_event_t *item)
{
        unsigned long timeout = 0;

        if(BES_PWR_IS_CONSTANT_EVENT(item->event))
                return 0;

        if(time_after(jiffies, item->timeout))
                return 0;

        timeout = (item->timeout >= jiffies) ?
                (item->timeout - jiffies) : (ULONG_MAX - jiffies + item->timeout);

        return timeout;
}

static bool bes2600_update_power_delay_events(struct bes2600_pwr_t *bes_pwr, unsigned long *timeout)
{
        struct bes2600_pwr_event_t *item = NULL, *temp = NULL;
        unsigned long max_timeout = 0;
        bool constant_event_exist = false;

        /* move event from async_timeout_list to pending_event_list */
        if(!list_empty(&bes_pwr->async_timeout_list)) {
                list_for_each_entry_safe(item, temp, &bes_pwr->async_timeout_list, link) {
                        bes2600_add_power_delay_event(bes_pwr, item->event, item->delay);
                        list_move_tail(&item->link, &bes_pwr->free_event_list);
                }
        }

        /* age power event and get max timeout */
        list_for_each_entry_safe(item, temp, &bes_pwr->pending_event_list, link) {
                if(BES_PWR_IS_CONSTANT_EVENT(item->event)) {
                       constant_event_exist = true;
                       continue;
                }
                if(time_after(jiffies, item->timeout)) {
                        bes2600_dbg(BES2600_DBG_PWR, "power busy event:0x%08x timeout\n", item->event);
                        list_move_tail(&item->link, &bes_pwr->free_event_list);
                } else {
                        if(max_timeout == 0) {
                                max_timeout = item->timeout;
                        } else {
                                max_timeout = time_after(item->timeout, max_timeout)
                                                ? item->timeout : max_timeout;
                        }
                }
        }

        bes2600_dump_power_busy_event(bes_pwr, "refresh");

        if(timeout) {
                *timeout = max_timeout;
        }

        return constant_event_exist;
}

static void bes2600_add_async_timeout_power_delay_event(struct bes2600_pwr_t *bes_pwr, u32 event, u32 timeout)
{
        struct bes2600_pwr_event_t *item = NULL;
        unsigned long max_timeout = 0;
        bool match = false;

        /* check if the event is already in pending list */
        if (!list_empty(&bes_pwr->async_timeout_list)) {
                list_for_each_entry(item, &bes_pwr->async_timeout_list, link) {
                        if(item->event == event) {
                                match = true;
                                break;
                        }
                }
        }

        /* update event information */
        if (match && (item != NULL)) {
                item->delay = timeout;
        } else {
                /* delete expired event if free_event_list is empty */
                if(list_empty(&bes_pwr->free_event_list)) {
                        bes2600_info(BES2600_DBG_PWR, "%s, update delay event\n", __func__);
                        bes2600_update_power_delay_events(bes_pwr, &max_timeout);
                }

                /* throw out exception if free_event_list is empty */
                BUG_ON(list_empty(&bes_pwr->free_event_list));

                /* add event instance to pending list */
                bes2600_dbg(BES2600_DBG_PWR, "%s, add async event:%d(%d) timeout:%d\n",
                        __func__, BES_PWR_EVENT_NUMBER(event),  event >> 31, timeout);
                item = list_first_entry(&bes_pwr->free_event_list,
                        struct bes2600_pwr_event_t, link);
                list_move_tail(&item->link, &bes_pwr->async_timeout_list);
                item->event = event;
                item->delay = timeout;
        }
}

static void bes2600_add_power_delay_event(struct bes2600_pwr_t *bes_pwr, u32 event, u32 timeout)
{
        struct bes2600_pwr_event_t *item = NULL;
        unsigned long max_timeout = 0;
        bool match = false;

        /* check if the event is already in pending list */
        if(!list_empty(&bes_pwr->pending_event_list)) {
                list_for_each_entry(item, &bes_pwr->pending_event_list, link) {
                        if(item->event == event) {
                                match = true;
                                break;
                        }
                }
        }

        /* update event or add a new event */
        if(match && (item != NULL)) {
                /* duplicate event */
                item->timeout = jiffies + (timeout * HZ + HZ * BES2600_POWER_DOWN_DELAY) / 1000;
                bes2600_dbg(BES2600_DBG_PWR, "%s, update event:%d(%d) timeout:%d\n",
                        __func__, BES_PWR_EVENT_NUMBER(event),  event >> 31, timeout);
        } else {
                /* delete expired event if free_event_list is empty */
                if(list_empty(&bes_pwr->free_event_list)) {
                        bes2600_info(BES2600_DBG_PWR, "%s, update delay event\n", __func__);
                        bes2600_update_power_delay_events(bes_pwr, &max_timeout);
                }

                /* throw out exception if free_event_list is empty */
                BUG_ON(list_empty(&bes_pwr->free_event_list));

                /* add event instance to pending list */
                bes2600_dbg(BES2600_DBG_PWR, "%s, add event:%d(%d) timeout:%d\n",
                        __func__, BES_PWR_EVENT_NUMBER(event),  event >> 31, timeout);
                item = list_first_entry(&bes_pwr->free_event_list,
                        struct bes2600_pwr_event_t, link);
                list_move_tail(&item->link, &bes_pwr->pending_event_list);
                item->event = event;
                item->timeout = jiffies + (timeout * HZ + HZ * BES2600_POWER_DOWN_DELAY) / 1000;
                bes2600_dump_power_busy_event(bes_pwr, "add new event");
        }
}

static bool bes2600_del_pending_event(struct bes2600_pwr_t *bes_pwr, u32 event)
{
        struct bes2600_pwr_event_t *item = NULL, *temp = NULL;
        bool matched = false;

        list_for_each_entry_safe(item, temp, &bes_pwr->pending_event_list, link) {
                if(event == item->event) {
                        matched = true;
                        list_move_tail(&item->link, &bes_pwr->free_event_list);
                        bes2600_dbg(BES2600_DBG_PWR, "delete pending event:%d(%d)\n",
                                BES_PWR_EVENT_NUMBER(event), event >> 31);
                        break;
                }
        }

        bes2600_dump_power_busy_event(bes_pwr, "delete");

        return matched;
}

static void bes2600_flush_pending_events(struct bes2600_pwr_t *bes_pwr)
{
        struct bes2600_pwr_event_t *item = NULL, *temp = NULL;

        list_for_each_entry_safe(item, temp, &bes_pwr->pending_event_list, link) {
                list_move_tail(&item->link, &bes_pwr->free_event_list);
                bes2600_dbg(BES2600_DBG_PWR, "flush pending event:%d(%d)\n",
                                BES_PWR_EVENT_NUMBER(item->event), item->event >> 31);
        }
        bes2600_dump_power_busy_event(bes_pwr, "flush");
}

static void bes2600_trigger_power_delay_down(struct bes2600_pwr_t *bes_pwr, unsigned long max_timeout)
{
        /* get the gap of the two timestamp */
        max_timeout = (max_timeout >= jiffies) ?
                (max_timeout - jiffies) : (ULONG_MAX - jiffies + max_timeout);

        bes2600_dbg(BES2600_DBG_PWR, "restart delayed work, timeout:%lu\n", max_timeout);
        queue_delayed_work(bes_pwr->hw_priv->workqueue, &bes_pwr->power_down_work, max_timeout);
}

static void bes2600_pwr_lock_tx(struct bes2600_common *hw_priv)
{
        unsigned long flags;

        spin_lock_irqsave(&hw_priv->bes_power.pwr_lock, flags);
        if(!hw_priv->bes_power.pending_lock) {
                hw_priv->bes_power.pending_lock = true;
                bes2600_dbg(BES2600_DBG_PWR, "bes pwr lock tx\n");
                wsm_lock_tx_async(hw_priv);
        }
        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);
}

static void bes2600_pwr_unlock_tx(struct bes2600_common *hw_priv)
{
        unsigned long flags;

        spin_lock_irqsave(&hw_priv->bes_power.pwr_lock, flags);
        if(hw_priv->bes_power.pending_lock) {
                hw_priv->bes_power.pending_lock = false;
                bes2600_dbg(BES2600_DBG_PWR, "bes pwr unlock tx\n");
                wsm_unlock_tx(hw_priv);
        }
        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);
}

static void bes2600_pwr_call_enter_lp_cb(struct bes2600_common *hw_priv)
{
        struct bes2600_pwr_enter_cb_item *item = NULL;

        mutex_lock(&hw_priv->bes_power.pwr_cb_mutex);
        if (!list_empty(&hw_priv->bes_power.enter_cb_list)) {
                list_for_each_entry(item, &hw_priv->bes_power.enter_cb_list, link) {
                        if(item->cb != NULL)
                                item->cb(hw_priv); 
                }
        }
        mutex_unlock(&hw_priv->bes_power.pwr_cb_mutex);
}

static void bes2600_pwr_call_exit_lp_cb(struct bes2600_common *hw_priv)
{
        struct bes2600_pwr_exit_cb_item *item = NULL;

        mutex_lock(&hw_priv->bes_power.pwr_cb_mutex);
        if (!list_empty(&hw_priv->bes_power.exit_cb_list)) {
                list_for_each_entry(item, &hw_priv->bes_power.exit_cb_list, link) {
                        if(item->cb != NULL)
                                item->cb(hw_priv); 
                }
        }
        mutex_unlock(&hw_priv->bes_power.pwr_cb_mutex);
}

static void bes2600_pwr_delete_all_cb(struct bes2600_common *hw_priv)
{
        struct bes2600_pwr_enter_cb_item *item = NULL, *temp = NULL;
        struct bes2600_pwr_exit_cb_item *item1 = NULL, *temp1 = NULL;

        mutex_lock(&hw_priv->bes_power.pwr_cb_mutex);

        /* delete all cb in enter_cb_list */
        list_for_each_entry_safe(item, temp, &hw_priv->bes_power.enter_cb_list, link) {
                list_del(&item->link);
                kfree(item);
        }

        /* delete all cb in exit_cb_list */
        list_for_each_entry_safe(item1, temp1, &hw_priv->bes_power.exit_cb_list, link) {
                list_del(&item->link);
                kfree(item);
        }

        mutex_unlock(&hw_priv->bes_power.pwr_cb_mutex);
}

static void bes2600_pwr_device_enter_lp_mode(struct bes2600_common *hw_priv)
{
        int ret = 0;
        struct wsm_operational_mode mode = {
		.power_mode = wsm_power_mode_quiescent,
		.disableMoreFlagUsage = true,
	};

        bes2600_dbg(BES2600_DBG_PWR, "host unlock lmac\n");
        ret = wsm_set_operational_mode(hw_priv, &mode, 0);
        bes2600_err_with_cond(ret, BES2600_DBG_PWR, "%s, set operation mode fail\n", __func__);

        /* wait other module to finish work */
        bes2600_pwr_call_enter_lp_cb(hw_priv);

        if(hw_priv->sbus_ops->sbus_deactive) {
                ret = hw_priv->sbus_ops->sbus_deactive(hw_priv->sbus_priv, SUBSYSTEM_MCU);
                bes2600_err_with_cond(ret, BES2600_DBG_PWR, "%s, deactive mcu fail\n", __func__);
        }

        if(hw_priv->sbus_ops->gpio_sleep)
                hw_priv->sbus_ops->gpio_sleep(hw_priv->sbus_priv, GPIO_WAKE_FLAG_MCU);
        bes2600_info(BES2600_DBG_PWR, "device enter sleep\n");
}

static int bes2600_pwr_enter_lp_mode(struct bes2600_common *hw_priv)
{
        int i = 0;
        struct bes2600_vif *priv;
        int ret = 0;
        char ip_str[20];
        unsigned long status = 0;

        /* set interface low power configuration */
        bes2600_for_each_vif(hw_priv, priv, i) {
#ifdef P2P_MULTIVIF
		if (i == (CW12XX_MAX_VIFS - 1))
                        continue;
#endif
		if (!priv)
			continue;

                if (priv->join_status == BES2600_JOIN_STATUS_STA &&
                    priv->bss_params.aid &&
                    priv->setbssparams_done &&
                    priv->filter4.enable) {
                        /* enable arp filter */
                        bes2600_dbg(BES2600_DBG_PWR, "%s, arp filter, enable:%d addr:%s\n",
                                __func__, priv->filter4.enable, bes2600_get_mac_str(ip_str, priv->filter4.ipv4Address[0]));
                        ret = wsm_set_arp_ipv4_filter(hw_priv, &priv->filter4, priv->if_id);
                        bes2600_err_with_cond(ret, BES2600_DBG_PWR, "%s, set arp filter failed\n", __func__);

                        /* skip beacon receive if applications don't have muticast service */
                        if(priv->join_dtim_period && !priv->has_multicast_subscription) {
                                unsigned listen_interval = 1;
                                if(priv->join_dtim_period >= CONFIG_BES2600_LISTEN_INTERVAL) {
                                        listen_interval = priv->join_dtim_period;
                                } else {
                                        listen_interval = CONFIG_BES2600_LISTEN_INTERVAL / priv->join_dtim_period;
                                }
                                ret = wsm_set_beacon_wakeup_period(hw_priv, 1, listen_interval, priv->if_id);
                                bes2600_err_with_cond(ret, BES2600_DBG_PWR, "%s, set wakeup period failed\n", __func__);
                        }

                        /* Set Enable Broadcast Address Filter */
                        priv->broadcast_filter.action_mode = WSM_FILTER_ACTION_FILTER_OUT;
                        if (priv->join_status == BES2600_JOIN_STATUS_AP)
                                priv->broadcast_filter.address_mode = WSM_FILTER_ADDR_MODE_A3;
                        ret = bes2600_set_macaddrfilter(hw_priv, priv, (u8 *)&priv->broadcast_filter);
                        bes2600_err_with_cond(ret, BES2600_DBG_PWR, "%s, set bc filter failed\n", __func__);

                        /* enter low power mode */
                        bes2600_dbg(BES2600_DBG_PWR, "%s, psMode:%s, fastPsmIdlePeriod:%d apPsmChangePeriod:%d minAutoPsPollPeriod:%d\n",
                                        __func__, bes2600_get_ps_mode_str(priv->powersave_mode.pmMode), priv->powersave_mode.fastPsmIdlePeriod,
                                        priv->powersave_mode.apPsmChangePeriod, priv->powersave_mode.minAutoPsPollPeriod);
                        ret = bes2600_set_pm(priv, &priv->powersave_mode);
                        bes2600_err_with_cond(ret, BES2600_DBG_PWR, "%s, set operation mode fail\n", __func__);

                        /* wait power save mode changed indication */
                        status = wait_for_completion_timeout(&hw_priv->bes_power.pm_enter_cmpl, 5 * HZ);
                        reinit_completion(&hw_priv->bes_power.pm_enter_cmpl);
                        bes2600_err_with_cond(!status, BES2600_DBG_PWR, "%s, wait pm ind timeout\n", __func__);
                }
	}

        /* set device low power configuration */
        bes2600_pwr_device_enter_lp_mode(hw_priv);

        return ret;
}

static void bes2600_pwr_device_exit_lp_mode(struct bes2600_common *hw_priv)
{
        int ret = 0;
        struct wsm_operational_mode mode = {
		.power_mode = wsm_power_mode_active,
		.disableMoreFlagUsage = true,
	};

        bes2600_dbg(BES2600_DBG_PWR, "host lock lmac\n");
        if(hw_priv->sbus_ops->gpio_wake)
                hw_priv->sbus_ops->gpio_wake(hw_priv->sbus_priv, GPIO_WAKE_FLAG_MCU);

        if(hw_priv->sbus_ops->sbus_active) {
                ret = hw_priv->sbus_ops->sbus_active(hw_priv->sbus_priv, SUBSYSTEM_MCU);
                bes2600_err_with_cond(ret, BES2600_DBG_PWR, "%s, active mcu fail\n", __func__);
        }

        ret = wsm_set_operational_mode(hw_priv, &mode, 0);
        bes2600_err_with_cond(ret, BES2600_DBG_PWR, "%s, set operation mode fail %i\n", __func__, ret);
        bes2600_info(BES2600_DBG_PWR, "device exit sleep\n");
}

static int bes2600_pwr_exit_lp_mode(struct bes2600_common *hw_priv)
{
        int i = 0, ret = 0;
        struct bes2600_vif *priv;
        struct wsm_arp_ipv4_filter filter;
        struct wsm_set_pm pm;
        char ip_str[20];

        /* set device low power configuration */
        bes2600_pwr_device_exit_lp_mode(hw_priv);

        /* set interface low power configutation */
        bes2600_for_each_vif(hw_priv, priv, i) {
#ifdef P2P_MULTIVIF
		if (i == (CW12XX_MAX_VIFS - 1))
                        continue;
#endif
		if (!priv)
			continue;

                if (priv->join_status == BES2600_JOIN_STATUS_STA &&
                    priv->bss_params.aid &&
                    priv->setbssparams_done &&
                    priv->filter4.enable) {
                        /* enable arp filter */
                        filter = priv->filter4;
                        filter.enable = false;
                        bes2600_dbg(BES2600_DBG_PWR, "%s, arp filter, enable:%d addr:%s\n",
                                __func__, filter.enable, bes2600_get_mac_str(ip_str, filter.ipv4Address[0]));
                        ret = wsm_set_arp_ipv4_filter(hw_priv, &filter, priv->if_id);
                        bes2600_err_with_cond(ret, BES2600_DBG_PWR, "%s, set arp filter failed\n", __func__);

                        /* set wakeup perioid */
                        wsm_set_beacon_wakeup_period(hw_priv, priv->join_dtim_period, 0, priv->if_id);
                        bes2600_err_with_cond(ret, BES2600_DBG_PWR, "%s, set wakeup period failed\n", __func__);

                        /* Set Enable Broadcast Address Filter */
                        priv->broadcast_filter.action_mode = WSM_FILTER_ACTION_IGNORE;
                        if (priv->join_status == BES2600_JOIN_STATUS_AP)
                                priv->broadcast_filter.address_mode = WSM_FILTER_ADDR_MODE_NONE;
                        bes2600_set_macaddrfilter(hw_priv, priv, (u8 *)&priv->broadcast_filter);
                        bes2600_err_with_cond(ret, BES2600_DBG_PWR, "%s, set bc filter failed\n", __func__);

                        /* exit low power mode */
                        pm = priv->powersave_mode;
                        pm.pmMode = WSM_PSM_ACTIVE;
                        bes2600_dbg(BES2600_DBG_PWR, "%s, psMode:%s, fastPsmIdlePeriod:%d apPsmChangePeriod:%d minAutoPsPollPeriod:%d\n",
                                        __func__, bes2600_get_ps_mode_str(pm.pmMode), pm.fastPsmIdlePeriod, pm.apPsmChangePeriod, pm.minAutoPsPollPeriod);
                        ret = bes2600_set_pm(priv, &pm);
                        bes2600_err_with_cond(ret, BES2600_DBG_PWR, "%s, set operation mode fail\n", __func__);
                }
	}

        /* call all exit lower power callback */
        bes2600_pwr_call_exit_lp_cb(hw_priv);

        return ret;
}

static void bes2600_pwr_unlock_device(struct bes2600_common *hw_priv)
{
        unsigned long flags;

        /* set device to low power mode */
        mutex_lock(&hw_priv->bes_power.pwr_mutex);

        bes2600_pwr_lock_tx(hw_priv);

        spin_lock_irqsave(&hw_priv->bes_power.pwr_lock, flags);
        if(hw_priv->bes_power.power_state == POWER_DOWN_STATE_LOCKED) {
                hw_priv->bes_power.power_state = POWER_DOWN_STATE_UNLOCKING;
                hw_priv->bes_power.power_down_task = current;
                spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);

                bes2600_pwr_enter_lp_mode(hw_priv);

                spin_lock_irqsave(&hw_priv->bes_power.pwr_lock, flags);
                hw_priv->bes_power.power_down_task = NULL;
                hw_priv->bes_power.power_state = POWER_DOWN_STATE_UNLOCKED;
                spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);
        } else {
                spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);
        }
        mutex_unlock(&hw_priv->bes_power.pwr_mutex);

        /* allow system to enter suspend mode */
        pm_relax(hw_priv->pdev);
}

static void bes2600_pwr_lock_device(struct bes2600_common *hw_priv)
{
        unsigned long flags;

        /* prevent system from entering suspend mode */
        pm_stay_awake(hw_priv->pdev);

        /* wakeup device from low power mode */
        mutex_lock(&hw_priv->bes_power.pwr_mutex);
        spin_lock_irqsave(&hw_priv->bes_power.pwr_lock, flags);
        if(hw_priv->bes_power.power_state == POWER_DOWN_STATE_UNLOCKED) {
                hw_priv->bes_power.power_state = POWER_DOWN_STATE_LOCKING;
                hw_priv->bes_power.power_up_task = current;
                spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);

                bes2600_pwr_exit_lp_mode(hw_priv);

                spin_lock_irqsave(&hw_priv->bes_power.pwr_lock, flags);
                hw_priv->bes_power.power_up_task = NULL;
                hw_priv->bes_power.power_state = POWER_DOWN_STATE_LOCKED;
                spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);
        } else {
                spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);
        }

        bes2600_pwr_unlock_tx(hw_priv);

        mutex_unlock(&hw_priv->bes_power.pwr_mutex);
}

static void bes2600_pwr_trigger_delayed_work(struct bes2600_common *hw_priv)
{
        unsigned long max_timeout = 0;
        bool constant_event_exist = false;
        unsigned long flags;

        spin_lock_irqsave(&hw_priv->bes_power.pwr_lock, flags);
        constant_event_exist = bes2600_update_power_delay_events(&hw_priv->bes_power, &max_timeout);

        if(!constant_event_exist && max_timeout > 0) {
                bes2600_trigger_power_delay_down(&hw_priv->bes_power, max_timeout);
        }
        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);
}

static void bes2600_power_down_work(struct work_struct *work)
{
        struct bes2600_common *hw_priv =
		container_of(work, struct bes2600_common, bes_power.power_down_work.work);

        unsigned long max_timeout = 0;
        bool constant_event_exist = false;
        unsigned long flags;

        spin_lock_irqsave(&hw_priv->bes_power.pwr_lock, flags);
        constant_event_exist = bes2600_update_power_delay_events(&hw_priv->bes_power, &max_timeout);
        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);

        if(!constant_event_exist && max_timeout == 0) {
                /* no pending event, unlock device */
                bes2600_dbg(BES2600_DBG_PWR, "%s no pending event\n", __func__);
                bes2600_pwr_unlock_device(hw_priv);
        } else {
                /* have power busy event, lock device */
                bes2600_dbg(BES2600_DBG_PWR, "%s have pending event\n", __func__);
                bes2600_pwr_lock_device(hw_priv);

                /* only have delayed power busy event, restart delayed work */
                if(!constant_event_exist && max_timeout > 0) {
                        bes2600_dbg(BES2600_DBG_PWR, "%s restart delayed work\n", __func__);
                        spin_lock_irqsave(&hw_priv->bes_power.pwr_lock, flags);
                        bes2600_trigger_power_delay_down(&hw_priv->bes_power, max_timeout);
                        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);
                }
        }
}

static void bes2600_power_async_work(struct work_struct *work)
{
        struct bes2600_common *hw_priv =
		container_of(work, struct bes2600_common, bes_power.power_async_work);

        bes2600_power_down_work(&hw_priv->bes_power.power_down_work.work);
}

static void bes2600_power_mcu_down_work(struct work_struct *work)
{
        struct bes2600_common *hw_priv =
		container_of(work, struct bes2600_common, bes_power.power_mcu_down_work);
        unsigned long max_timeout = 0;
        bool constant_event_exist = false;
        unsigned long flags;
        enum power_down_state power_state;
        int ret = 0;

        spin_lock_irqsave(&hw_priv->bes_power.pwr_lock, flags);
        constant_event_exist = bes2600_update_power_delay_events(&hw_priv->bes_power, &max_timeout);
        power_state = hw_priv->bes_power.power_state;
        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);

        if(!constant_event_exist &&
           max_timeout == 0 &&
           power_state == POWER_DOWN_STATE_UNLOCKED) {
                bes2600_info(BES2600_DBG_PWR, "mcu sleep directly");
                mutex_lock(&hw_priv->bes_power.pwr_mutex);

                if(hw_priv->sbus_ops->gpio_wake)
                        hw_priv->sbus_ops->gpio_wake(hw_priv->sbus_priv, GPIO_WAKE_FLAG_MCU);

                if(hw_priv->sbus_ops->sbus_active) {
                        ret = hw_priv->sbus_ops->sbus_active(hw_priv->sbus_priv, SUBSYSTEM_MCU);
                        bes2600_err_with_cond(ret, BES2600_DBG_PWR, "%s, active mcu fail\n", __func__);
                }

                 if(hw_priv->sbus_ops->sbus_deactive) {
                        ret = hw_priv->sbus_ops->sbus_deactive(hw_priv->sbus_priv, SUBSYSTEM_MCU);
                        bes2600_err_with_cond(ret, BES2600_DBG_PWR, "%s, deactive mcu fail\n", __func__);
                }

                if(hw_priv->sbus_ops->gpio_sleep)
                        hw_priv->sbus_ops->gpio_sleep(hw_priv->sbus_priv, GPIO_WAKE_FLAG_MCU);
                mutex_unlock(&hw_priv->bes_power.pwr_mutex);
        }
}

void bes2600_pwr_init(struct bes2600_common *hw_priv)
{
        int i = 0;

        hw_priv->bes_power.power_state = POWER_DOWN_STATE_UNLOCKED;
        hw_priv->bes_power.hw_priv = hw_priv;
        spin_lock_init(&hw_priv->bes_power.pwr_lock);
        INIT_DELAYED_WORK(&hw_priv->bes_power.power_down_work, bes2600_power_down_work);
        INIT_WORK(&hw_priv->bes_power.power_async_work, bes2600_power_async_work);
        INIT_WORK(&hw_priv->bes_power.power_mcu_down_work, bes2600_power_mcu_down_work);
        INIT_LIST_HEAD(&hw_priv->bes_power.async_timeout_list);
        INIT_LIST_HEAD(&hw_priv->bes_power.pending_event_list);
        INIT_LIST_HEAD(&hw_priv->bes_power.free_event_list);
        mutex_init(&hw_priv->bes_power.pwr_cb_mutex);
        INIT_LIST_HEAD(&hw_priv->bes_power.enter_cb_list);
        INIT_LIST_HEAD(&hw_priv->bes_power.exit_cb_list);
        hw_priv->bes_power.pending_lock = false;
        hw_priv->bes_power.power_down_task = NULL;
        hw_priv->bes_power.power_up_task = NULL;
        mutex_init(&hw_priv->bes_power.pwr_mutex);
        atomic_set(&hw_priv->bes_power.dev_state, 0);
        init_completion(&hw_priv->bes_power.pm_enter_cmpl);
        sema_init(&hw_priv->bes_power.sync_lock, 1);
        device_set_wakeup_capable(hw_priv->pdev, true);

        for(i = 0; i < BES2600_DELAY_EVENT_NUM; i++) {
                hw_priv->bes_power.pwr_events[i].idx = i;
                list_add_tail(&hw_priv->bes_power.pwr_events[i].link, &hw_priv->bes_power.free_event_list);
        }
}

void bes2600_pwr_exit(struct bes2600_common *hw_priv)
{
        bes2600_pwr_delete_all_cb(hw_priv);
}

void bes2600_pwr_prepare(struct bes2600_common *hw_priv)
{
        /* wait stop operation end */
        down(&hw_priv->bes_power.sync_lock);
}


void bes2600_pwr_complete(struct bes2600_common *hw_priv)
{
        /* notify stop operation end */
        up(&hw_priv->bes_power.sync_lock);
}

void bes2600_pwr_start(struct bes2600_common *hw_priv)
{
        unsigned long flags;

        if (!bes2600_chrdev_is_signal_mode())
                return ;

        /* start power management state machine */
        atomic_set(&hw_priv->bes_power.dev_state, 1);
        bes2600_dbg(BES2600_DBG_PWR, "start power management.\n");

        /* enable device wakeup function */
        device_wakeup_enable(hw_priv->pdev);

        /* set power_state to busy and clear state */
        spin_lock_irqsave(&hw_priv->bes_power.pwr_lock, flags);
        hw_priv->bes_power.power_state = POWER_DOWN_STATE_LOCKED;
        hw_priv->bes_power.power_down_task = NULL;
        hw_priv->bes_power.power_up_task = NULL;
        hw_priv->bes_power.sys_suspend_task = NULL;
        hw_priv->bes_power.sys_resume_task = NULL;
        hw_priv->bes_power.pending_lock = false;
        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);

        /* set gpio and prevent device from entering sleep mode */
        if(hw_priv->sbus_ops->gpio_wake)
                hw_priv->sbus_ops->gpio_wake(hw_priv->sbus_priv, GPIO_WAKE_FLAG_MCU);

        /* start idle timer */
        queue_delayed_work(hw_priv->workqueue,
			&hw_priv->bes_power.power_down_work, (HZ * BES2600_POWER_DOWN_DELAY) / 1000);
}

void bes2600_pwr_stop(struct bes2600_common *hw_priv)
{
        unsigned long flags;
        unsigned long max_timeout;

        if (!bes2600_chrdev_is_signal_mode())
                return ;

        /* stop power management state machine */
        atomic_set(&hw_priv->bes_power.dev_state, 0);
        bes2600_info(BES2600_DBG_PWR, "stop power management.\n");

        /* cancel pending work */
        cancel_delayed_work_sync(&hw_priv->bes_power.power_down_work);
        flush_delayed_work(&hw_priv->bes_power.power_down_work);
        cancel_work_sync(&hw_priv->bes_power.power_async_work);
        flush_work(&hw_priv->bes_power.power_async_work);
        cancel_work_sync(&hw_priv->bes_power.power_mcu_down_work);
        flush_work(&hw_priv->bes_power.power_mcu_down_work);

        /* delete all pending event and clear state */
        spin_lock_irqsave(&hw_priv->bes_power.pwr_lock, flags);
        bes2600_update_power_delay_events(&hw_priv->bes_power, &max_timeout);
        bes2600_flush_pending_events(&hw_priv->bes_power);
        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);

        /* allow mcu sleep */
        bes2600_power_down_work(&hw_priv->bes_power.power_down_work.work);
        bes2600_warn_with_cond(hw_priv->bes_power.power_state != POWER_DOWN_STATE_UNLOCKED,
                                BES2600_DBG_PWR, "power state is not unlocked when stop.\n");

        /* unlock tx if tx is locked */
        bes2600_pwr_unlock_tx(hw_priv);

        /* disable device wakeup function */
        device_wakeup_disable(hw_priv->pdev);
}

int bes2600_pwr_set_busy_event(struct bes2600_common *hw_priv, u32 event)
{
        int ret = 0;
        bool need_lock = false;
        bool need_wait = false;
        unsigned long flags;

        if(atomic_read(&hw_priv->bes_power.dev_state) == 0) {
               return -1;
        }

        spin_lock_irqsave(&hw_priv->bes_power.pwr_lock, flags);

        /* don't set busy event if the command is for unlocking device */
        if((event == BES_PWR_LOCK_ON_WSM_TX)
           && (hw_priv->bes_power.power_state == POWER_DOWN_STATE_UNLOCKING)) {
                if(hw_priv->bes_power.power_down_task == current) {
                        /* BES_PWR_LOCK_ON_WSM_TX is from power down work */
                        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);
                        return 0;
                }
        }

        /* don't set busy event also if the command is for locking device */
        if((event == BES_PWR_LOCK_ON_WSM_TX)
           && (hw_priv->bes_power.power_state == POWER_DOWN_STATE_LOCKING)) {
                if(hw_priv->bes_power.power_up_task == current) {
                        /* BES_PWR_LOCK_ON_WSM_TX is from power down work */
                        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);
                        return 0;
                }
        }

        /* don't set busy event if the command is for suspend/resume */
        if((event == BES_PWR_LOCK_ON_WSM_TX)
           && (hw_priv->bes_power.power_state == POWER_DOWN_STATE_UNLOCKED)) {
                if(hw_priv->bes_power.sys_suspend_task == current ||
                   hw_priv->bes_power.sys_resume_task == current) {
                        /* BES_PWR_LOCK_ON_WSM_TX is from suspend/resume work */
                        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);
                        return 0;
                }
        }

        /* set busy event to pending_event_list */
        BES_PWR_EVENT_SET_CONSTANT(event);
        bes2600_add_power_delay_event(&hw_priv->bes_power, event, 0);

        /* execute lock device operation or wait lock operation finish */
        if((hw_priv->bes_power.power_state == POWER_DOWN_STATE_UNLOCKED)
           || (hw_priv->bes_power.power_state == POWER_DOWN_STATE_UNLOCKING)) {
                need_lock = true;
        } else if(hw_priv->bes_power.power_state == POWER_DOWN_STATE_LOCKING
           && (hw_priv->bes_power.power_up_task != current)) {
                need_wait = true;
        }

        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);

        if(need_wait) {
                /* lock device is doing, wait operation done */
                bes2600_info(BES2600_DBG_PWR, "%s wait lock device done, event:%d\n", __func__, BES_PWR_EVENT_NUMBER(event));
                mutex_lock(&hw_priv->bes_power.pwr_mutex);
                mutex_unlock(&hw_priv->bes_power.pwr_mutex);
        }

        if(need_lock) {
                /* cancel delayed work */
                cancel_delayed_work_sync(&hw_priv->bes_power.power_down_work);
                flush_delayed_work(&hw_priv->bes_power.power_down_work);

                bes2600_info(BES2600_DBG_PWR, "%s lock device by event:%d\n", __func__, BES_PWR_EVENT_NUMBER(event));
                bes2600_pwr_lock_device(hw_priv);
        }

       return ret;
}

int bes2600_pwr_set_busy_event_async(struct bes2600_common *hw_priv, u32 event)
{
        bool need_lock = false;
        unsigned long flags;

        if(atomic_read(&hw_priv->bes_power.dev_state) == 0) {
                return -1;
        }

        spin_lock_irqsave(&hw_priv->bes_power.pwr_lock, flags);
        BES_PWR_EVENT_SET_CONSTANT(event);
        bes2600_add_power_delay_event(&hw_priv->bes_power, event, 0);
        if(((hw_priv->bes_power.power_state == POWER_DOWN_STATE_UNLOCKED)
           || (hw_priv->bes_power.power_state == POWER_DOWN_STATE_UNLOCKING))) {
                need_lock = true;
        }
        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);

        if(need_lock && !work_pending(&hw_priv->bes_power.power_async_work)) {
                bes2600_info(BES2600_DBG_PWR, "%s lock device by event:%d\n", __func__, BES_PWR_EVENT_NUMBER(event));
                queue_work(hw_priv->workqueue, &hw_priv->bes_power.power_async_work);
        }

        return 0;

}

int bes2600_pwr_set_busy_event_with_timeout(struct bes2600_common *hw_priv, u32 event, u32 timeout)
{
        int ret = 0;
        bool need_lock = false;
        bool need_wait = false;
        unsigned long flags;

        if(atomic_read(&hw_priv->bes_power.dev_state) == 0) {
                return -1;
        }

        spin_lock_irqsave(&hw_priv->bes_power.pwr_lock, flags);

        /* add delayed event to pending_event_list */
        bes2600_add_power_delay_event(&hw_priv->bes_power, event, timeout);

        /* execute lock device operation or wait lock operation finish */
        if((hw_priv->bes_power.power_state == POWER_DOWN_STATE_UNLOCKED)
           || (hw_priv->bes_power.power_state == POWER_DOWN_STATE_UNLOCKING)) {
                need_lock = true;
        } else if(hw_priv->bes_power.power_state == POWER_DOWN_STATE_LOCKING
           && (hw_priv->bes_power.power_up_task != current)) {
                need_wait = true;
        }

        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);

        if(need_wait) {
                /* lock device is doing, wait operation done */
                bes2600_info(BES2600_DBG_PWR, "%s wait lock device done, event:%d\n", __func__, event);
                mutex_lock(&hw_priv->bes_power.pwr_mutex);
                mutex_unlock(&hw_priv->bes_power.pwr_mutex);
        }

        if(need_lock) {
                /* cancel delayed work */
                bes2600_info(BES2600_DBG_PWR, "%s lock device by event:%d\n", __func__, event);
                cancel_delayed_work_sync(&hw_priv->bes_power.power_down_work);
                flush_delayed_work(&hw_priv->bes_power.power_down_work);

                bes2600_pwr_lock_device(hw_priv);
        }

        if(!delayed_work_pending(&hw_priv->bes_power.power_down_work)) {
                bes2600_pwr_trigger_delayed_work(hw_priv);
        }

       return ret;
}

int bes2600_pwr_set_busy_event_with_timeout_async(struct bes2600_common *hw_priv, u32 event, u32 timeout)
{
        int ret = 0;
        bool need_lock = false;
        unsigned long flags;

        if(atomic_read(&hw_priv->bes_power.dev_state) == 0) {
                return -1;
        }

        spin_lock_irqsave(&hw_priv->bes_power.pwr_lock, flags);
        if ((hw_priv->bes_power.power_state == POWER_DOWN_STATE_UNLOCKED) ||
           (hw_priv->bes_power.power_state == POWER_DOWN_STATE_LOCKED)) {
                bes2600_add_power_delay_event(&hw_priv->bes_power, event, timeout);
                if(hw_priv->bes_power.power_state == POWER_DOWN_STATE_UNLOCKED) {
                        need_lock = true;
                }
        } else if ((hw_priv->bes_power.power_state == POWER_DOWN_STATE_LOCKING) ||
           (hw_priv->bes_power.power_state == POWER_DOWN_STATE_UNLOCKING)) {
                bes2600_add_async_timeout_power_delay_event(&hw_priv->bes_power, event, timeout);
                if(hw_priv->bes_power.power_state == POWER_DOWN_STATE_UNLOCKING) {
                        need_lock = true;
                }
        }
        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);

        if(need_lock && !work_pending(&hw_priv->bes_power.power_async_work)) {
                bes2600_info(BES2600_DBG_PWR, "%s lock device by event:%d\n", __func__, event);
                queue_work(hw_priv->workqueue, &hw_priv->bes_power.power_async_work);
        }

       return ret;
}


int bes2600_pwr_clear_busy_event(struct bes2600_common *hw_priv, u32 event)
{
        int ret = 0;
        u32 constant_event = event;
        unsigned long flags;

        if(atomic_read(&hw_priv->bes_power.dev_state) == 0) {
                return -1;
        }

        spin_lock_irqsave(&hw_priv->bes_power.pwr_lock, flags);

        /* don't need to clear busy event if the command is for unlocking device */
        if((event == BES_PWR_LOCK_ON_WSM_TX)
           && (hw_priv->bes_power.power_state == POWER_DOWN_STATE_UNLOCKING)) {
                if(hw_priv->bes_power.power_down_task == current) {
                        /* BES_PWR_LOCK_ON_WSM_TX is from power down work */
                        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);
                        return 0;
                }
        }

        /* don't need also to clear busy event if the command is for locking device */
        if((event == BES_PWR_LOCK_ON_WSM_TX)
           && (hw_priv->bes_power.power_state == POWER_DOWN_STATE_LOCKING)) {
                if(hw_priv->bes_power.power_up_task == current) {
                        /* BES_PWR_LOCK_ON_WSM_TX is for powering up operation */
                        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);
                        return 0;
                }
        }

         /* don't set busy event if the command is for suspend/resume */
        if((event == BES_PWR_LOCK_ON_WSM_TX)
           && (hw_priv->bes_power.power_state == POWER_DOWN_STATE_UNLOCKED)) {
                if(hw_priv->bes_power.sys_suspend_task == current ||
                   hw_priv->bes_power.sys_resume_task == current) {
                        /* BES_PWR_LOCK_ON_WSM_TX is from suspend/resume work */
                        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);
                        return 0;
                }
        }

        /* change constant event to delay event */
        BES_PWR_EVENT_SET_CONSTANT(constant_event);
        if(bes2600_del_pending_event(&hw_priv->bes_power, constant_event)) {
                bes2600_add_power_delay_event(&hw_priv->bes_power, event, 0);
        }
        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);

        /* trigger power down delayed work */
        if(!delayed_work_pending(&hw_priv->bes_power.power_down_work)) {
                bes2600_dbg(BES2600_DBG_PWR, "%s restart delayed work\n", __func__);
                bes2600_pwr_trigger_delayed_work(hw_priv);
        }

       return ret;
}

void bes2600_pwr_notify_ps_changed(struct bes2600_common *hw_priv, u8 psmode)
{
        if((psmode & 0x01) != WSM_PSM_ACTIVE) {
                bes2600_dbg(BES2600_DBG_PWR, "complete pm_enter_cmpl\n");
                complete(&hw_priv->bes_power.pm_enter_cmpl);
        }
}

bool bes2600_pwr_device_is_idle(struct bes2600_common *hw_priv)
{
    bool idle = false;
    unsigned long flags;

    if (!bes2600_chrdev_is_signal_mode())
        return false;

    spin_lock_irqsave(&hw_priv->bes_power.pwr_lock, flags);
    idle = (hw_priv->bes_power.power_state == POWER_DOWN_STATE_UNLOCKED);
    spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);

    return idle;
}

void bes2600_pwr_register_en_lp_cb(struct bes2600_common *hw_priv, bes_pwr_enter_lp_cb cb)
{
        struct bes2600_pwr_enter_cb_item *item = NULL;

        mutex_lock(&hw_priv->bes_power.pwr_cb_mutex);
        list_for_each_entry(item, &hw_priv->bes_power.enter_cb_list, link) {
                if(item->cb == cb) {
                        bes2600_warn(BES2600_DBG_PWR, "the enter cb is already exist\n");
                        mutex_unlock(&hw_priv->bes_power.pwr_cb_mutex);
                        return;
                }
        }

        item = kzalloc(sizeof(struct bes2600_pwr_enter_cb_item), GFP_KERNEL);
        if(item) {
                item->cb = cb;
                list_add_tail(&item->link, &hw_priv->bes_power.enter_cb_list);
        }
        mutex_unlock(&hw_priv->bes_power.pwr_cb_mutex);

        bes2600_err_with_cond(item == NULL, BES2600_DBG_PWR, "register en_lp_cb fail.\n");
}

void bes2600_pwr_unregister_en_lp_cb(struct bes2600_common *hw_priv, bes_pwr_enter_lp_cb cb)
{
        struct bes2600_pwr_enter_cb_item *item = NULL, *temp = NULL;

        mutex_lock(&hw_priv->bes_power.pwr_cb_mutex);
        list_for_each_entry_safe(item, temp, &hw_priv->bes_power.enter_cb_list, link) {
                if(cb == item->cb) {
                        list_del(&item->link);
                        kfree(item);
                        break;
                }
        }
        mutex_unlock(&hw_priv->bes_power.pwr_cb_mutex);
}

void bes2600_pwr_register_exit_lp_cb(struct bes2600_common *hw_priv, bes_pwr_enter_lp_cb cb)
{
        struct bes2600_pwr_exit_cb_item *item = NULL;

        mutex_lock(&hw_priv->bes_power.pwr_cb_mutex);
        list_for_each_entry(item, &hw_priv->bes_power.exit_cb_list, link) {
                if(item->cb == cb) {
                        mutex_unlock(&hw_priv->bes_power.pwr_cb_mutex);
                        bes2600_warn(BES2600_DBG_PWR, "the exit cb is already exist\n");
                        return;
                }
        }

        item = kzalloc(sizeof(struct bes2600_pwr_exit_cb_item), GFP_KERNEL);
        if(item) {
                item->cb = cb;
                list_add_tail(&item->link, &hw_priv->bes_power.exit_cb_list);
        }
        mutex_unlock(&hw_priv->bes_power.pwr_cb_mutex);

        bes2600_err_with_cond(item == NULL, BES2600_DBG_PWR, "register en_lp_cb fail.\n");
        
}

void bes2600_pwr_unregister_exit_lp_cb(struct bes2600_common *hw_priv, bes_pwr_enter_lp_cb cb)
{
        struct bes2600_pwr_exit_cb_item *item = NULL, *temp = NULL;

        mutex_lock(&hw_priv->bes_power.pwr_cb_mutex);
        list_for_each_entry_safe(item, temp, &hw_priv->bes_power.exit_cb_list, link) {
                if(cb == item->cb) {
                        list_del(&item->link);
                        kfree(item);
                        break;
                }
        }
        mutex_unlock(&hw_priv->bes_power.pwr_cb_mutex);
}

void bes2600_pwr_suspend_start(struct bes2600_common *hw_priv)
{
        if(atomic_read(&hw_priv->bes_power.dev_state) == 0) {
                return;
        }

        mutex_lock(&hw_priv->bes_power.pwr_mutex);
        hw_priv->bes_power.sys_suspend_task = current;
        bes2600_pwr_device_exit_lp_mode(hw_priv);
        mutex_unlock(&hw_priv->bes_power.pwr_mutex);
}

void bes2600_pwr_suspend_end(struct bes2600_common *hw_priv)
{
        unsigned long max_timeout = 0;
        bool constant_event_exist = false;
        unsigned long flags;

        if(atomic_read(&hw_priv->bes_power.dev_state) == 0) {
                return;
        }

        spin_lock_irqsave(&hw_priv->bes_power.pwr_lock, flags);
        constant_event_exist = bes2600_update_power_delay_events(&hw_priv->bes_power, &max_timeout);
        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);

        mutex_lock(&hw_priv->bes_power.pwr_mutex);
        if(!constant_event_exist && max_timeout == 0)
                bes2600_pwr_device_enter_lp_mode(hw_priv);
        hw_priv->bes_power.sys_suspend_task = NULL;
        mutex_unlock(&hw_priv->bes_power.pwr_mutex);
}

void bes2600_pwr_resume_start(struct bes2600_common *hw_priv)
{
        if(atomic_read(&hw_priv->bes_power.dev_state) == 0) {
                return;
        }

        mutex_lock(&hw_priv->bes_power.pwr_mutex);
        hw_priv->bes_power.sys_resume_task = current;
        bes2600_pwr_device_exit_lp_mode(hw_priv);
        mutex_unlock(&hw_priv->bes_power.pwr_mutex);
}

void bes2600_pwr_resume_end(struct bes2600_common *hw_priv)
{
        unsigned long max_timeout = 0;
        bool constant_event_exist = false;
        unsigned long flags;

        if(atomic_read(&hw_priv->bes_power.dev_state) == 0) {
                return ;
        }

        spin_lock_irqsave(&hw_priv->bes_power.pwr_lock, flags);
        constant_event_exist = bes2600_update_power_delay_events(&hw_priv->bes_power, &max_timeout);
        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);

        mutex_lock(&hw_priv->bes_power.pwr_mutex);
        if(!constant_event_exist && max_timeout == 0)
                bes2600_pwr_device_enter_lp_mode(hw_priv);
        hw_priv->bes_power.sys_resume_task = NULL;
        mutex_unlock(&hw_priv->bes_power.pwr_mutex);
}

void bes2600_pwr_mcu_sleep_directly(struct bes2600_common *hw_priv)
{
        if(atomic_read(&hw_priv->bes_power.dev_state) == 0) {
                return;
        }

        if (bes2600_pwr_device_is_idle(hw_priv)) {
                if(!work_pending(&hw_priv->bes_power.power_mcu_down_work)) {
                        queue_work(hw_priv->workqueue, &hw_priv->bes_power.power_mcu_down_work);
                }
        }
}

int bes2600_pwr_busy_event_dump(struct bes2600_common *hw_priv, char *buffer, u32 buf_len)
{
        unsigned long max_timeout = 0;
        int used_len = 0;
        struct bes2600_pwr_event_t *item = NULL;
        unsigned long flags;

        if(!buffer) {
                return -1;
        }

        spin_lock_irqsave(&hw_priv->bes_power.pwr_lock, flags);
        bes2600_update_power_delay_events(&hw_priv->bes_power, &max_timeout);
         used_len = snprintf(buffer, buf_len, "Event    \t\tFlag\t\ttimeout(ticks)\n");
        if(!list_empty(&hw_priv->bes_power.pending_event_list)) {
                list_for_each_entry(item, &hw_priv->bes_power.pending_event_list, link) {
                        if(used_len + 50 < buf_len) {
                                used_len += snprintf(buffer + used_len, 50, "%9s\t\t%s\t\t%lu\n",
                                        bes2600_get_pwr_busy_event_name(item),
                                        BES_PWR_IS_CONSTANT_EVENT(item->event) ? "C" : "D",
                                        bes2600_get_pwr_busy_event_timeout(item));
                        } else {
                                spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);
                                return -1;
                        }
                }
        }
        spin_unlock_irqrestore(&hw_priv->bes_power.pwr_lock, flags);

        return 0;
}
