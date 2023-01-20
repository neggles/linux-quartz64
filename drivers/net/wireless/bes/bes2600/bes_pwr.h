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
#ifndef __BES_PWR_H__
#define __BES_PWR_H__

#include "bes2600.h"

enum bes2600_pwr_event_type {
        BES_PWR_LOCK_ON_SCAN = 1,
        BES_PWR_LOCK_ON_JOIN,
        BES_PWR_LOCK_ON_TX,
        BES_PWR_LOCK_ON_RX,
        BES_PWR_LOCK_ON_FLUSH,
        BES_PWR_LOCK_ON_ROC,
        BES_PWR_LOCK_ON_WSM_TX,
        BES_PWR_LOCK_ON_WSM_OPER,
        BES_PWR_LOCK_ON_BSS_LOST,
        BES_PWR_LOCK_ON_GET_IP,
        BES_PWR_LOCK_ON_PS_ACTIVE,
        BES_PWR_LOCK_ON_LMAC_RSP,
        BES_PWR_LOCK_ON_AP,
        BES_PWR_LOCK_ON_TEST_CMD,
        BES_PWR_LOCK_ON_MUL_REQ,
        BES_PWR_LOCK_ON_ADV_SCAN,
        BES_PWR_LOCK_ON_DISCON,
        BES_PWR_LOCK_ON_QUEUE_GC,
        BES_PWR_LOCK_ON_AP_LP_BAD,
        /* add new lock event here */
        BES_PWR_LOCK_ON_EVENT_MAX,
};

#define BES_PWR_IS_CONSTANT_EVENT(x)    ((x) & 0x80000000)
#define BES_PWR_EVENT_SET_CONSTANT(x)   (x = (x | 0x80000000))
#define BES_PWR_EVENT_NUMBER(x)         ((x) & 0x7fffffff)

#define BES2600_POWER_DOWN_DELAY        50       // unit in millisecond
#define BES2600_DELAY_EVENT_NUM         (BES_PWR_LOCK_ON_EVENT_MAX << 1)

#define BES_PWR_EVENT_TX_TIMEOUT        1500       // unit in millisecond
#define BES_PWR_EVENT_RX_TIMEOUT        1500      // unit in millisecond

struct bes2600_pwr_event_t
{
        struct list_head link;
        unsigned long timeout;
        unsigned long delay;
        u8 idx;
        enum bes2600_pwr_event_type event;
};

enum power_down_state
{
        POWER_DOWN_STATE_LOCKED = 0,
        POWER_DOWN_STATE_LOCKING,
        POWER_DOWN_STATE_UNLOCKING,
        POWER_DOWN_STATE_UNLOCKED,
};

typedef void (*bes_pwr_enter_lp_cb)(struct bes2600_common *hw_priv);
typedef void (*bes_pwr_exit_lp_cb)(struct bes2600_common *hw_priv);

struct bes2600_pwr_enter_cb_item
{
        struct list_head link;
        bes_pwr_enter_lp_cb cb;
};

struct bes2600_pwr_exit_cb_item
{
        struct list_head link;
        bes_pwr_exit_lp_cb cb;
};

struct bes2600_pwr_t
{
        spinlock_t pwr_lock;
        struct delayed_work power_down_work;
        struct work_struct power_async_work;
        struct work_struct power_mcu_down_work;
        struct list_head async_timeout_list;
        struct list_head pending_event_list;
        struct list_head free_event_list;
        enum power_down_state power_state;
        struct task_struct *power_down_task;
        struct task_struct *power_up_task;
        struct task_struct *sys_suspend_task;
        struct task_struct *sys_resume_task;
        struct semaphore sync_lock;
        bool pending_lock;
        atomic_t dev_state;
        struct mutex pwr_mutex;
        struct bes2600_common *hw_priv;
        struct completion pm_enter_cmpl;        
        struct mutex pwr_cb_mutex;
        struct list_head enter_cb_list;
        struct list_head exit_cb_list;
        struct bes2600_pwr_event_t pwr_events[BES2600_DELAY_EVENT_NUM];
};

#ifdef CONFIG_BES2600_WOWLAN
void bes2600_pwr_init(struct bes2600_common *hw_priv);
void bes2600_pwr_exit(struct bes2600_common *hw_priv);
void bes2600_pwr_prepare(struct bes2600_common *hw_priv);
void bes2600_pwr_complete(struct bes2600_common *hw_priv);
void bes2600_pwr_start(struct bes2600_common *hw_priv);
void bes2600_pwr_stop(struct bes2600_common *hw_priv);
int bes2600_pwr_set_busy_event(struct bes2600_common *hw_priv, u32 event);
int bes2600_pwr_set_busy_event_async(struct bes2600_common *hw_priv, u32 event);
int bes2600_pwr_set_busy_event_with_timeout(struct bes2600_common *hw_priv, u32 event, u32 timeout);
int bes2600_pwr_set_busy_event_with_timeout_async(struct bes2600_common *hw_priv, u32 event, u32 timeout);
int bes2600_pwr_clear_busy_event(struct bes2600_common *hw_priv, u32 event);
void bes2600_pwr_notify_ps_changed(struct bes2600_common *hw_priv, u8 psmode);
bool bes2600_pwr_device_is_idle(struct bes2600_common *hw_priv);
void bes2600_pwr_register_en_lp_cb(struct bes2600_common *hw_priv, bes_pwr_enter_lp_cb cb);
void bes2600_pwr_unregister_en_lp_cb(struct bes2600_common *hw_priv, bes_pwr_enter_lp_cb cb);
void bes2600_pwr_register_exit_lp_cb(struct bes2600_common *hw_priv, bes_pwr_enter_lp_cb cb);
void bes2600_pwr_unregister_exit_lp_cb(struct bes2600_common *hw_priv, bes_pwr_enter_lp_cb cb);
void bes2600_pwr_suspend_start(struct bes2600_common *hw_priv);
void bes2600_pwr_suspend_end(struct bes2600_common *hw_priv);
void bes2600_pwr_resume_start(struct bes2600_common *hw_priv);
void bes2600_pwr_resume_end(struct bes2600_common *hw_priv);
void bes2600_pwr_mcu_sleep_directly(struct bes2600_common *hw_priv);
int bes2600_pwr_busy_event_dump(struct bes2600_common *hw_priv, char *buffer, u32 buf_len);
#else
static inline void bes2600_pwr_init(struct bes2600_common *hw_priv) { }
static inline void bes2600_pwr_exit(struct bes2600_common *hw_priv) { }
static inline void bes2600_pwr_prepare(struct bes2600_common *hw_priv) { }
static inline void bes2600_pwr_complete(struct bes2600_common *hw_priv) { }
static inline void bes2600_pwr_start(struct bes2600_common *hw_priv) { }
static inline void bes2600_pwr_stop(struct bes2600_common *hw_priv) { }
static inline int bes2600_pwr_set_busy_event(struct bes2600_common *hw_priv, u32 event) { return 0; }
static inline int bes2600_pwr_set_busy_event_async(struct bes2600_common *hw_priv, u32 event) {return 0; }
static inline int bes2600_pwr_set_busy_event_with_timeout(struct bes2600_common *hw_priv, u32 event, u32 timeout) { return 0; }
static inline int bes2600_pwr_set_busy_event_with_timeout_async(struct bes2600_common *hw_priv, u32 event, u32 timeout) { return 0; }
static inline int bes2600_pwr_clear_busy_event(struct bes2600_common *hw_priv, u32 event) { return 0; }
static inline void bes2600_pwr_notify_ps_changed(struct bes2600_common *hw_priv, u8 psmode) { }
static inline bool bes2600_pwr_device_is_idle(struct bes2600_common *hw_priv) { return false; }
static inline void bes2600_pwr_register_en_lp_cb(struct bes2600_common *hw_priv, bes_pwr_enter_lp_cb cb) { }
static inline void bes2600_pwr_unregister_en_lp_cb(struct bes2600_common *hw_priv, bes_pwr_enter_lp_cb cb) { }
static inline void bes2600_pwr_register_exit_lp_cb(struct bes2600_common *hw_priv, bes_pwr_enter_lp_cb cb) { }
static inline void bes2600_pwr_unregister_exit_lp_cb(struct bes2600_common *hw_priv, bes_pwr_enter_lp_cb cb) { }
static inline void bes2600_pwr_suspend_start(struct bes2600_common *hw_priv) { }
static inline void bes2600_pwr_suspend_end(struct bes2600_common *hw_priv) { }
static inline void bes2600_pwr_resume_start(struct bes2600_common *hw_priv) { }
static inline void bes2600_pwr_resume_end(struct bes2600_common *hw_priv) { }
static inline void bes2600_pwr_mcu_sleep_directly(struct bes2600_common *hw_priv) { }
static inline int bes2600_pwr_busy_event_dump(struct bes2600_common *hw_priv, char *buffer, u32 buf_len) { return 0; }
#endif

#endif