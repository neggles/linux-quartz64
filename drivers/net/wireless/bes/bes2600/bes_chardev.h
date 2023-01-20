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
#ifndef __BES_CHARDEV_H__
#define __BES_CHARDEV_H__

#define BES2600_FW_TYPE_WIFI_SIGNAL	0
#define BES2600_FW_TYPE_WIFI_NO_SIGNAL	1
#define BES2600_FW_TYPE_BT		2
#define BES2600_FW_TYPE_MAX_NUM     3

/* dpd management */
u8* bes2600_chrdev_get_dpd_buffer(u32 size);
int bes2600_chrdev_update_dpd_data(void);
const u8* bes2600_chrdev_get_dpd_data(u32 *len);
void bes2600_chrdev_free_dpd_data(void);

/* get/set subs_priv instance from/to bes_chrdev module */
void bes2600_chrdev_set_sbus_priv_data(struct sbus_priv *priv);
struct sbus_priv *bes2600_chrdev_get_sbus_priv_data(void);

/* used to control device power down */
int bes2600_chrdev_check_system_close(void);
int bes2600_chrdev_do_system_close(const struct sbus_ops *sbus_ops, struct sbus_priv *priv);
void bes2600_chrdev_wakeup_bt(void);
void bes2600_chrdev_wifi_force_close(struct bes2600_common *hw_priv);

/* get and set internal state */
bool bes2600_chrdev_is_wifi_opened(void);
bool bes2600_chrdev_is_bt_opened(void);
int bes2600_chrdev_get_fw_type(void);
bool bes2600_chrdev_is_signal_mode(void);
void bes2600_chrdev_update_signal_mode(void);
bool bes2600_chrdev_is_bus_error(void);

/* init and deinit module */
int bes2600_chrdev_init(struct sbus_ops *ops);
void bes2600_chrdev_free(void);

#endif