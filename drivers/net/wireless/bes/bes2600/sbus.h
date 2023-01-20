/*
 * Common sbus abstraction layer interface for bes2600 wireless driver
 *
 * Copyright (c) 2010, Bestechnic
 * Author:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef BES2600_SBUS_H
#define BES2600_SBUS_H

/*
 * sbus priv forward definition.
 * Implemented and instantiated in particular modules.
 */
struct sbus_priv;
struct bes2600_common;

typedef void (*sbus_irq_handler)(void *priv);

enum SUBSYSTEM {
	SUBSYSTEM_MCU = 0,
	SUBSYSTEM_WIFI,
	SUBSYSTEM_BT,
	SUBSYSTEM_BT_LP,
};

enum GPIO_WAKE_FLAG
{
	GPIO_WAKE_FLAG_MCU = 0,
	GPIO_WAKE_FLAG_WIFI_ON,
	GPIO_WAKE_FLAG_WIFI_OFF,
	GPIO_WAKE_FLAG_BT_ON,
	GPIO_WAKE_FLAG_BT_OFF,
	GPIO_WAKE_FLAG_BT_LP_ON,
	GPIO_WAKE_FLAG_BT_LP_OFF,
	GPIO_WAKE_FLAG_HOST_SUSPEND,
	GPIO_WAKE_FLAG_HOST_RESUME,
	GPIO_WAKE_FLAG_SDIO_RX,
	GPIO_WAKE_FLAG_SDIO_PROBE,
};

struct sbus_ops {
	int (*init)(struct sbus_priv *self, struct bes2600_common *ar);
	int (*sbus_memcpy_fromio)(struct sbus_priv *self, unsigned int addr,
					void *dst, int count);
	int (*sbus_memcpy_toio)(struct sbus_priv *self, unsigned int addr,
					const void *src, int count);
	void (*lock)(struct sbus_priv *self);
	void (*unlock)(struct sbus_priv *self);
	int (*irq_subscribe)(struct sbus_priv *self, sbus_irq_handler handler,
				void *priv);
	int (*irq_unsubscribe)(struct sbus_priv *self);
	int (*reset)(struct sbus_priv *self);
	size_t (*align_size)(struct sbus_priv *self, size_t size);
	int (*set_block_size)(struct sbus_priv *self, size_t size);
	int (*pipe_send)(struct sbus_priv *self, u8 pipe, u32 len, u8 *buf);
	void * (*pipe_read)(struct sbus_priv *self);
	int (*sbus_reg_read)(struct sbus_priv *self, u32 reg,
					void *buf, int count);
	int (*sbus_reg_write)(struct sbus_priv *self, u32 reg,
					const void *buf, int count);

	/* sub_system: 0 for mcu, 1 for wifi, 2 for bt, ... */
	int (*sbus_active)(struct sbus_priv *self, int sub_system);
	int (*sbus_deactive)(struct sbus_priv *self, int sub_system);
	int (*power_switch)(struct sbus_priv *self, int on);
	/* gpio wake, beacuse bes2600 sdio can't wakeup mcu, so add the two of interfaces */
	void (*gpio_wake)(struct sbus_priv *self, int falg);
	void (*gpio_sleep)(struct sbus_priv *self, int falg);
};

#ifdef CONFIG_BES2600_WLAN_USB
/* tx/rx pipes for usb */
enum BES2600_USB_PIPE_ID {
	BES2600_USB_PIPE_TX_CTRL = 0,
	BES2600_USB_PIPE_TX_WLAN,
	BES2600_USB_PIPE_TX_BT,
	BES2600_USB_PIPE_RX_CTRL,
	BES2600_USB_PIPE_RX_WLAN,
	BES2600_USB_PIPE_RX_BT,
	BES2600_USB_PIPE_MAX
};

// virtual register definition
#define BES_USB_CONTROL_REG	0
#define BES_USB_STATUS_REG	1

// virtual register bits definition
#define BES_USB_FW_TX_DONE              BIT(0)
#define BES_USB_FW_RX_INDICATION        BIT(1)
#endif

void bes2600_irq_handler(struct bes2600_common *priv);

/* This MUST be wrapped with hwbus_ops->lock/unlock! */
int __bes2600_irq_enable(int enable);

#endif /* BES2600_SBUS_H */
