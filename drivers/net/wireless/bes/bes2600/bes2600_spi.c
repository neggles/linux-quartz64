/*
 * Mac80211 SPI driver for BES2600 device
 *
 * Based on bes2600_sdio.c
 * Copyright (c) 2010, Bestechnic
 * Author:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/gpio.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <net/mac80211.h>

#include <linux/spi/spi.h>
#include <linux/device.h>

#include "bes2600.h"
#include "sbus.h"
#include "wsm.h"
#include "bes2600_plat.h"
#include "hwio.h"

#include <linux/sunxi-gpio.h>
#include <linux/of_gpio.h>
#include "bes2600_driver_mode.h"
#include "bes_chardev.h"

#if defined(FW_DOWNLOAD_BY_UART)
extern int bes2600_load_firmware_uart(struct bes2600_common *hw_priv);
#endif

MODULE_AUTHOR("Solomon Peachy <speachy@sagrad.com>");
MODULE_DESCRIPTION("mac80211 BES2600 SPI driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("spi:bes2600_wlan_spi");

/* #define SPI_DEBUG */

struct sbus_priv {
	struct spi_device	*func;
	struct bes2600_common	*core;
	const struct bes2600_platform_data_spi *pdata;
	struct device *dev;
	spinlock_t		lock; /* Serialize all bus operations */
	wait_queue_head_t       wq;
	int claimed;
	struct spi_message m;
	struct spi_transfer t_cmd;
	struct spi_transfer t_data;
	u8 *tx_dummy_buf;
	u8 *rx_dummy_buf;
	u8 *rx_offline_packets;
	struct sk_buff_head rx_queue;
	int gpio_irq;
	u32 lmac_ptr_pool[BES_LMAC_BUF_NUMS];
	u32 lmac_ptr_top;
	u32 lmac_ptr;
	u32 lmac_addr_min;
	u32 lmac_addr_max;
	u32 packets_upload;
	bool spi_active;
	long unsigned int gpio_wakup_flags;
};

/* Notes on byte ordering:
   LE:  B0 B1 B2 B3
   BE:  B3 B2 B1 B0

   Hardware expects 32-bit data to be written as 16-bit BE words:

   B1 B0 B3 B2
*/

static int bes2600_spi_memcpy_fromio(struct sbus_priv *self,
				     unsigned int addr,
				     void *dst, int count)
{
	int ret;
	//u32 cfg_addr, cfg_val;
	u32 reg_addr, done_addr, done_val;
	struct spi_transfer *t_cmd;
	struct spi_transfer *t_data;
	struct spi_message *m;

	bes2600_dbg(BES2600_DBG_SPI, "%s, count=%d,addr=%x\n", __func__, count, addr);
	if (!dst || (count & 0x3) || ((addr != BES_TX_DATA_ADDR) && (addr != BES_CALI_DATA_ADDR) && (addr < BES_LMAC_BUF_DESC
					|| addr > BES_LMAC_BUF_DESC + BES_LMAC_BUF_NUMS * 4))) {
		bes2600_err(BES2600_DBG_SPI, "%s,%d %x:%p:%d", __func__, __LINE__, addr, dst, count);
		return -EINVAL;
	}

	BUG_ON(!self);
	BUG_ON(!self->tx_dummy_buf);
	BUG_ON(!self->rx_dummy_buf);
	t_cmd = &self->t_cmd;
	t_data = &self->t_data;
	m = &self->m;

	//cfg_addr = SPI_WR_ADDR(SPI_RD_CFG_REG_ID);
	//cfg_val = SPI_CONTINUOUS_CFG_VAL;
	reg_addr = SPI_RD_ADDR(addr);
	done_addr = SPI_WR_ADDR(BES_HOST_INT_REG_ID);
	done_val = BES_HOST_INT_RD_DONE;

#if defined(__LITTLE_ENDIAN)
	if (likely(self->func->bits_per_word == 8)) {
		//cfg_addr = swab32(cfg_addr);
		//cfg_val = swab32(cfg_val);
		reg_addr = swab32(reg_addr);
		done_addr = swab32(done_addr);
		done_val = swab32(done_val);
	}
#endif

	memset(m, 0, sizeof(*m));
	memset(t_cmd, 0, sizeof(*t_cmd));
	memset(t_data, 0, sizeof(*t_data));
	//memcpy(self->tx_dummy_buf, &cfg_addr, 4);
	//memcpy(self->tx_dummy_buf + 4, &cfg_val, 4);
	memcpy(self->tx_dummy_buf + 8, &reg_addr, 4);
	memcpy(self->tx_dummy_buf + 16 + count, &done_addr, 4);
	memcpy(self->tx_dummy_buf + 20 + count, &done_val, 4);
	//t_cmd->tx_buf = self->tx_dummy_buf;
	//t_cmd->rx_buf = self->rx_dummy_buf;
	//t_cmd->len = 4 + 4;
	//spi_message_init(m);
	//spi_message_add_tail(t_cmd, m);
	//ret = spi_sync(self->func, m);
	//if (ret) {
		//bes2600_err(BES2600_DBG_SPI, "%s,%d err=%d\n", __func__, __LINE__, ret);
		//goto exit;
	//}

	t_cmd->tx_buf = &self->tx_dummy_buf[8];
	t_cmd->rx_buf = self->rx_dummy_buf;
	t_cmd->len = 4 + 4;
	t_cmd->speed_hz = self->func->max_speed_hz;
	t_data->tx_buf = &self->tx_dummy_buf[16];
	t_data->rx_buf = dst;
	t_data->len = count;
	t_data->speed_hz = self->func->max_speed_hz;
	spi_message_init(m);
	spi_message_add_tail(t_cmd, m);
	spi_message_add_tail(t_data, m);

	ret = spi_sync(self->func, m);
	if (!ret) {
#if 0
		bes2600_dbg(BES2600_DBG_SPI, "READ LENGTH:%d,%d,%u\n", m->actual_length, count, ++packets_upload);
		bes2600_dbg_dump(BES2600_DBG_SPI, "read_data:", dst, 8);
		if (PACKET_COUNT(ctrl_reg) >= 2)
			bes2600_dbg_dump(BES2600_DBG_SPI, "read_data1:", self->rx_offline_packets[0], 8);
		if (PACKET_COUNT(ctrl_reg) >= 3)
			bes2600_dbg_dump(BES2600_DBG_SPI, "read_data2:", self->rx_offline_packets[1], 8);
#endif
	} else {
		bes2600_err(BES2600_DBG_SPI, "%s,%d err=%d\n", __func__, __LINE__, ret);
		goto exit;
	}

	if (addr != BES_TX_DATA_ADDR && addr != BES_CALI_DATA_ADDR) {
#if defined(__LITTLE_ENDIAN)
	if (likely(self->func->bits_per_word == 8)) {
		u32 *buf_u32 = (u32 *)dst;
		int i;
		for(i = 0; i < (count >> 2); i++) {
			buf_u32[i] = swab32(buf_u32[i]);
		}
	}
#endif
		return ret;
	}

	t_cmd->tx_buf = &self->tx_dummy_buf[count + 16];
	t_cmd->rx_buf = self->rx_dummy_buf;
	t_cmd->len = 4 + 4;
	t_cmd->speed_hz = self->func->max_speed_hz;
	spi_message_init(m);
	spi_message_add_tail(t_cmd, m);
	ret = spi_sync(self->func, m);
	if (ret) {
		bes2600_err(BES2600_DBG_SPI, "%s,%d err=%d\n", __func__, __LINE__, ret);
	}
	self->packets_upload ++;

	bes2600_dbg_dump(BES2600_DBG_SPI, "read_done:", &self->tx_dummy_buf[count + 16], 8);
exit:
	return ret;
}

static int bes2600_spi_addr_update(struct sbus_priv *self);

static int bes2600_spi_memcpy_toio(struct sbus_priv *self,
				   unsigned int addr,
				   const void *src, int count)
{
	int ret, i;
	u32 reg_addr, reg_use, src_pos = 0, buf_pos = 4;
	u32 done_addr, done_val;
	u8 *src_u8;
	u32 *src_u32, *buf_u32;
	struct spi_transfer *t_cmd;
	struct spi_transfer *t_data;
	struct spi_message *m;

	if (!src || count <= 0 || ((!addr) && (count >= 1632))) {
		bes2600_err(BES2600_DBG_SPI, "%s,%d err=%p:%d\n", __func__, __LINE__, src, count);
		return -EINVAL;
	}

	BUG_ON(!self);
	BUG_ON(!self->tx_dummy_buf);
	BUG_ON(!self->rx_dummy_buf);
	m = &self->m;
	t_cmd = &self->t_cmd;
	t_data = &self->t_data;

	if (likely(!addr)) {
		if (bes2600_chrdev_is_signal_mode()) {
			ret = bes2600_spi_addr_update(self);
			if (WARN_ON(ret)) {
				return ret;
			}
			reg_use = self->lmac_ptr_pool[self->lmac_ptr & (BES_LMAC_BUF_NUMS - 1)];
			if (WARN_ON(reg_use > self->lmac_addr_max || reg_use < self->lmac_addr_min)) {
				bes2600_err(BES2600_DBG_SPI, "%s, addr err:%x,%x,%x\n", __func__, reg_use, self->lmac_addr_max, self->lmac_addr_min);
				return -EIO;
			}
			self->lmac_ptr++;
		} else {
			reg_use = BES_MISC_DATA_ADDR;
		}
	} else {
		reg_use = addr;
	}

	reg_addr = SPI_WR_ADDR(reg_use);
	if (addr != BES_MISC_DATA_ADDR) {
		done_val = BES_HOST_INT_WR_DONE;
		done_addr = SPI_WR_ADDR(BES_HOST_INT_REG_ID);
	} else {
		done_val = BES_MISC_DATA_DONE;
		done_addr = SPI_WR_ADDR(BES_HOST_SUBINT_REG_ID);
	}

	/* We have to byteswap if the SPI bus is limited to 8b operation
	   or we are running on a Big Endian system
	*/
#if defined(__LITTLE_ENDIAN)
	bes2600_dbg(BES2600_DBG_SPI, "write_addr:%x(%u)\n", reg_use, self->lmac_ptr);
	bes2600_dbg_dump(BES2600_DBG_SPI, "wirte_data:", src, 8);
	if (likely(self->func->bits_per_word == 8))
	{
		reg_addr = swab32(reg_addr);
		done_addr = swab32(done_addr);
		done_val = swab32(done_val);
		buf_pos = 1;
		src_pos = 0;
		src_u32 = (u32 *)src;
		buf_u32 = (u32 *)self->tx_dummy_buf;
		for (i = 0; i < (count >> 2); i++) {
			buf_u32[buf_pos] = swab32(src_u32[src_pos]);
			buf_pos ++;
			src_pos ++;
		}

		buf_pos = buf_pos << 2;
		src_pos = src_pos << 2;

		if (count & 0x3) {

			src_u8 = (u8 *)src;
			if ((count % 4) == 1) {
				self->tx_dummy_buf[buf_pos ++] = 0;
				self->tx_dummy_buf[buf_pos ++] = 0;
				self->tx_dummy_buf[buf_pos ++] = 0;
				self->tx_dummy_buf[buf_pos ++] = src_u8[src_pos ++];
			} else if ((count % 4) == 2) {
				self->tx_dummy_buf[buf_pos ++] = 0;
				self->tx_dummy_buf[buf_pos ++] = 0;
				self->tx_dummy_buf[buf_pos ++] = src_u8[src_pos + 1];
				self->tx_dummy_buf[buf_pos ++] = src_u8[src_pos];
				src_pos += 2;
			} else {
				self->tx_dummy_buf[buf_pos ++] = 0;
				self->tx_dummy_buf[buf_pos ++] = src_u8[src_pos + 2];
				self->tx_dummy_buf[buf_pos ++] = src_u8[src_pos + 1];
				self->tx_dummy_buf[buf_pos ++] = src_u8[src_pos];
				src_pos += 3;
			}
		}
	}
	bes2600_dbg(BES2600_DBG_SPI, "transver %u,%u(%d)\n", buf_pos, src_pos, count);
#endif

	bes2600_dbg(BES2600_DBG_SPI, "WRITE %d:%x(%x)\n", count, reg_use, reg_addr);

	memset(t_cmd, 0, sizeof(*t_cmd));
	memcpy(self->tx_dummy_buf, &reg_addr, 4);
	memcpy(&self->tx_dummy_buf[buf_pos], &done_addr, 4);
	memcpy(&self->tx_dummy_buf[buf_pos + 4], &done_val, 4);
	t_cmd->tx_buf = self->tx_dummy_buf;
	t_cmd->rx_buf = self->rx_dummy_buf;
	t_cmd->len = buf_pos;
	t_cmd->speed_hz = self->func->max_speed_hz;

	bes2600_dbg_dump(BES2600_DBG_SPI, "WRITE:", (u8 *)t_cmd->tx_buf, t_cmd->len);

	spi_message_init(m);
	spi_message_add_tail(t_cmd, m);
	if (!src_pos) {
		memset(t_data, 0, sizeof(*t_data));
		t_data->tx_buf = src;
		t_data->rx_buf = self->rx_dummy_buf;
		t_data->len = count;
		t_data->speed_hz = self->func->max_speed_hz;
		spi_message_add_tail(t_data, m);
	}
	ret = spi_sync(self->func, m);
	if (ret) {
		bes2600_err(BES2600_DBG_SPI, "%s,%d err=%d\n", __func__, __LINE__, ret);
	}

	if ((!addr) || (addr == BES_MISC_DATA_ADDR)) {
		t_cmd->tx_buf = &self->tx_dummy_buf[buf_pos];
		t_cmd->rx_buf = self->rx_dummy_buf;
		t_cmd->len = 8;
		t_cmd->speed_hz = self->func->max_speed_hz;
		spi_message_init(m);
		spi_message_add_tail(t_cmd, m);
		ret = spi_sync(self->func, m);
		if (ret)
			bes2600_err(BES2600_DBG_SPI, "%s,%d err=%d.\n", __func__, __LINE__, ret);
	}

	if (addr == BES_MISC_DATA_ADDR) {
		done_val = BES_HOST_INT_SUBINT;
		done_addr = SPI_WR_ADDR(BES_HOST_INT_REG_ID);
		done_val = swab32(done_val);
		done_addr = swab32(done_addr);
		memcpy(&self->tx_dummy_buf[buf_pos], &done_addr, 4);
		memcpy(&self->tx_dummy_buf[buf_pos + 4], &done_val, 4);
		t_cmd->tx_buf = &self->tx_dummy_buf[buf_pos];
		t_cmd->rx_buf = self->rx_dummy_buf;
		t_cmd->len = 8;
		t_cmd->speed_hz = self->func->max_speed_hz;
		spi_message_init(m);
		spi_message_add_tail(t_cmd, m);
		ret = spi_sync(self->func, m);
		if (ret)
			bes2600_err(BES2600_DBG_SPI, "%s,%d err=%d.\n", __func__, __LINE__, ret);
	}

	//print_hex_dump(KERN_NOTICE, "write_done  ", 0, 16, 1, &self->tx_dummy_buf[buf_pos], 8, false);
	//temp_test(self);

	return ret;
}

static void bes2600_spi_lock(struct sbus_priv *self)
{
	unsigned long flags;

	DECLARE_WAITQUEUE(wait, current);

	might_sleep();

	add_wait_queue(&self->wq, &wait);
	spin_lock_irqsave(&self->lock, flags);
	while (1) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (!self->claimed)
			break;
		spin_unlock_irqrestore(&self->lock, flags);
		schedule();
		spin_lock_irqsave(&self->lock, flags);
	}
	set_current_state(TASK_RUNNING);
	self->claimed = 1;
	spin_unlock_irqrestore(&self->lock, flags);
	remove_wait_queue(&self->wq, &wait);

	return;
}

static void bes2600_spi_unlock(struct sbus_priv *self)
{
	unsigned long flags;

	spin_lock_irqsave(&self->lock, flags);
	self->claimed = 0;
	spin_unlock_irqrestore(&self->lock, flags);
	wake_up(&self->wq);

	return;
}

static irqreturn_t bes2600_spi_irq_handler(int irq, void *dev_id)
{
	struct sbus_priv *self = dev_id;

	if (self->core) {
		//bes2600_spi_lock(self);
		bes2600_irq_handler(self->core);
		//bes2600_spi_unlock(self);
		return IRQ_HANDLED;
	} else {
		return IRQ_NONE;
	}
}

struct bes2600_platform_data_spi *bes2600_get_platform_data(void);
static int bes2600_spi_irq_subscribe(struct sbus_priv *self, sbus_irq_handler handler,
				void *priv)
{
	int ret, irq;

	bes2600_info(BES2600_DBG_SPI, "SW IRQ subscribe\n");

	if (self->pdata && gpio_is_valid(self->pdata->irq_gpio)) {
		self->gpio_irq = gpio_to_irq(self->pdata->irq_gpio);
		bes2600_info(BES2600_DBG_SPI, "gpio for irq detected:%d,%d\n", self->pdata->irq_gpio, self->gpio_irq);
		irq = self->gpio_irq;
	} else {
		irq = self->func->irq;
	}

	ret = request_threaded_irq(irq, NULL,
				bes2600_spi_irq_handler,
				IRQF_TRIGGER_HIGH | IRQF_ONESHOT,
				"bes2600_wlan_irq", self);

	if (WARN_ON(ret < 0))
		goto exit;

	ret = enable_irq_wake(irq);
	if (WARN_ON(ret))
		goto free_irq;

	return 0;

free_irq:
	free_irq(irq, self);

exit:
	return ret;
}

static int bes2600_spi_irq_unsubscribe(struct sbus_priv *self)
{
	int ret = 0, irq;

	bes2600_info(BES2600_DBG_SPI, "SW IRQ unsubscribe\n");

	if (!IS_ERR_VALUE((uintptr_t)self->gpio_irq))
		irq = self->gpio_irq;
	else
		irq = self->func->irq;

	disable_irq_wake(irq);
	free_irq(irq, self);

	return ret;
}

static int bes2600_spi_off(const struct bes2600_platform_data_spi *pdata)
{
	bes2600_info(BES2600_DBG_SPI, "%s enter\n", __func__);

	if (pdata == NULL)
		return 0;

#if defined(BES2600_INDEPENDENT_EVB) || defined(BES2600_INTEGRATED_MODULE_V3)
	if (gpio_is_valid(pdata->powerup)) {
		bes2600_info(BES2600_DBG_SPI, "bes2600 powerdown.\n");
		gpio_direction_output(pdata->powerup, 0);
	}
#endif

	return 0;
}

static int bes2600_spi_on(const struct bes2600_platform_data_spi *pdata)
{
	bes2600_info(BES2600_DBG_SPI, "%s enter\n", __func__);

	if (pdata == NULL)
		return 0;

#if defined(BES2600_INDEPENDENT_EVB) || defined(BES2600_INTEGRATED_MODULE_V3)
	if (gpio_is_valid(pdata->powerup)) {
		bes2600_info(BES2600_DBG_SPI, "bes2600 powerup.\n");
		gpio_direction_output(pdata->powerup, 1);
	}
#endif

	return 0;
}

static size_t bes2600_spi_align_size(struct sbus_priv *self, size_t size)
{
#if 0
	return ((size + 3) & (~0x3));
#else
	return size;
#endif
}

int bes2600_spi_set_block_size(struct sbus_priv *self, size_t size)
{
	return 0;
}

int bes2600_spi_send(struct bes2600_common *ar, u8 pipe, u32 len, u8 *buf)
{
	return 0;
}

void * bes2600_spi_read(struct bes2600_common *ar)
{
	return 0;
}

static int bes2600_spi_reg_write(struct sbus_priv *self, u32 reg,
					const void *src, int count);
static int bes2600_spi_init(struct sbus_priv *self, struct bes2600_common *ar)
{
	int ret = 0;
	//u32 cfg_val;

	if (self->tx_dummy_buf) {
		bes2600_err(BES2600_DBG_SPI, "bes2600 sbus has been initialized ???\n");
		return -1;
	}

	/* 4byte for read cfg_addr
	 * 4byte for read cfg_val
	 * 4byte for read addr
	 * 4byte for status followed read addr
	 * 1632byte for data
	 * 4byte for done addr
	 * 4byte for done val
	 */
#if 0
	self->tx_dummy_buf = kmalloc(1632 + 24, GFP_KERNEL);
	if (!self->tx_dummy_buf)
		return -ENOMEM;

	self->rx_dummy_buf = kmalloc(1632 + 24, GFP_KERNEL);
	if (!self->rx_dummy_buf) {
		ret = -ENOMEM;
		goto free_tx;
	}
#else
	self->tx_dummy_buf = (u8 *)__get_dma_pages(GFP_KERNEL, get_order((1632 + 24) * MAX_SEND_PACKETS_NUM));
	if (!self->tx_dummy_buf)
		return -ENOMEM;
	self->rx_dummy_buf = (u8 *)__get_dma_pages(GFP_KERNEL, get_order((1632 + 24) * MAX_SEND_PACKETS_NUM));
	if (!self->rx_dummy_buf)
		goto free_tx;
	bes2600_info(BES2600_DBG_SPI, "%s, buf_addr:%p:%p(%d)\n", __func__,
			self->tx_dummy_buf, self->rx_dummy_buf, get_order((1632 + 24) * MAX_SEND_PACKETS_NUM));
#endif
	self->core = ar;

	self->lmac_ptr_top = 0;
	self->lmac_ptr = 0;
	self->lmac_addr_min = 0;
	self->lmac_addr_max = 0;
	self->packets_upload = 0;

	skb_queue_head_init(&self->rx_queue);

#if 0
	cfg_val = SPI_CONTINUOUS_CFG_VAL;
	if ((ret = bes2600_spi_reg_write(self, SPI_RD_CFG_REG_ID, &cfg_val, 4))) {
		bes2600_err(BES2600_DBG_SPI, "%s,%d err=%d\n", __func__, __LINE__, ret);
		goto free_rx;
	}
#endif

	return 0;

#if 0
free_rx:
	free_pages((unsigned long)self->rx_dummy_buf, get_order((1632 + 24) * MAX_SEND_PACKETS_NUM));
#endif

free_tx:
	free_pages((unsigned long)self->tx_dummy_buf, get_order((1632 + 24) * MAX_SEND_PACKETS_NUM));

	return ret;
}

/* bes spi slave regs can only be accessed as DWORD(32-bit)
 * if BYTE or WORD(16-bit) reg wants to be accessed,
 * please extract form a DWORD read or write operation and this is not implemented yet
 */
static int bes2600_spi_reg_read(struct sbus_priv *self, u32 reg,
					void *dst, int count)
{
	int ret = 0;
	u32 reg_addr, cfg_val;
	//u32 cfg_addr;
	struct spi_message *m;
	struct spi_transfer *t_cmd;

	if (!dst || count != 4) {
		bes2600_err(BES2600_DBG_SPI, "%s,%d %p:%d\n", __func__, __LINE__, dst, count);
		return -EINVAL;
	}
	BUG_ON(!self);
	BUG_ON(!self->tx_dummy_buf);
	BUG_ON(!self->rx_dummy_buf);

	m = &self->m;
	t_cmd = &self->t_cmd;

	//cfg_addr = SPI_WR_ADDR(SPI_RD_CFG_REG_ID);
	//cfg_val = SPI_NCONTINUOUS_CFG_VAL;
	reg_addr = SPI_RD_ADDR(reg);
	//bes2600_info(BES2600_DBG_SPI, "TX %x:%x:%x(%x)\n", cfg_addr, cfg_val, reg_addr, reg);

#if defined(__LITTLE_ENDIAN)
	if (likely(self->func->bits_per_word == 8)) {
		//cfg_addr = swab32(cfg_addr);
		//cfg_val = swab32(cfg_val);
		reg_addr = swab32(reg_addr);
	}
#endif

	memset(t_cmd, 0, sizeof(*t_cmd));
	//memcpy(self->tx_dummy_buf, &cfg_addr, 4);
	//memcpy(self->tx_dummy_buf + 4, &cfg_val, 4);
	memcpy(self->tx_dummy_buf + 8, &reg_addr, 4);
	//t_cmd->tx_buf = &self->tx_dummy_buf;
	//t_cmd->rx_buf = self->rx_dummy_buf;
	//t_cmd->len = 4 + 4;
	//spi_message_init(m);
	//spi_message_add_tail(t_cmd, m);
	//ret = spi_sync(self->func, m);
	//if (ret) {
		//bes2600_err(BES2600_DBG_SPI, "%s,%d err=%d\n", __func__, __LINE__, ret);
		//goto exit;
	//}

	t_cmd->tx_buf = &self->tx_dummy_buf[8];
	t_cmd->rx_buf = self->rx_dummy_buf;
	t_cmd->len = 4 + 4 + 4;
	t_cmd->speed_hz = self->func->max_speed_hz;

	spi_message_init(m);
	spi_message_add_tail(t_cmd, m);
	ret = spi_sync(self->func, m);
	if (!ret){

		bes2600_dbg_dump(BES2600_DBG_SPI, "READ:", (u8 *)t_cmd->rx_buf, t_cmd->len);
		cfg_val = *(u32 *)(t_cmd->rx_buf + 8);
		cfg_val = swab32(cfg_val);
		memcpy(dst, &cfg_val, 4);
		//bes2600_info(BES2600_DBG_SPI, "reg_read val:%x\n", cfg_val);
	}

//exit:
	return ret;
}

static int bes2600_spi_reg_write(struct sbus_priv *self, u32 reg,
					const void *src, int count)
{
	int ret = 0;
	u32 reg_addr, wr_val;
	struct spi_message *m;
	struct spi_transfer *t_cmd;

	if (!src || count != 4) {
		bes2600_err(BES2600_DBG_SPI, "%s,%d %p:%d\n", __func__, __LINE__, src, count);
		return -EINVAL;
	}
	BUG_ON(!self);
	BUG_ON(!self->tx_dummy_buf);
	BUG_ON(!self->rx_dummy_buf);
	m = &self->m;
	t_cmd = &self->t_cmd;

	reg_addr = SPI_WR_ADDR(reg);
	memcpy(&wr_val, src, 4);
	//bes2600_info(BES2600_DBG_SPI, "TX_CMD %08x(%08x):%08x\n", reg_addr, reg, wr_val);

#if defined(__LITTLE_ENDIAN)
	if (likely(self->func->bits_per_word == 8)) {
		reg_addr = swab32(reg_addr);
		wr_val = swab32(wr_val);
		//bes2600_info(BES2600_DBG_SPI, "TRANSVERT_TX_CMD %08x:%08x\n", reg_addr, wr_val);
	}
#endif

	memset(m, 0, sizeof(*m));
	memset(t_cmd, 0, sizeof(*t_cmd));
	memcpy(self->tx_dummy_buf, &reg_addr, 4);
	memcpy(self->tx_dummy_buf + 4, &wr_val, 4);

	t_cmd->tx_buf = self->tx_dummy_buf;
	t_cmd->rx_buf = self->rx_dummy_buf;
	t_cmd->len = 4 + 4;
	t_cmd->speed_hz = self->func->max_speed_hz;

	bes2600_dbg_dump(BES2600_DBG_SPI, "WRITE:", (u8 *)t_cmd->tx_buf,t_cmd->len);

	spi_message_init(m);
	spi_message_add_tail(t_cmd, m);
	ret = spi_sync(self->func, m);
	if (!ret){
		//bes2600_info(BES2600_DBG_SPI, "reg_write:%x", *(u32 *)src);
	} else {
		bes2600_err(BES2600_DBG_SPI, "%s,%d err=%d", __func__, __LINE__, ret);
	}
	return ret;
}

static int bes2600_spi_addr_update(struct sbus_priv *self)
{
	int ret;
	u32 pos;
	u32 diff = (u32)(self->lmac_ptr_top - self->lmac_ptr);

	if (diff > 0 && diff < BES_LMAC_BUF_NUMS)
		return 0;

	if ((ret = bes2600_spi_reg_read(self, BES_LMAC_BUF_TOTAL, &self->lmac_ptr_top, 4))) {
		return ret;
	}

	diff = (u32)(self->lmac_ptr_top - self->lmac_ptr);
	BUG_ON(diff > BES_LMAC_BUF_NUMS);

	pos = self->lmac_ptr & (BES_LMAC_BUF_NUMS - 1);
	//bes2600_info(BES2600_DBG_SPI, "%s, %u %u %u\n", __func__, diff, pos, self->lmac_ptr_top);
	if (BES_LMAC_BUF_NUMS - pos >= diff)
		ret = bes2600_spi_memcpy_fromio(self, BES_LMAC_BUF_DESC + pos * 4, &self->lmac_ptr_pool[pos], diff << 2);
	else {
		ret = bes2600_spi_memcpy_fromio(self, BES_LMAC_BUF_DESC, self->lmac_ptr_pool, BES_LMAC_BUF_NUMS << 2);
	}

	if (unlikely(!self->lmac_addr_min)) {
		self->lmac_addr_min = self->lmac_ptr_pool[0];
		/* temporary workaround */
		self->lmac_addr_max = self->lmac_ptr_pool[self->lmac_ptr_top - 1] + 1632 + 1632;
	}

	return ret;
}

static int bes2600_spi_packets_check(u32 ctrl_reg, u8 *packets)
{
	int i;
	u32 single, total_cal = 0;
	u32 packets_length;
	u32 *buf_u32;

	/* bit 31-28 indicate count of packets */
	u32 packets_cnt = PACKET_COUNT_V2(ctrl_reg);
	if (WARN_ON(packets_cnt > MAX_SEND_PACKETS_NUM))
		return -200;

	/* bit 27-0 indicate totoal length of packets */
	packets_length = PACKET_TOTAL_LEN_V2(ctrl_reg);

	/* first 32-bit: addr in mcu;
	 * second 32-bit: packet length;
	 * next: data
	 */
	for (i = 0; i < packets_cnt; i++) {
		buf_u32 = (u32 *)(packets + total_cal);
		//bes2600_info(BES2600_DBG_SPI, "%s, %x,%x,%x\n", __func__, buf_u32[0], buf_u32[1], ctrl_reg);
		single = buf_u32[1];
		if (WARN_ON(single > 1632)) {
			return -201;
		}
		total_cal += single;
		total_cal += 8;
	}
	//bes2600_info(BES2600_DBG_SPI, "%s, %d,%u,%u\n", __func__, packets_cnt, packets_length, total_cal);

	if (WARN_ON(packets_length != total_cal)) {
		return -202;
	}

	return 0;
}

static int bes2600_spi_extract_packets(struct sbus_priv *self, u32 ctrl_reg, u8 *data)
{
	int i;
	u32 packets_cnt = PACKET_COUNT_V2(ctrl_reg);
	u32 packet_len, pos = 0;
	struct sk_buff *skb;
	for (i = 0; i < packets_cnt; i++) {
		packet_len = *(u32 *)&(data[pos + 4]);
		skb = dev_alloc_skb(packet_len);
		if (WARN_ON(!skb)) {
			return -ENOMEM;
		}
		skb_trim(skb, 0);
		skb_put(skb, packet_len);
		memcpy(skb->data, &data[pos + 8], packet_len);
		//bes2600_info(BES2600_DBG_SPI, "%s, %d,%d\n", __func__, packet_len, skb->len);
		skb_queue_tail(&self->rx_queue, skb);
		pos += packet_len;
		pos += 8;
	}
	return 0;
}

static void *bes2600_spi_pipe_read(struct sbus_priv *self)
{
	int ret;
	u32 ctrl_reg;
	int total_len;
	u8 *buf = &self->rx_dummy_buf[8];
	struct sk_buff *skb;

	skb = skb_dequeue(&self->rx_queue);
	if (skb != NULL)
		return skb;

	bes2600_spi_lock(self);

	if (unlikely(self->spi_active == false)) {
		goto null_exit;
	}

	ret = bes2600_spi_reg_read(self, BES_TX_CTRL_REG_ID, &ctrl_reg, 4);
	if (WARN_ON(ret))
		goto null_exit;

	if (!ctrl_reg)
		goto null_exit;

	total_len = PACKET_TOTAL_LEN_V2(ctrl_reg);
	ret = bes2600_spi_memcpy_fromio(self, BES_TX_DATA_ADDR, buf, total_len);
	if (WARN_ON(ret))
		goto null_exit;

	if ((ret = bes2600_spi_packets_check(ctrl_reg, buf)))
		goto null_exit;

	if ((ret = bes2600_spi_extract_packets(self, ctrl_reg, buf)))
		goto null_exit;

	bes2600_spi_unlock(self);

	return skb_dequeue(&self->rx_queue);

null_exit:
	bes2600_spi_unlock(self);
	return NULL;
}

void bes2600_sbus_dump(void *priv)
{
	struct sbus_priv *sbus_priv = (struct sbus_priv *)priv;
	bes2600_info(BES2600_DBG_SPI, "%s, upload=%u\n", __func__, sbus_priv->packets_upload);
}

#if defined(CONFIG_BES2600_SPI_THROUGHPUT_TEST)
#include <linux/proc_fs.h>
static struct proc_dir_entry *bes_wlan_dir;
#endif

#ifdef CONFIG_BES2600_SPI_THROUGHPUT_TEST
static struct proc_dir_entry *spi_throughput_entry;
static struct spi_throughput_struct {
	struct task_struct *thread;
	wait_queue_head_t test_wq;
	unsigned long test_count, test_packet_size;
	unsigned long read_packets, irq_enters;
	unsigned long average_time, max_time, min_time;
	unsigned long total_time;
	atomic_t rx;
	void *bus_data;
	char read_buf[512];
} *spi_throughput_data;
static int spi_throughput_test(void *arg);
static const struct sbus_ops bes2600_spi_sbus_ops;

static int spi_throughput_open(struct inode *inode, struct file *filp)
{
	bes2600_info(BES2600_DBG_SPI, "%s\n", __func__);
	return 0;
}

static int spi_throughput_close(struct inode *inode, struct file *filp)
{
	bes2600_info(BES2600_DBG_SPI, "%s\n", __func__);
	return 0;
}

static ssize_t spi_throughput_read(struct file *filp, char __user *buf,
				size_t size, loff_t *ppos)
{
	bes2600_info(BES2600_DBG_SPI, "%s, %ld\n", __func__, size);
	return 0;
}

static ssize_t spi_throughput_write(struct file *filp, const char __user *buf,
				size_t count, loff_t *ppos)
{
	char data[512];
	char cnt_delimiter[] = "count=";
	char size_delimiter[] = "size=";
	char *cnt_p, *size_p;
	unsigned long len;
	char *end;
	memset(data, 0, 512);
	len = copy_from_user(data, buf, count < 511 ? count : 511);
	bes2600_info(BES2600_DBG_SPI, "%s, %s\n", __func__, data);
	if (strncmp(data, "start", 5) == 0) {
		cnt_p = strstr(data, cnt_delimiter);
		size_p = strstr(data, size_delimiter);
		if (!cnt_p || !size_p)
			goto exit;
		bes2600_info(BES2600_DBG_SPI, "%s\n", cnt_p);
		bes2600_info(BES2600_DBG_SPI, "%s\n", size_p);
		if (cnt_p > (data + 511) || size_p > (data + 511))
			goto exit;
		spi_throughput_data->test_count = simple_strtoul(cnt_p + strlen(cnt_delimiter), &end, 10);
		spi_throughput_data->test_packet_size = simple_strtoul(size_p + strlen(size_delimiter), &end, 10);
		if(spi_throughput_data->test_packet_size > PAGE_SIZE) {
			bes2600_info(BES2600_DBG_SPI, "%s, correct test_size %ld-->%ld\n", __func__, spi_throughput_data->test_packet_size,
					PAGE_SIZE);
			spi_throughput_data->test_packet_size = PAGE_SIZE;
		}
		spi_throughput_data->thread = kthread_run(spi_throughput_test, spi_throughput_data, "spi_throughput");
	}

	if (strncmp(data, "stop", 4) == 0) {
		if (spi_throughput_data->thread)
			kthread_stop(spi_throughput_data->thread);
	}

exit:
	return count;
}

static const struct file_operations spi_throughput_ops = {
	.owner = THIS_MODULE,
	.read = spi_throughput_read,
	.write = spi_throughput_write,
	.open = spi_throughput_open,
	.release = spi_throughput_close,
};

static int create_spi_throughput_entry(struct sbus_priv *self)
{
	if (!bes_wlan_dir) {
		bes_wlan_dir = proc_mkdir_data("bes_wlan", 0666, NULL, NULL);
		if (!bes_wlan_dir)
			return -ENOMEM;
	}

	spi_throughput_data = kzalloc(sizeof(struct spi_throughput_struct), GFP_KERNEL);
	if (!spi_throughput_data)
		return -ENOMEM;

	spi_throughput_entry = proc_create_data("spi_throughput", 0666, bes_wlan_dir, &spi_throughput_ops, NULL);
	if (!spi_throughput_entry)
		return -ENOMEM;

	spi_throughput_data->bus_data = self;

	return 0;
}

static int destory_spi_throughput_entry(void)
{
	if (spi_throughput_entry) {
		if (spi_throughput_data)
			kfree(spi_throughput_data);
		proc_remove(spi_throughput_entry);
	}
	if (bes_wlan_dir) {
		proc_remove(bes_wlan_dir);
	}
	return 0;
}

static irqreturn_t bes2600_spi_irq_handler_test(int irq, void *dev_id)
{
	struct spi_throughput_struct *test = dev_id;

	test->irq_enters ++;
	if (atomic_inc_return(&test->rx) == 1) {
		wake_up(&test->test_wq);
	}
	return IRQ_HANDLED;
}

static int bes2600_spi_irq_subscribe_test(struct sbus_priv *self, void *priv)
{
	int ret, irq;

	bes2600_info(BES2600_DBG_SPI, "%s\n", __func__);

	if (!IS_ERR_VALUE((uintptr_t)self->gpio_irq))
		irq = self->gpio_irq;
	else
		irq = self->func->irq;

	ret = request_threaded_irq(irq, NULL,
				bes2600_spi_irq_handler_test,
				IRQF_TRIGGER_HIGH | IRQF_ONESHOT,
				"bes2600_wlan_irq", priv);

	if (WARN_ON(ret < 0))
		goto exit;

	ret = enable_irq_wake(irq);
	if (WARN_ON(ret))
		goto free_irq;

	return 0;

free_irq:
	free_irq(irq, self);

exit:
	return ret;
}

static int bes2600_spi_irq_unsubscribe_test(struct sbus_priv *self, void *priv)
{
	int ret = 0, irq;

	bes2600_info(BES2600_DBG_SPI, "%s\n", __func__);

	if (!IS_ERR_VALUE((uintptr_t)self->gpio_irq))
		irq = self->gpio_irq;
	else
		irq = self->func->irq;

	free_irq(irq, priv);

	return ret;
}

static int spi_throughput_test(void *arg)
{
	u8 *test_data;
	int ret, rx;
	long status;
	u32 next_len;
	u32 val;
	struct timeval time_before, time_after;
	unsigned long jiffies_start = jiffies;
	unsigned long interval;
	struct spi_throughput_struct *test = spi_throughput_data;
		struct sbus_priv *sbus_priv = test->bus_data;
	bes2600_info(BES2600_DBG_SPI, "%s packets=%ld, packet_size=%ld\n", __func__, test->test_count, test->test_packet_size);

	test_data = (u8 *)__get_free_page(GFP_KERNEL);
	if (!test_data) {
		bes2600_err(BES2600_DBG_SPI, "%s alloc page failed\n", __func__);
		goto exit;
	}

	init_waitqueue_head(&test->test_wq);
	bes2600_spi_sbus_ops.init(sbus_priv, NULL);
	test->irq_enters = 0;
	atomic_set(&test->rx, 0);
	test->max_time = 0;
	test->min_time = 100 * 1000000;
	test->average_time = 0;
	test->total_time = 0;

	allow_signal(SIGKILL | SIGINT | SIGTERM);

	bes2600_spi_irq_subscribe_test(sbus_priv, test);

	bes2600_spi_sbus_ops.lock(sbus_priv);
	val = test->test_count;
	bes2600_spi_sbus_ops.sbus_reg_write(sbus_priv, BES_LMAC_BUF_USE, &val, 4);
	val = BES_HOST_SLAVE_SYNC;
	bes2600_spi_sbus_ops.sbus_reg_write(sbus_priv, BES_HOST_SYNC_REG_ID, &val, 4);
	bes2600_spi_sbus_ops.unlock(sbus_priv);

	do {
		do_gettimeofday(&time_before);
		status = wait_event_interruptible_timeout(test->test_wq,
			({rx = atomic_xchg(&test->rx,  0); (rx);}), MAX_SCHEDULE_TIMEOUT);

		if (status < 0 && status != -ERESTARTSYS) {
			bes2600_err(BES2600_DBG_SPI, "%s,%d err=%ld\n", __func__, __LINE__, status);
			break;
		}

		bes2600_spi_sbus_ops.lock(sbus_priv);
		ret = bes2600_spi_sbus_ops.sbus_reg_read(sbus_priv, BES_TX_CTRL_REG_ID, &next_len, 4);
		bes2600_spi_sbus_ops.unlock(sbus_priv);
		if (ret) {
			bes2600_err(BES2600_DBG_SPI, "%s,%d err=%d\n", __func__, __LINE__, ret);
			break;
		}

rx_again:
		if (next_len) {
			bes2600_spi_sbus_ops.lock(sbus_priv);
			ret = bes2600_spi_sbus_ops.sbus_memcpy_fromio(sbus_priv,
					BES_TX_DATA_ADDR, test_data, next_len);
			bes2600_spi_sbus_ops.unlock(sbus_priv);
			if (ret)
				break;
			do_gettimeofday(&time_after);
			interval = (time_after.tv_sec * 1000000 + time_after.tv_usec) -
					(time_before.tv_sec * 1000000 + time_before.tv_usec);
			if (test->max_time < interval)
				test->max_time = interval;
			if (test->min_time > interval)
				test->min_time = interval;
			if (test->average_time) {
				test->average_time += interval;
				test->average_time /= 2;
			} else {
				test->average_time = interval;
			}
			test->read_packets ++;
			if (test->read_packets >= test->test_count) {
				test->total_time = jiffies - jiffies_start;
				bes2600_info(BES2600_DBG_SPI, "%s packets/irq=%ld %ld\n", __func__, test->read_packets, test->irq_enters);
				break;
			}
		}

		if (next_len & 0xffff) {
			next_len &= 0xffff0000;
			goto rx_again;
		}

	} while (!kthread_should_stop());
	free_page((unsigned long)test_data);
	bes2600_spi_irq_unsubscribe_test(sbus_priv, test);
exit:
	test->thread = NULL;
	bes2600_info(BES2600_DBG_SPI, "%s exit ...\n", __func__);
	bes2600_info(BES2600_DBG_SPI, "test results:%ld %ld %ld %ld\n", test->total_time, test->average_time,
			test->max_time, test->min_time);
	return 0;
}

#endif

#if defined(PLAT_ALLWINNER) || defined(PLAT_QCOM_QM215)
static struct bes2600_platform_data_spi bes_spi_plat_data = {
	.spi_bits_per_word = 8,
};
#endif

struct bes2600_platform_data_spi *bes2600_get_platform_data(void)
{
#if defined(PLAT_ALLWINNER) || defined(PLAT_QCOM_QM215)
	return &bes_spi_plat_data;
#else
	return NULL;
#endif
}

static int bes2600_platform_data_init(struct device *dev)
{
	int ret = 0;
	struct device_node *np = dev->of_node;
	struct gpio_config config;
	struct bes2600_platform_data_spi *pdata = bes2600_get_platform_data();

	if (!pdata)
		return -ENODEV;

	pdata->spi_bits_per_word = 8;
	pdata->priv = to_spi_device(dev);

	pdata->reset = of_get_named_gpio_flags(np, "reset",
			0, (enum of_gpio_flags *)&config);
		/* Ensure I/Os are pulled low */
	if (gpio_is_valid(pdata->reset)) {
		ret = gpio_request(pdata->reset, "bes2600_wlan_reset");
		if (ret) {
			bes2600_err(BES2600_DBG_SPI, "can't request reset_gpio:%d\n", ret);
			pdata->reset = -1;
			goto exit;
		} else {
			gpio_direction_output(pdata->reset, 0);
		}
	} else {
		bes2600_err(BES2600_DBG_SPI, "reset is invalid\n");
	}

	pdata->powerup = of_get_named_gpio_flags(np, "powerup",
			0, (enum of_gpio_flags *)&config);
	if (gpio_is_valid(pdata->powerup)) {
		ret = gpio_request(pdata->powerup, "bes2600_wlan_powerup");
		if (ret) {
			bes2600_err(BES2600_DBG_SPI, "can't request powerup_gpio:%d\n", ret);
			pdata->powerup = -1;
			goto exit;
		} else {
			gpio_direction_output(pdata->powerup, 0);
		}
	} else {
		bes2600_err(BES2600_DBG_SPI, "powerup is invalid\n");
	}

	pdata->irq_gpio = of_get_named_gpio_flags(np, "irq_gpio", 0, (enum of_gpio_flags *)&config);
	if (gpio_is_valid(pdata->irq_gpio)) {
		ret = gpio_request(pdata->irq_gpio, "bes2600_wlan_irq_gpio");
		if (ret) {
			bes2600_err(BES2600_DBG_SPI, "can't request irq gpio:%d\n", ret);
			goto exit;
		} else {
			ret = gpio_direction_input(pdata->irq_gpio);
			if (ret < 0) {
				bes2600_err(BES2600_DBG_SPI, "can't config irq_gpio input\n");
				pdata->irq_gpio = -1;
				goto exit;
			}
		}
	} else {
		bes2600_err(BES2600_DBG_SPI, "irq gpio is invalid\n");
	}

	pdata->host_wakeup_wlan = of_get_named_gpio_flags(np, "host_wakeup_wlan", 0, (enum of_gpio_flags *)&config);
	if (gpio_is_valid(pdata->host_wakeup_wlan)) {
		ret = gpio_request(pdata->host_wakeup_wlan, "bes2600_host_wakeup_wlan");
		if (ret) {
			bes2600_err(BES2600_DBG_SPI, "can't request host_wakeup_wlan gpio:%d\n", ret);
			goto exit;
		} else {
			gpio_direction_output(pdata->host_wakeup_wlan, 0);
		}
	} else {
		bes2600_err(BES2600_DBG_SPI, "irq gpio is invalid\n");
	}

exit:
	return ret;
}

static void bes2600_platform_data_deinit(void)
{
	const struct bes2600_platform_data_spi *pdata = bes2600_get_platform_data();

	if (pdata == NULL) {
		return;
	}

	if (gpio_is_valid(pdata->reset)) {
		gpio_free(pdata->reset);
	}

	if (gpio_is_valid(pdata->powerup)) {
		gpio_free(pdata->powerup);
	}

	if (gpio_is_valid(pdata->irq_gpio)) {
		gpio_free(pdata->irq_gpio);
	}

	if (gpio_is_valid(pdata->host_wakeup_wlan)) {
		gpio_free(pdata->host_wakeup_wlan);
	}

}

static int bes2600_spi_reset(struct sbus_priv *self)
{
	struct bes2600_platform_data_spi *plat_data = bes2600_get_platform_data();

	bes2600_info(BES2600_DBG_SPI, "%s ...\n", __func__);

	if (plat_data == NULL)
		return 0;

	if (gpio_is_valid(plat_data->reset)) {
		gpio_set_value(plat_data->reset, 1);
		mdelay(50);
		gpio_set_value(plat_data->reset, 0);
	}
	return 0;
}

static int bes2600_spi_awake(struct sbus_priv *self)
{
	int retries = 0;
	u32 sync_header;

	bes2600_spi_lock(self);

#if 0
	if (gpio_is_valid(pdata->host_wakeup_wlan)) {
		bes2600_dbg(BES2600_DBG_SPI, "toggle wake up line\n");
		gpio_set_value(pdata->host_wakeup_wlan, 1);
		msleep(20);
		gpio_set_value(pdata->host_wakeup_wlan, 0);
	} else {
		bes2600_err(BES2600_DBG_SPI, "toggle wake up line failed\n");
	}
#endif

	do {
		bes2600_spi_reg_read(self, BES_HOST_SYNC_REG_ID, &sync_header, 4);
		if (sync_header == BES_SLAVE_SYNC_HEADER) {
			self->spi_active = true;
			break;
		} else {
			msleep(10);
		}
		++retries;
	} while (retries < 5);
	bes2600_spi_unlock(self);

	if (retries >= 5) {
		bes2600_err(BES2600_DBG_SPI, "%s spi sync failed(%x)\n", __func__, sync_header);
		return -1;
	}

	return 0;
}

static void bes2600_gpio_wakeup_mcu(struct sbus_priv *self, int falg)
{
	unsigned long flags;
	bool gpio_wakeup = false;
	const struct bes2600_platform_data_spi *pdata = bes2600_get_platform_data();
	if (pdata == NULL)
		return;

	bes2600_info(BES2600_DBG_SPI, "%s with %d\n", __func__, falg);

	/* error check */
	if(test_bit(falg, &self->gpio_wakup_flags)) {
		bes2600_err(BES2600_DBG_SPI,
			"repeat set gpio_wake_flag, sub_sys:%d", falg);
		return;
	}

	/* check if this is the first subsystem that need mcu to keep awake */
	local_irq_save(flags);
	gpio_wakeup = (self->gpio_wakup_flags == 0);
	local_irq_restore(flags);

	/* do wakeup mcu operation */
	if(gpio_wakeup) {
		bes2600_info(BES2600_DBG_SPI, "pull high gpio by flag:%d\n", falg);
		if (gpio_is_valid(pdata->host_wakeup_wlan)) {
			gpio_set_value(pdata->host_wakeup_wlan, 1);
			msleep(1);
		} else {
			bes2600_err(BES2600_DBG_SPI,
				"%s, wakeup gpio is invalid\n", __func__);
		}
	}

	/* set flag of gpio_wakeup_flags */
	set_bit(falg, &self->gpio_wakup_flags);
}

static void bes2600_gpio_allow_mcu_sleep(struct sbus_priv *self, int falg)
{
	unsigned long flags;
	bool gpio_sleep = false;
	const struct bes2600_platform_data_spi *pdata = bes2600_get_platform_data();
	if (pdata == NULL)
		return;

	bes2600_info(BES2600_DBG_SPI, "%s with %d\n", __func__, falg);

	/* error check */
	if(test_bit(falg, &self->gpio_wakup_flags) == 0) {
		bes2600_err(BES2600_DBG_SPI,
			"repeat clear gpio_wake_flag, sub_sys:%d", falg);
		return;
	}


	/* clear flag of gpio_wakeup_flags */
	clear_bit(falg, &self->gpio_wakup_flags);

	/* check if this is the last subsystem that need mcu to keep awake */
	local_irq_save(flags);
	gpio_sleep = (self->gpio_wakup_flags == 0);
	local_irq_restore(flags);

	/* do wakeup mcu operation */
	if(gpio_sleep) {
		bes2600_info(BES2600_DBG_SPI, "pull low gpio by flag:%d\n", falg);
		if (gpio_is_valid(pdata->host_wakeup_wlan)) {
			gpio_set_value(pdata->host_wakeup_wlan, 0);
		} else {
			bes2600_err(BES2600_DBG_SPI,
				"%s, wakeup gpio is invalid\n", __func__);
		}
	}
}

int bes2600_spi_active(struct sbus_priv *self, int sub_system)
{
	int ret = 0;

	if (bes2600_chrdev_is_signal_mode() || sub_system == SUBSYSTEM_WIFI) {
		uint32_t subint = 0, int_type = BES_HOST_INT_SUBINT, status, cfm;
		int retries;

		if (sub_system == SUBSYSTEM_MCU) {
			subint |= BES_SUBSYSTEM_MCU_ACTIVE;
			cfm = BES_SLAVE_STATUS_MCU_WAKEUP_READY;
		} else if (sub_system == SUBSYSTEM_WIFI) {
			subint |= BES_SUBSYSTEM_WIFI_ACTIVE;
			cfm = BES_SLAVE_STATUS_WIFI_OPEN_READY;
		} else if (sub_system == SUBSYSTEM_BT) {
			subint |= BES_SUBSYSTEM_BT_ACTIVE;
			cfm = BES_SLAVE_STATUS_BT_OPEN_READY;
		} else {
			return -EINVAL;
		}

		if ((ret = bes2600_spi_awake(self)))
			return ret;

		bes2600_spi_lock(self);

		retries = 0;
		do {
			if ((ret = bes2600_spi_reg_write(self, BES_HOST_SUBINT_REG_ID, &subint, 4)))
				goto exit;
			if ((ret = bes2600_spi_reg_write(self, BES_HOST_INT_REG_ID, &int_type, 4)))
				goto exit;
			msleep(25);
			if ((ret = bes2600_spi_reg_read(self, BES_SLAVE_STATUS_REG_ID, &status, 4)))
				goto exit;
			if (status & cfm)
				break;
			retries++;
		} while (retries < 80);

		if (retries >= 80) {
			bes2600_err(BES2600_DBG_SPI, "bes2600_spi_active(%d) failed(0x%x)\n", sub_system, status);
			ret = -110;
			goto exit;
		}
exit:
		bes2600_spi_unlock(self);
	}

	return ret;
}

static void bes2600_spi_work_empty(struct sbus_priv *self)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&self->rx_queue))) {
		dev_kfree_skb(skb);
	}

	self->lmac_ptr_top = 0;
	self->lmac_ptr = 0;
	self->lmac_addr_min = 0;
	self->lmac_addr_max = 0;
	self->packets_upload = 0;
}

int bes2600_spi_deactive(struct sbus_priv *self, int sub_system)
{
	int ret;

	if (bes2600_chrdev_is_signal_mode()) {
		u32 subint, cfm, status, int_type = BES_HOST_INT_SUBINT, sync = 0;
		int retries;

		if (sub_system == SUBSYSTEM_MCU) {
			subint = BES_SUBSYSTEM_MCU_DEACTIVE;
			cfm = BES_SLAVE_STATUS_MCU_WAKEUP_READY;
		} else if (sub_system == SUBSYSTEM_WIFI) {
			subint = BES_SUBSYSTEM_WIFI_DEACTIVE;
			cfm = BES_SLAVE_STATUS_WIFI_OPEN_READY;
		} else if (sub_system == SUBSYSTEM_BT) {
			subint = BES_SUBSYSTEM_BT_DEACTIVE;
			cfm = BES_SLAVE_STATUS_BT_OPEN_READY;
		} else {
			return -EINVAL;
		}

		bes2600_spi_lock(self);

		retries = 0;
		do {
			if ((ret = bes2600_spi_reg_write(self, BES_HOST_SUBINT_REG_ID, &subint, 4)))
				goto exit;
			if ((ret = bes2600_spi_reg_write(self, BES_HOST_INT_REG_ID, &int_type, 4)))
				goto exit;
			msleep(10);
			bes2600_spi_reg_read(self, BES_HOST_SYNC_REG_ID, &sync, 4);
			if ((ret = bes2600_spi_reg_read(self, BES_SLAVE_STATUS_REG_ID, &status, 4)))
				goto exit;
			if ( (sync != BES_SLAVE_SYNC_HEADER) || !(cfm & status) ) {
				break;
			}
			retries++;
		} while (retries < 5);

		if (retries >= 5) {
			ret = -EIO;
			bes2600_err(BES2600_DBG_SPI, "bes2600 spi deactive(%d) failed\n", sub_system);
			goto exit;
		}

		if (sub_system == SUBSYSTEM_MCU)
			self->spi_active = false;

		if (sub_system == SUBSYSTEM_WIFI)
			bes2600_spi_work_empty(self);

	} else {
		return 0;
	}

exit:
	bes2600_spi_unlock(self);
	return ret;
}

static int bes2600_spi_power_switch (struct sbus_priv *self, int on);
static struct sbus_ops bes2600_spi_sbus_ops = {
	.init = bes2600_spi_init,
	.sbus_memcpy_fromio	= bes2600_spi_memcpy_fromio,
	.sbus_memcpy_toio	= bes2600_spi_memcpy_toio,
	.lock			= bes2600_spi_lock,
	.unlock			= bes2600_spi_unlock,
	.irq_subscribe		= bes2600_spi_irq_subscribe,
	.irq_unsubscribe	= bes2600_spi_irq_unsubscribe,
	.align_size		= bes2600_spi_align_size,
	.set_block_size	= bes2600_spi_set_block_size,
	.sbus_reg_read = bes2600_spi_reg_read,
	.sbus_reg_write = bes2600_spi_reg_write,
	.pipe_read = bes2600_spi_pipe_read,
	.reset = bes2600_spi_reset,
	.sbus_active = bes2600_spi_active,
	.sbus_deactive = bes2600_spi_deactive,
	.power_switch = bes2600_spi_power_switch,
	.gpio_wake	    = bes2600_gpio_wakeup_mcu,
	.gpio_sleep         = bes2600_gpio_allow_mcu_sleep,
};

/* Probe Function to be called by SPI stack when device is discovered */
static int bes2600_spi_probe(struct spi_device *func)
{
	int ret;
	const struct bes2600_platform_data_spi *plat_data;
	struct sbus_priv *self;

	if ((ret = bes2600_platform_data_init(&func->dev)))
		return ret;

	plat_data = bes2600_get_platform_data();
	if ((ret = bes2600_spi_on(plat_data)))
		goto err_on;

	/* Sanity check speed */
#ifdef PLAT_ALLWINNER_T507
	if (!func->master->max_speed_hz || func->master->max_speed_hz > 48000000)
		func->max_speed_hz = 48000000;
	else
		func->max_speed_hz = func->master->max_speed_hz;
#endif

	/* Fix up transfer size */
	if (plat_data && plat_data->spi_bits_per_word)
		func->bits_per_word = plat_data->spi_bits_per_word;
	if (!func->bits_per_word)
		func->bits_per_word = 16;

	/* And finally.. */
	func->mode = SPI_MODE_3;

	bes2600_info(BES2600_DBG_SPI, "bes2600_wlan_spi: Probe called (FUNC %p CS %d M %d BPW %d CLK %d).\n",
		func, func->chip_select, func->mode, func->bits_per_word,
		func->max_speed_hz);

	if ((ret = spi_setup(func))) {
		bes2600_err(BES2600_DBG_SPI, "spi_setup() failed(%d)!\n", ret);
		goto err_setup;
	}

	self = devm_kzalloc(&func->dev, sizeof(*self), GFP_KERNEL);
	if (!self) {
		bes2600_err(BES2600_DBG_SPI, "Can't allocate SPI sbus_priv.");
		ret = -ENOMEM;
		goto err_nomem;
	}
	pr_info("%s self=%p\n", __func__, self);

	self->pdata = plat_data;
	self->func = func;
	self->dev = &func->dev;
	self->gpio_wakup_flags = 0;
	if (bes2600_chrdev_is_signal_mode())
		self->spi_active = false;
	else
		self->spi_active = true;

	spin_lock_init(&self->lock);

	spi_set_drvdata(func, self);

	init_waitqueue_head(&self->wq);

	bes2600_reg_set_object(&bes2600_spi_sbus_ops, self);

	if ((ret = bes2600_load_firmware(&bes2600_spi_sbus_ops, self)) < 0) {
		bes2600_err(BES2600_DBG_SPI, "bes2600_load_firmware failed(%d)\n", ret);
		goto err_probe;
	}

	if (ret) {
		bes2600_chrdev_set_sbus_priv_data(NULL);
		bes2600_spi_off(plat_data);
		goto out;
	}

#ifdef CONFIG_BES2600_SPI_THROUGHPUT_TEST
	return create_spi_throughput_entry(self);
#endif
	if ((ret = bes2600_core_probe(&bes2600_spi_sbus_ops,
			      self, &func->dev, &self->core))) {
		bes2600_err(BES2600_DBG_SPI, "bes2600_core_probe failed(%d)\n", ret);
		goto err_probe;
	}
	bes2600_chrdev_set_sbus_priv_data(self);

out:
	return 0;

err_probe:
	bes2600_reg_set_object(NULL, NULL);
err_nomem:
err_setup:
	bes2600_spi_off(plat_data);
err_on:
	bes2600_platform_data_deinit();
	return ret;
}

int bes2600_register_net_dev(struct sbus_priv *bus_priv)
{
	int status = 0;
	BUG_ON(!bus_priv);
	status = bes2600_core_probe(&bes2600_spi_sbus_ops,
			      bus_priv, bus_priv->dev, &bus_priv->core);

	return status;
}

int bes2600_unregister_net_dev(struct sbus_priv *bus_priv)
{
	BUG_ON(!bus_priv);
	if (bus_priv->core) {
		bes2600_core_release(bus_priv->core);
		bus_priv->core = NULL;
	}
	return 0;
}

bool bes2600_is_net_dev_created(struct sbus_priv *bus_priv)
{
	BUG_ON(!bus_priv);
	return (bus_priv->core != NULL);
}

static int bes2600_spi_power_switch (struct sbus_priv *null_self, int on)
{
	int ret;
	struct bes2600_platform_data_spi *pdata = bes2600_get_platform_data();
	struct sbus_priv *self = spi_get_drvdata((struct spi_device *)pdata->priv);
	pr_info("self:%p pdata:%p\n", self, pdata);
	if (on) {
		ret = bes2600_spi_on(pdata);
		if ((ret = bes2600_load_firmware(&bes2600_spi_sbus_ops, self)) < 0) {
			bes2600_err(BES2600_DBG_SPI, "%s bes2600_load_firmware failed(%d)\n", __func__, ret);
			goto off;
		}
		if ((ret = bes2600_register_net_dev(self)))
			goto off;
		bes2600_chrdev_set_sbus_priv_data(self);
		return 0;
	} else {
		bes2600_unregister_net_dev(self);
		bes2600_chrdev_set_sbus_priv_data(NULL);
	}

off:
	ret = bes2600_spi_off(self->pdata);
	return ret;
}

/* Disconnect Function to be called by SPI stack when device is disconnected */
static int bes2600_spi_disconnect(struct spi_device *func)
{
	struct sbus_priv *self = spi_get_drvdata(func);

	bes2600_info(BES2600_DBG_SPI, "%s\n", __func__);

#ifdef CONFIG_BES2600_SPI_THROUGHPUT_TEST
	destory_spi_throughput_entry();
#endif

	if (self) {
		//bes2600_spi_irq_unsubscribe(self);
		if (self->core) {
			bes2600_core_release(self->core);
			bes2600_spi_off(self->pdata);
			if (self->tx_dummy_buf)
				free_pages((unsigned long)self->tx_dummy_buf, get_order((1632 + 24)) * MAX_SEND_PACKETS_NUM);
			self->core = NULL;
		}
	}

	bes2600_reg_set_object(NULL, NULL);
	bes2600_platform_data_deinit();

	return 0;
}

static int __maybe_unused bes2600_spi_suspend(struct device *dev)
{
	int ret = 0;
	struct sbus_priv *self = spi_get_drvdata(to_spi_device(dev));

	bes2600_info(BES2600_DBG_SPI, "%s enter\n", __func__);

	bes2600_spi_lock(self);
	if (self->spi_active == true)
		ret = -EBUSY;
	bes2600_spi_unlock(self);

	/* XXX notify host that we have to keep BES2600 powered on? */
	return ret;
}

static int __maybe_unused bes2600_spi_resume(struct device *dev)
{
	/* SPI master shoud be reinitialize? */
	return 0;
}

static SIMPLE_DEV_PM_OPS(bes2600_pm_ops, bes2600_spi_suspend, bes2600_spi_resume);

static const struct of_device_id bes_spi_dev_ids[] = {
	{.compatible = "bes,wlan_2002"},
	{},
};

static struct spi_driver spi_driver = {
	.probe		= bes2600_spi_probe,
	.remove		= bes2600_spi_disconnect,
	.driver = {
		.name		= "bes2600_wlan_spi",
		.pm		= IS_ENABLED(CONFIG_PM) ? &bes2600_pm_ops : NULL,
		.of_match_table	= of_match_ptr(bes_spi_dev_ids),
	},
};


/* Init Module function -> Called by insmod */
static int __init bes2600_spi_module_init(void)
{
	int ret;

	bes2600_info(BES2600_DBG_SPI, "------Driver: bes2600.ko version :%s\n", BES2600_DRV_VERSION);

	bes2600_chrdev_update_signal_mode();

	ret = bes2600_chrdev_init(&bes2600_spi_sbus_ops);
	if(ret)
		return ret;

	ret = spi_register_driver(&spi_driver);

	return ret;
}

/* Called at Driver Unloading */
static void __exit bes2600_spi_module_exit(void)
{
	spi_unregister_driver(&spi_driver);
	bes2600_chrdev_free();
}

module_init(bes2600_spi_module_init);
module_exit(bes2600_spi_module_exit);
