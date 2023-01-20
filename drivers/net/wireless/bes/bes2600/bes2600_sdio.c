/*
 * Mac80211 SDIO driver for BES2600 device
 *
 * Copyright (c) 2010, Bestechnic
 * Author:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
 #define DEBUG 1
#include <linux/version.h>
#include <linux/module.h>
#include <linux/gpio.h>
#include <linux/delay.h>
#include <linux/mmc/host.h>
#include <linux/mmc/sdio_func.h>
#include <linux/mmc/card.h>
#include <linux/mmc/sdio.h>
#include <linux/spinlock.h>
#include <net/mac80211.h>
#include <linux/scatterlist.h>
#include <linux/mmc/host.h>
#include <linux/mmc/card.h>
#include <linux/mmc/sdio.h>
#include <linux/mmc/sdio_func.h>
#include <linux/version.h>
#include <linux/of_gpio.h>

#include "bes2600.h"
#include "sbus.h"
#include "bes2600_plat.h"
#include "hwio.h"
#include "bes2600_driver_mode.h"
#include "bes_chardev.h"

#ifdef PLAT_ROCKCHIP
#include <linux/rfkill-wlan.h>
#endif

#ifdef PLAT_ALLWINNER
#include <linux/sunxi-gpio.h>

extern int sunxi_wlan_get_bus_index(void);
extern void sunxi_mmc_rescan_card(unsigned id);
extern void sw_mci_rescan_card(unsigned id, unsigned insert);
extern void sunxi_wlan_set_power(bool on_off);
#endif

#if defined(BES2600_BOOT_UART_TO_SDIO)
static struct sbus_ops bes2600_sdio_sbus_ops;
extern int bes2600_boot_uart_to_sdio(struct sbus_ops *ops);
#endif
static void sdio_scan_work(struct work_struct *work);
static void bes2600_sdio_power_down(struct sbus_priv *self);
struct bes2600_platform_data_sdio *bes2600_get_platform_data(void);
int bes2600_register_net_dev(struct sbus_priv *bus_priv);
int bes2600_unregister_net_dev(struct sbus_priv *bus_priv);
static void bes2600_gpio_wakeup_mcu(struct sbus_priv *self, int falg);
static void bes2600_gpio_allow_mcu_sleep(struct sbus_priv *self, int falg);

MODULE_AUTHOR("Dmitry Tarnyagin <dmitry.tarnyagin@stericsson.com>");
MODULE_DESCRIPTION("mac80211 BES2600 SDIO driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("bes2600_wlan");

struct sbus_priv {
	struct sdio_func	*func;
	struct bes2600_common	*core;
	const struct bes2600_platform_data_sdio *pdata;
	spinlock_t		lock;
	sbus_irq_handler	irq_handler;
	void			*irq_priv;
	struct work_struct sdio_scan_work;
	struct device *dev;
	struct workqueue_struct *sdio_wq;
	bool fw_started;
	struct mutex io_mutex;
	long unsigned int gpio_wakup_flags;
	struct mutex sbus_mutex;
	bool retune_protected;
#ifdef BES_SDIO_RXTX_TOGGLE
	u8 next_toggle;
	int tx_data_toggle;
	int rx_data_toggle;
#endif
#ifdef BES_SDIO_RX_MULTIPLE_ENABLE
	spinlock_t rx_queue_lock;
	struct sk_buff_head rx_queue;
	u8 *rx_buffer;
	struct work_struct rx_work;
	u32 rx_last_ctrl;
	u32 rx_valid_ctrl;
	u32 rx_total_ctrl_cnt;
	u32 rx_continuous_ctrl_cnt;
	u32 rx_zero_ctrl_cnt;
	u32 rx_remain_ctrl_cnt;
	u32 rx_data_cnt;
	u32 rx_xfer_cnt;
	u32 rx_proc_cnt;
	long unsigned int last_irq_timestamp;
	long unsigned int last_rx_data_timestamp;
#endif
#ifdef BES_SDIO_TX_MULTIPLE_ENABLE
	u8 *tx_buffer;
	struct list_head tx_bufferlist;
	struct kmem_cache *tx_bufferlistpool;
	spinlock_t tx_bufferlock;
	struct work_struct tx_work;
	struct scatterlist tx_sg[BES_SDIO_TX_MULTIPLE_NUM + 1];
	struct scatterlist tx_sg_nosignal[BES_SDIO_TX_MULTIPLE_NUM_NOSIGNAL + 1];
	u32 tx_data_cnt;
	u32 tx_xfer_cnt;
	u32 tx_proc_cnt;
	long unsigned int last_tx_data_timestamp;
#endif
};

#define IS_DRIVER_VENDOR_CMD(X) ((X & 0x0C00) == 0x0C00)
struct HI_MSG_HDR {
	uint16_t MsgLen;
	uint16_t MsgId;
};

enum DRIVER_TO_MCU_MSG_ST {
	ST_ENTER,
	ST_EXIT,
};

#define BES_VENDOR_ID	0xbe57
#define BES_DEVICE_ID_2002	0x2002

static const struct sdio_device_id bes2600_sdio_ids[] = {
	{ SDIO_DEVICE(BES_VENDOR_ID, BES_DEVICE_ID_2002) },
	{ /* end: all zeroes */			},
};

#ifdef BES2600_GPIO_WAKEUP_AP
#ifdef PLAT_ALLWINNER
extern int sunxi_wlan_get_oob_irq_flags(void);
extern int sunxi_wlan_get_oob_irq(void);
#endif
static int bes2600_gpio_wakeup_ap_config(struct sbus_priv *priv);
#endif

/* sbus_ops implemetation */

#ifdef CONFIG_BES2600_WLAN_BES
static inline unsigned int sdio_max_byte_size(struct sdio_func *func)
{
	unsigned mval = min(func->card->host->max_seg_size, func->card->host->max_blk_size);

	if (func->card->quirks & MMC_QUIRK_BLKSZ_FOR_BYTE_MODE)
		mval = min(mval, func->cur_blksize);
	else
		mval = min(mval, func->max_blksize);

	return min(mval, 512u);
}

#define SDIO_USE_V2
#ifndef SDIO_USE_V2
int bes_sdio_memcpy_io_helper(struct sdio_func *func, int write, void *data, unsigned size)
{
	unsigned remainder = size;
	unsigned max_blocks;
	int ret = 0;

	sdio_claim_host(func);

	if (!func || (func->num > 7) || (!data) || (!size)) {
		ret = -EINVAL;
		goto out;
	}

	if (func->card->cccr.multi_block && (size > sdio_max_byte_size(func))) {
		max_blocks = min(func->card->host->max_blk_count, 511u);

		while (remainder >= func->cur_blksize) {
			unsigned blocks;

			blocks = remainder / func->cur_blksize;
			if (blocks > max_blocks)
				blocks = max_blocks;
			size = blocks * func->cur_blksize;

			bes2600_dbg(BES2600_DBG_SDIO, "%s size=%d block=%d dir=%d", __func__, size, blocks, write);
			if (write)
				ret = sdio_memcpy_toio(func, size, data, size);
			else
				ret = sdio_memcpy_fromio(func, data, size, size);
			if (ret)
				goto out;

			remainder -= size;
			data += size;
		}
	}


	while (remainder > 0) {
		size = min(remainder, sdio_max_byte_size(func));

		bes2600_dbg(BES2600_DBG_SDIO, "%s size=%d dir=%d", __func__, size, write);
		if (write)
			ret = sdio_memcpy_toio(func, size, data, size);
		else
			ret = sdio_memcpy_fromio(func, data, size, size);
		if (ret)
			goto out;

		remainder -= size;
		data += size;
	}
out:
	sdio_release_host(func);
	return ret;
}
#else
static int bes_sdio_memcpy_io_helper(struct sdio_func *func, int write, void *data_buf, unsigned size)
{
	int ret = 0;
	unsigned remainder = size;
	unsigned max_blocks, align_blocks, pads;

#ifdef BES_SDIO_RXTX_TOGGLE
	struct sbus_priv *self = NULL;
#endif

	struct mmc_request mrq;
	struct mmc_command cmd;
	struct mmc_data data;
	struct scatterlist sg[2], *next;
	u8 *pad_buf = (u8 *)kmalloc(func->cur_blksize, GFP_KERNEL);

	if (!pad_buf)
		return -ENOMEM;

	if (!func || (func->num > 7) || (!data_buf) || (!size)) {
		ret = -EINVAL;
		goto out;
	}

#ifdef BES_SDIO_RXTX_TOGGLE
	self = sdio_get_drvdata(func);
	BUG_ON(!self);
#endif

	if (func->card->cccr.multi_block && size > sdio_max_byte_size(func) ) {
		max_blocks = min(func->card->host->max_blk_count, 511u);
		align_blocks = (size + func->cur_blksize - 1) / func->cur_blksize;
		if (align_blocks > max_blocks) {
			/* to be simplified, consider this should not
			 * happen, and to be continued;
			 */
			bes2600_dbg(BES2600_DBG_SDIO, "%s warning to be continued, align=%d max=%d", __func__, align_blocks, max_blocks);
			ret = -EINVAL;
			goto out;
		}
		pads = align_blocks * func->cur_blksize - size;
		bes2600_dbg(BES2600_DBG_SDIO, "%s sz=%u blk=%u pad=%u,dir=%d", __func__, size, align_blocks, pads, write);

		memset(&mrq, 0, sizeof(mrq));
		memset(&cmd, 0, sizeof(cmd));
		memset(&data, 0, sizeof(data));

		mrq.cmd = &cmd;
		mrq.data = &data;

		cmd.opcode = SD_IO_RW_EXTENDED;
		cmd.arg = write ? 0x80000000 : 0x00000000;
		cmd.arg |= func->num << 28;
		cmd.arg |= 0x04000000;
		cmd.arg |= size << 9;

#ifdef BES_SDIO_RXTX_TOGGLE
		if (likely(self->fw_started == true)) {
			cmd.arg &= ~(1 << 25);
			if (write) {
				cmd.arg |= ((self->tx_data_toggle & 0x1) << 25);
				++self->tx_data_toggle;
			} else {
				cmd.arg |= ((self->rx_data_toggle & 0x1) << 25);
				++self->rx_data_toggle;
			}
		}
#endif

		cmd.arg |= 0x08000000 | align_blocks;
		cmd.flags = MMC_RSP_SPI_R5 | MMC_RSP_R5 | MMC_CMD_ADTC;

		data.blksz = func->cur_blksize;
		data.blocks = align_blocks;
		data.flags = write ? MMC_DATA_WRITE : MMC_DATA_READ;

		data.sg = sg;
		data.sg_len = 1;
		sg_init_table(sg, 2);
		sg_set_buf(sg, data_buf, size);
		if (pads) {
			next = sg_next(sg);
			sg_set_buf(next, pad_buf, pads);
			data.sg_len = 2;
		}

		mmc_set_data_timeout(&data, func->card);

		mmc_wait_for_req(func->card->host, &mrq);

		if (cmd.error){
			ret = cmd.error;
			goto out;
		}
		if (data.error) {
			ret = data.error;
			goto out;
		}
		if (cmd.resp[0] & R5_ERROR) {
			ret = -EIO;
			goto out;
		}
		if (cmd.resp[0] & R5_FUNCTION_NUMBER) {
			ret = -EINVAL;
			goto out;
		}
		if (cmd.resp[0] & R5_OUT_OF_RANGE) {
			ret = -ERANGE;
			goto out;
		}
	} else {
		while (remainder) {
			size = min(remainder, sdio_max_byte_size(func));

			bes2600_dbg(BES2600_DBG_SDIO, "%s size=%d dir=%d", __func__, size, write);
			if (write) {
#ifndef BES_SDIO_RXTX_TOGGLE
				ret = sdio_memcpy_toio(func, size, data_buf, size);
#else
				if (likely(self->fw_started == true)) {
					ret = sdio_memcpy_toio(func, size | ((self->tx_data_toggle & 0x1) << 16), data_buf, size);
					++self->tx_data_toggle;
				} else {
					ret = sdio_memcpy_toio(func, size, data_buf, size);
				}
#endif
			} else {
#ifndef BES_SDIO_RXTX_TOGGLE
				ret = sdio_memcpy_fromio(func, data_buf, size, size);
#else
				if (likely(self->fw_started == true)) {
					ret = sdio_memcpy_fromio(func, data_buf, size | ((self->rx_data_toggle & 0x1) << 16), size);
					++self->rx_data_toggle;
				} else {
					ret = sdio_memcpy_fromio(func, data_buf, size, size);
				}
#endif
			}
			if (ret)
				goto out;

			remainder -= size;
			data_buf += size;
		}
	}
out:
	kfree(pad_buf);
	if (ret) {
		bes2600_err(BES2600_DBG_SDIO, "%s, err=%d(%d:%p:%d)",
				__func__, ret, func->num, data_buf, size);
#ifdef BES_SDIO_RXTX_TOGGLE
				if (self && self->fw_started == true) {
					if (write)
						--self->tx_data_toggle;
					else
						--self->rx_data_toggle;
					bes2600_err(BES2600_DBG_SDIO, "%s,toggle count:%u,%u\n", __func__, self->tx_data_toggle, self->rx_data_toggle);
				}
#endif
	}
	return ret;
}
#endif
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,19,56))
static void sdio_retune_hold_now(struct sdio_func *func)
{
	func->card->host->retune_now = 0;
	func->card->host->hold_retune += 1;
}

static void sdio_retune_release(struct sdio_func *func)
{
	if (func->card->host->hold_retune)
		func->card->host->hold_retune -= 1;
	else
		WARN_ON(1);
}
#endif

static int bes2600_sdio_memcpy_fromio(struct sbus_priv *self,
				     unsigned int addr,
				     void *dst, int count)
{
	return bes_sdio_memcpy_io_helper(self->func, 0, dst, count);
}

static int bes2600_sdio_memcpy_toio(struct sbus_priv *self,
				   unsigned int addr,
				   const void *src, int count)
{
	return bes_sdio_memcpy_io_helper(self->func, 1, (void *)src, count);
}

static void bes2600_sdio_lock(struct sbus_priv *self)
{
	sdio_claim_host(self->func);
}

static void bes2600_sdio_unlock(struct sbus_priv *self)
{
	sdio_release_host(self->func);
}

/* bes sdio slave regs can only be accessed by command52
 * if a WORD or DWORD reg wants to be accessed,
 * please combine the results of multiple command52
 */
static int bes2600_sdio_reg_read(struct sbus_priv *self, u32 reg,
					void *dst, int count)
{
	int ret = 0;
	if (count <= 0 || !dst)
		return -EINVAL;
	while(count && !ret) {
		*(u8 *)dst = sdio_readb(self->func, reg, &ret);
		dst ++;
		reg ++;
		count--;
	}
	return ret;

}

static int bes2600_sdio_reg_write(struct sbus_priv *self, u32 reg,
					const void *src, int count)
{
	int ret = 0;
	if (count <= 0 || !src)
		return -EINVAL;
	while (count && !ret) {
		sdio_writeb(self->func, *(u8 *)src, reg, &ret);
		src ++;
		reg ++;
		count --;
	}
	return ret;
}

#ifndef CONFIG_BES2600_USE_GPIO_IRQ
static void bes2600_sdio_irq_handler(struct sdio_func *func)
{
	struct sbus_priv *self = sdio_get_drvdata(func);
	unsigned long flags;
	bes2600_dbg(BES2600_DBG_SDIO, "\n %s called, fw_started:%d \n",
			 __func__, self->fw_started);

	if (WARN_ON(!self)) {
		return;
	}

	if (likely(self->fw_started)) {
		queue_work(self->sdio_wq, &self->rx_work);
		self->last_irq_timestamp = jiffies;
	} else {
		spin_lock_irqsave(&self->lock, flags);
		if (self->irq_handler)
			self->irq_handler(self->irq_priv);
		spin_unlock_irqrestore(&self->lock, flags);
	}
}
#else /* CONFIG_BES2600_USE_GPIO_IRQ */
static u32 bes2600_gpio_irq_handler(void *dev_id)
{
	struct sbus_priv *self = (struct sbus_priv *)dev_id;

	bes2600_dbg(BES2600_DBG_SDIO, "\n %s called \n", __func__);
	BUG_ON(!self);
	if (self->irq_handler)
		self->irq_handler(self->irq_priv);
	return 0;
}

static int bes2600_request_irq(struct sbus_priv *self,
			      u32 handler)
{
	int ret = 0;
	int func_num;
	const struct resource *irq = self->pdata->irq;
	u8 cccr;
	int ret0 = 0;

#ifdef PLAT_ALLWINNER_SUN6I   // for Allwinner we define plat specific API to allocate IRQ line
		aw_gpio_irq_handle = sw_gpio_irq_request(irq->start, TRIG_EDGE_POSITIVE, (peint_handle)handler, self);
		if (aw_gpio_irq_handle == 0) {
			bes2600_err(BES2600_DBG_SDIO, "[%s]  err sw_gpio_irq_request..   :%d\n", __func__,aw_gpio_irq_handle);
			return -1;
		} else
		{
			ret = 0;
		}
#endif  // PLAT_ALLWINNER_SUN6I

	/* Hack to access Fuction-0 */
	func_num = self->func->num;
	self->func->num = 0;

	cccr = sdio_readb(self->func, SDIO_CCCR_IENx, &ret);
	if (WARN_ON(ret))
		goto set_func;

	/* Master interrupt enable ... */
	cccr |= BIT(0);

	/* ... for our function */
	cccr |= BIT(func_num);

	sdio_writeb(self->func, cccr, SDIO_CCCR_IENx, &ret);
	if (WARN_ON(ret))
		goto set_func;

	/* Restore the WLAN function number */
	self->func->num = func_num;
	return 0;

set_func:
	//AW judge sdio read write timeout, 1s
	ret0 = sw_mci_check_r1_ready(self->func->card->host, 1000);
	if (ret0 != 0)
		bes2600_err(BES2600_DBG_SDIO, ("%s data timeout.\n", __FUNCTION__));

	self->func->num = func_num;
#ifdef PLAT_ALLWINNER_SUN6I
	sw_gpio_irq_free(aw_gpio_irq_handle);
	aw_gpio_irq_handle = 0;
#endif
	bes2600_err(BES2600_DBG_SDIO, "[%s]  fail exiting sw_gpio_irq_request..   :%d\n",__func__, ret);
	return ret;
}
#endif /* CONFIG_BES2600_USE_GPIO_IRQ */

static int bes2600_sdio_irq_subscribe(struct sbus_priv *self,
				     sbus_irq_handler handler,
				     void *priv)
{
	int ret;
	unsigned long flags;

	if (!handler)
		return -EINVAL;

	spin_lock_irqsave(&self->lock, flags);
	self->irq_priv = priv;
	self->irq_handler = handler;
	spin_unlock_irqrestore(&self->lock, flags);

	bes2600_dbg(BES2600_DBG_SDIO,  "SW IRQ subscribe\n");
	sdio_claim_host(self->func);
#ifndef CONFIG_BES2600_USE_GPIO_IRQ
	ret = sdio_claim_irq(self->func, bes2600_sdio_irq_handler);
#else
	mdelay(10);
	ret = bes2600_request_irq(self, bes2600_gpio_irq_handler);
#endif
	sdio_release_host(self->func);
	return ret;
}

static int bes2600_sdio_irq_unsubscribe(struct sbus_priv *self)
{
	int ret = 0;
	unsigned long flags;
#ifdef CONFIG_BES2600_USE_GPIO_IRQ
	const struct resource *irq = self->pdata->irq;
#ifdef PLAT_ALLWINNER_SUN6I
	sw_gpio_irq_free(aw_gpio_irq_handle);
	aw_gpio_irq_handle = 0;
#endif
#endif

	WARN_ON(!self->irq_handler);
	if (!self->irq_handler)
		return 0;

	bes2600_dbg(BES2600_DBG_SDIO, "SW IRQ unsubscribe\n");

/*
#ifndef CONFIG_BES2600_USE_GPIO_IRQ
	sdio_claim_host(self->func);
	ret = sdio_release_irq(self->func);
	sdio_release_host(self->func);
#else
	free_irq(irq->start, self);
#endif  //CONFIG_BES2600_USE_GPIO_IRQ
*/

	spin_lock_irqsave(&self->lock, flags);
	self->irq_priv = NULL;
	self->irq_handler = NULL;
	spin_unlock_irqrestore(&self->lock, flags);

	return ret;
}

static int bes2600_sdio_off(const struct bes2600_platform_data_sdio *pdata)
{
	bes2600_info(BES2600_DBG_SDIO, "%s enter\n", __func__);

#if defined(PLAT_ALLWINNER)
	sunxi_wlan_set_power(false);
#endif

#if defined(PLAT_ROCKCHIP)
	rockchip_wifi_set_carddetect(0);
	rockchip_wifi_power(0);
#endif

	if (pdata == NULL)
		return 0;

#if defined(PLAT_GENERIC) || defined(BES2600_INDEPENDENT_EVB)
	if (gpio_is_valid(pdata->powerup)) {
		gpio_direction_output(pdata->powerup, 0);
	}
#endif

	return 0;
}

static int bes2600_sdio_on(const struct bes2600_platform_data_sdio *pdata)
{

	bes2600_info(BES2600_DBG_SDIO, "%s enter\n", __func__);

#if defined(PLAT_ALLWINNER)
	sunxi_wlan_set_power(true);
#endif

#ifdef PLAT_ROCKCHIP
	rockchip_wifi_power(0);
	rockchip_wifi_power(1);
	rockchip_wifi_set_carddetect(1);
#endif

	if (pdata != NULL) {
#if defined(PLAT_GENERIC) || defined(BES2600_INDEPENDENT_EVB)
		if (gpio_is_valid(pdata->powerup)) {
			gpio_direction_output(pdata->powerup, 1);
		}
#endif
	}

#if defined(BES2600_BOOT_UART_TO_SDIO)
	return bes2600_boot_uart_to_sdio(&bes2600_sdio_sbus_ops);
#endif

	return 0;
}

static size_t bes2600_sdio_align_size(struct sbus_priv *self, size_t size)
{
	size_t aligned  = size;
	if (self->func->cur_blksize > size)
	       aligned = sdio_align_size(self->func, size);
	else
		aligned = (aligned + 3) & (~3);

	return aligned;
}

int bes2600_sdio_set_block_size(struct sbus_priv *self, size_t size)
{
	return sdio_set_block_size(self->func, size);
}

void sdio_work_debug(struct sbus_priv *self)
{
	u8 cfg;
	int ret;
	bes2600_err(BES2600_DBG_SDIO, "%s now=%u last irq timestamp=%u\n", __func__,
			(u32)jiffies_to_msecs(jiffies), jiffies_to_msecs(self->last_irq_timestamp));
	bes2600_err(BES2600_DBG_SDIO, "%s rx ctrl: total=%u continuous=%u xfer=%u remain=%u zero=%u last=%x(%x) next=%d\n", __func__,
			self->rx_total_ctrl_cnt, self->rx_continuous_ctrl_cnt, self->rx_xfer_cnt, self->rx_remain_ctrl_cnt, self->rx_zero_ctrl_cnt,
			self->rx_last_ctrl, self->rx_valid_ctrl, self->next_toggle);
	bes2600_err(BES2600_DBG_SDIO, "%s rx: last timestamp=%u, total=%u(%u), proc=%u\n", __func__,
			(u32)jiffies_to_msecs(self->last_rx_data_timestamp),
			self->rx_data_cnt, self->rx_xfer_cnt, self->rx_proc_cnt);
	bes2600_err(BES2600_DBG_SDIO, "%s tx: last timestamp=%u, total=%u,%u, proc=%u\n", __func__,
			(u32)jiffies_to_msecs(self->last_tx_data_timestamp),
			self->tx_data_cnt, self->tx_xfer_cnt, self->tx_proc_cnt);
	mutex_lock(&self->sbus_mutex);
	sdio_claim_host(self->func);
	bes2600_sdio_reg_read(self, BES_TX_CTRL_REG_ID + 1, &cfg, 1);
	bes2600_err(BES2600_DBG_SDIO, "realtime ctrl=%x\n", cfg);
	cfg = BES_HOST_INT | BES_SUBSYSTEM_WIFI_DEBUG;
	sdio_writeb(self->func, 0, BES_HOST_INT_REG_ID + 1, &ret);
	sdio_writeb(self->func, cfg, BES_HOST_INT_REG_ID, &ret);
	sdio_release_host(self->func);
	mutex_unlock(&self->sbus_mutex);
}

#ifndef BES_SDIO_OPTIMIZED_LEN
static u8 const crc8_table[256] = {
	0x00, 0x07, 0x0E, 0x09, 0x1C, 0x1B, 0x12, 0x15,
	0x38, 0x3F, 0x36, 0x31, 0x24, 0x23, 0x2A, 0x2D,
	0x70, 0x77, 0x7E, 0x79, 0x6C, 0x6B, 0x62, 0x65,
	0x48, 0x4F, 0x46, 0x41, 0x54, 0x53, 0x5A, 0x5D,
	0xE0, 0xE7, 0xEE, 0xE9, 0xFC, 0xFB, 0xF2, 0xF5,
	0xD8, 0xDF, 0xD6, 0xD1, 0xC4, 0xC3, 0xCA, 0xCD,
	0x90, 0x97, 0x9E, 0x99, 0x8C, 0x8B, 0x82, 0x85,
	0xA8, 0xAF, 0xA6, 0xA1, 0xB4, 0xB3, 0xBA, 0xBD,
	0xC7, 0xC0, 0xC9, 0xCE, 0xDB, 0xDC, 0xD5, 0xD2,
	0xFF, 0xF8, 0xF1, 0xF6, 0xE3, 0xE4, 0xED, 0xEA,
	0xB7, 0xB0, 0xB9, 0xBE, 0xAB, 0xAC, 0xA5, 0xA2,
	0x8F, 0x88, 0x81, 0x86, 0x93, 0x94, 0x9D, 0x9A,
	0x27, 0x20, 0x29, 0x2E, 0x3B, 0x3C, 0x35, 0x32,
	0x1F, 0x18, 0x11, 0x16, 0x03, 0x04, 0x0D, 0x0A,
	0x57, 0x50, 0x59, 0x5E, 0x4B, 0x4C, 0x45, 0x42,
	0x6F, 0x68, 0x61, 0x66, 0x73, 0x74, 0x7D, 0x7A,
	0x89, 0x8E, 0x87, 0x80, 0x95, 0x92, 0x9B, 0x9C,
	0xB1, 0xB6, 0xBF, 0xB8, 0xAD, 0xAA, 0xA3, 0xA4,
	0xF9, 0xFE, 0xF7, 0xF0, 0xE5, 0xE2, 0xEB, 0xEC,
	0xC1, 0xC6, 0xCF, 0xC8, 0xDD, 0xDA, 0xD3, 0xD4,
	0x69, 0x6E, 0x67, 0x60, 0x75, 0x72, 0x7B, 0x7C,
	0x51, 0x56, 0x5F, 0x58, 0x4D, 0x4A, 0x43, 0x44,
	0x19, 0x1E, 0x17, 0x10, 0x05, 0x02, 0x0B, 0x0C,
	0x21, 0x26, 0x2F, 0x28, 0x3D, 0x3A, 0x33, 0x34,
	0x4E, 0x49, 0x40, 0x47, 0x52, 0x55, 0x5C, 0x5B,
	0x76, 0x71, 0x78, 0x7F, 0x6A, 0x6D, 0x64, 0x63,
	0x3E, 0x39, 0x30, 0x37, 0x22, 0x25, 0x2C, 0x2B,
	0x06, 0x01, 0x08, 0x0F, 0x1A, 0x1D, 0x14, 0x13,
	0xAE, 0xA9, 0xA0, 0xA7, 0xB2, 0xB5, 0xBC, 0xBB,
	0x96, 0x91, 0x98, 0x9F, 0x8A, 0x8D, 0x84, 0x83,
	0xDE, 0xD9, 0xD0, 0xD7, 0xC2, 0xC5, 0xCC, 0xCB,
	0xE6, 0xE1, 0xE8, 0xEF, 0xFA, 0xFD, 0xF4, 0xF3
};

static u8 bes_crc8(const u8 *data, unsigned len)
{
	u8 crc = 0;

	while(len--)
		crc = crc8_table[crc ^ *data++];

	return crc;
}
#endif

int bes2600_sdio_read_ctrl(struct sbus_priv *self, u32 *ctrl_reg)
{
	u8 data[4];
	#ifndef BES_SDIO_OPTIMIZED_LEN
	u8 check;
	u16 pkts, len;
	#endif
	int ret = 0, again = 0;
	*ctrl_reg = 0;

	/* clear sdio slave gen interrupt */
	ret = bes2600_sdio_reg_read(self, BES_TX_CTRL_REG_ID + 1, data, 1);
	#ifndef BES_SDIO_OPTIMIZED_LEN
	ret = bes2600_sdio_reg_read(self, BES_TX_NEXT_LEN_REG_ID, data, 4);
	#endif
	if (unlikely(ret)) {
		bes2600_err(BES2600_DBG_SDIO, "[SBUS] Failed(%d) to read control register.\n", ret);
		return ret;
	}
	self->rx_total_ctrl_cnt++;

	#ifndef BES_SDIO_OPTIMIZED_LEN
	check = bes_crc8((const u8 *)data, 3);
	if (data[3] == check) {
		/* length field crc8 pass */
		*ctrl_reg = *(u32 *)data;
		if (((data[2] >> 7) & 0x1) == self->next_toggle) {
			/* toggle valid */
			*ctrl_reg &= (~0xff800000);
		} else {
			/* last toggle */
			*ctrl_reg = 0;
			again = 1;
		}

		if (*ctrl_reg) {
			/* length field valid */
			again = 1;
			pkts = ((*ctrl_reg) >> 16) & 0x7f;
			len = (*ctrl_reg) & 0xffff;
			if (pkts && len) {
				self->next_toggle_debug = *(u32 *)data;
				self->next_toggle ^= 1;
			} else {
				*ctrl_reg = 0;
			}
		}
	} else {
		/* length field crc fail */
		//pr_err("%s, crc err:%x,%x,%x,%x,%x\n", __func__, data[0], data[1], data[2], data[3], check);
		//msleep(1);
		*ctrl_reg = 0;
		again = 1;
	}
	#else
	if (data[0] & 0x7f) {
		/* length field valid */
		again = 1;
		if (((data[0] >> 7) & 0x1) == self->next_toggle) {
			*ctrl_reg = (data[0] & 0x7f) << 9;
			self->rx_valid_ctrl = data[0];
			if (self->rx_last_ctrl && (((self->rx_last_ctrl >> 7) & 0x1) != self->next_toggle))
				self->rx_continuous_ctrl_cnt++;
			self->next_toggle ^= 1;
		} else {
			self->rx_remain_ctrl_cnt++;
		}
	} else {
		/* distinguish zero true or false */
		self->rx_zero_ctrl_cnt++;
		ret = bes2600_sdio_reg_read(self, BES_TX_CTRL_REG_ID, &data[1], 1);
		if (!ret && (data[1] & 0x01))
			again = 0;
		else
			again = 1;
	}
	self->rx_last_ctrl = data[0];
	#endif
	return again;
}

#ifdef BES_SDIO_RX_MULTIPLE_ENABLE

static int bes2600_sdio_packets_check(u32 ctrl_reg, u8 *packets)
{
	int i;
	u16 single, total_cal = 0;
	u16 packets_length;
	struct HI_MSG_HDR *pMsg;

	/* bit 23-16 indicate count of packets */
	u32 packets_cnt;
	#ifndef BES_SDIO_OPTIMIZED_LEN
	packets_cnt = PACKET_COUNT(ctrl_reg);
	if (WARN_ON(packets_cnt > BES_SDIO_RX_MULTIPLE_NUM))
		return -200;
	#else
	packets_cnt = BES_SDIO_RX_MULTIPLE_NUM;
	#endif

	/* bit 15-0 indicate totoal length of packets */
	packets_length = PACKET_TOTAL_LEN(ctrl_reg);

	/* first 32-bit: addr in mcu;
	 * second 32-bit: packet length;
	 * next: data
	 */
	for (i = 0; i < packets_cnt; i++) {
		pMsg = (struct HI_MSG_HDR *)(packets + total_cal);
		bes2600_dbg(BES2600_DBG_SDIO, "%s, %x,%x\n", __func__, pMsg->MsgId, pMsg->MsgLen);
		single = pMsg->MsgLen;
		single = (single + 3) & (~0x3);
		if (unlikely(single > 1632)) {
			bes2600_warn(BES2600_DBG_SDIO, "%s %d,len=%u,%dth,total=%u,%u\n", __func__, __LINE__, single, i,
					packets_length, total_cal);
			if (i >= 1) {
				return -201;
			}
		}
		total_cal += single;
		#ifdef BES_SDIO_OPTIMIZED_LEN
		if ((!pMsg->MsgLen) || (total_cal == packets_length)) {
			//pr_info("%s, contain %d packets\n", __func__, i);
			break;
		}
		#endif
	}
	bes2600_dbg(BES2600_DBG_SDIO, "%s, %d,%u,%u\n", __func__, packets_cnt, packets_length, total_cal);

	#ifndef BES_SDIO_OPTIMIZED_LEN
	if (WARN_ON(packets_length != total_cal)) {
		return -202;
	}
	#else
	if (packets_length < total_cal) {
		pr_err("%s,%d pkt len=%u, total len=%u", __func__, __LINE__, packets_length, total_cal);
		return -202;
	}
	#endif

	return 0;
}

static int bes2600_sdio_extract_packets(struct sbus_priv *self, u32 ctrl_reg, u8 *data)
{
	int i, alloc_retry = 0;
	#ifndef BES_SDIO_OPTIMIZED_LEN
	u8 packets_cnt = PACKET_COUNT(ctrl_reg);
	#else
	u8 packets_cnt = BES_SDIO_RX_MULTIPLE_NUM;
	#endif
	u16 packet_len, pos = 0;
	struct sk_buff *skb;

	for (i = 0; i < packets_cnt; i++) {
		packet_len = ((struct HI_MSG_HDR *)&(data[pos]))->MsgLen;
		#ifdef BES_SDIO_OPTIMIZED_LEN
		if (!packet_len)
			break;
		#endif
		do {
			skb = dev_alloc_skb(packet_len);
			if (likely(skb))
				break;
			bes2600_warn(BES2600_DBG_SDIO, "%s,%d no memory and sleep\n", __func__, __LINE__);
			msleep(100);
			++alloc_retry;
		} while(alloc_retry < 10);
		if (WARN_ON(!skb)) {
			return -ENOMEM;
		}
		skb_trim(skb, 0);
		skb_put(skb, packet_len);
		memcpy(skb->data, &data[pos], packet_len);
		bes2600_dbg(BES2600_DBG_SDIO, "%s, %d,%d\n", __func__, packet_len, pos);
		spin_lock(&self->rx_queue_lock);
		skb_queue_tail(&self->rx_queue, skb);
		self->rx_data_cnt++;
		spin_unlock(&self->rx_queue_lock);
		packet_len = (packet_len + 3) & (~0x3);
		pos += packet_len;
		#ifdef BES_SDIO_OPTIMIZED_LEN
		if (pos == PACKET_TOTAL_LEN(ctrl_reg))
			break;
		#endif
	}
	return 0;
}

static void sdio_rx_work (struct work_struct *work)
{
	int ret, again = 0, retry = 0, crc_retry = 0;
	u32 ctrl_reg = 0;
	int total_len;
	struct sbus_priv *self = container_of(work, struct sbus_priv, rx_work);
	u8 *buf = self->rx_buffer;

	/* don't read/write sdio when sdio error */
	if(bes2600_chrdev_is_bus_error())
		return;

	bes2600_gpio_wakeup_mcu(self, GPIO_WAKE_FLAG_SDIO_RX);

	do {
		bes2600_sdio_lock(self);
		again = bes2600_sdio_read_ctrl(self, &ctrl_reg);

		if(again == -EBUSY || again == -ETIMEDOUT) {
			bes2600_err(BES2600_DBG_SDIO, "%s sdio read error\n", __func__);
			bes2600_sdio_unlock(self);
			goto failed;
		}

		total_len = PACKET_TOTAL_LEN(ctrl_reg);
		if (!total_len) {
			bes2600_sdio_unlock(self);
			if ((again == 1) && retry <= 5) {
				retry++;
				continue;
			} else {
				break;
			}
		}

		do {
			ret = bes2600_sdio_memcpy_fromio(self, 0, buf, total_len);
			if (likely(ret != -84)) {
				crc_retry = 0;
				break;
			} else {
				crc_retry++;
				bes2600_err(BES2600_DBG_SDIO, "%s sdio read crc error(%d)\n", __func__, crc_retry);
			}
		} while (crc_retry <= 10);
		if (self->retune_protected == true) {
			sdio_retune_release(self->func);
			self->retune_protected = false;
		}
		bes2600_sdio_unlock(self);
		if (ret) {
			bes2600_err(BES2600_DBG_SDIO, "%s,%d error=%d\n", __func__, __LINE__, ret);
			sdio_work_debug(self);
			goto failed;
		}
		retry = 0;
		self->rx_xfer_cnt++;
		self->last_rx_data_timestamp = jiffies;

		if ((ret = bes2600_sdio_packets_check(ctrl_reg, buf))) {
			bes2600_err(BES2600_DBG_SDIO, "%s,%d error=%d\n", __func__, __LINE__, ret);
			sdio_work_debug(self);
			goto failed;
		}

		if ((ret = bes2600_sdio_extract_packets(self, ctrl_reg, buf))) {
			bes2600_err(BES2600_DBG_SDIO, "%s,%d error=%d\n", __func__, __LINE__, ret);
			goto failed;
		}

		ctrl_reg = 0;

		if (likely(self->irq_handler)) {
			self->irq_handler(self->irq_priv);
		} else {
			bes2600_err(BES2600_DBG_SDIO, "%s,%d\n", __func__, __LINE__);
			goto failed;
		}

	} while (again);

	bes2600_gpio_allow_mcu_sleep(self, GPIO_WAKE_FLAG_SDIO_RX);
	return;

failed:
	bes2600_gpio_allow_mcu_sleep(self, GPIO_WAKE_FLAG_SDIO_RX);
	bes2600_chrdev_wifi_force_close(self->core);
	WARN_ON(1);
}

static void sdio_scan_work(struct work_struct *work)
{
#ifdef PLAT_ALLWINNER
	//sw_mci_rescan_card(AW_SDIOID, 1);
	sunxi_mmc_rescan_card(sunxi_wlan_get_bus_index());
#endif

#ifdef PLAT_ROCKCHIP
	rockchip_wifi_set_carddetect(1);
#endif
	bes2600_info(BES2600_DBG_SDIO, "%s: power down, rescan card\n", __FUNCTION__);
}

static void *bes2600_sdio_pipe_read(struct sbus_priv *self)
{
	struct sk_buff *skb;

	if(bes2600_chrdev_is_bus_error()) {
		return bes2600_tx_loop_read(self->core);
	}

	spin_lock(&self->rx_queue_lock);
	skb = skb_dequeue(&self->rx_queue);
	if (skb)
		self->rx_proc_cnt++;
	spin_unlock(&self->rx_queue_lock);
	if (likely(self->fw_started == true &&
		!bes2600_pwr_device_is_idle(self->core) &&
		self->core->hw_bufs_used > 0))
		if (!skb)
			queue_work(self->sdio_wq, &self->rx_work);
	return skb;
}

#endif

#ifdef BES_SDIO_TX_MULTIPLE_ENABLE

struct bes_sdio_tx_list_t {
	struct list_head node;
	u8 *buf;
	u32 len;
};

static int bes_sdio_memcpy_to_io_helper(struct sdio_func *func, unsigned origin_size, struct scatterlist *sg, u32 sg_num)
{
	int ret = 0;
	u32 align_blocks;
	u32 compensate, sg_compensate_num = sg_num;
	unsigned size = origin_size & (~0x3);


#ifdef BES_SDIO_RXTX_TOGGLE
	struct sbus_priv *self = NULL;
#endif

	struct mmc_request mrq;
	struct mmc_command cmd;
	struct mmc_data data;

#ifdef BES_SDIO_RXTX_TOGGLE
	self = sdio_get_drvdata(func);
#endif

	if (size && func->card->cccr.multi_block) {

		align_blocks = (size + func->cur_blksize - 1) / func->cur_blksize;
		bes2600_dbg(BES2600_DBG_SDIO, "%s sz=%u blk=%u", __func__, size, align_blocks);
		compensate = align_blocks * func->cur_blksize - size;
		if (compensate) {
			sg_set_buf(&sg[sg_num], self->tx_buffer, compensate);
			sg_compensate_num = sg_num + 1;
		}
		sg_mark_end(&sg[sg_compensate_num - 1]);

		memset(&mrq, 0, sizeof(mrq));
		memset(&cmd, 0, sizeof(cmd));
		memset(&data, 0, sizeof(data));

		mrq.cmd = &cmd;
		mrq.data = &data;

		cmd.opcode = SD_IO_RW_EXTENDED;
		cmd.arg = 0x80000000;
		cmd.arg |= func->num << 28;
		cmd.arg |= 0x04000000;
		cmd.arg |= (origin_size) << 9;

#ifdef BES_SDIO_RXTX_TOGGLE
		if (likely(self->fw_started == true)) {
			cmd.arg &= ~(1 << 25);
			cmd.arg |= ((self->tx_data_toggle & 0x1) << 25);
			++self->tx_data_toggle;
		}
#endif

		cmd.arg |= 0x08000000 | align_blocks;
		cmd.flags = MMC_RSP_SPI_R5 | MMC_RSP_R5 | MMC_CMD_ADTC;

		data.blksz = func->cur_blksize;
		data.blocks = align_blocks;
		data.flags = MMC_DATA_WRITE;

		data.sg = sg;
		data.sg_len = sg_compensate_num;

		mmc_set_data_timeout(&data, func->card);

		mmc_wait_for_req(func->card->host, &mrq);

		if (cmd.error){
			ret = cmd.error;
			goto out;
		}
		if (data.error) {
			ret = data.error;
			goto out;
		}
		if (cmd.resp[0] & R5_ERROR) {
			ret = -EIO;
			goto out;
		}
		if (cmd.resp[0] & R5_FUNCTION_NUMBER) {
			ret = -EINVAL;
			goto out;
		}
		if (cmd.resp[0] & R5_OUT_OF_RANGE) {
			ret = -ERANGE;
			goto out;
		}
	} else {
		bes2600_err(BES2600_DBG_SDIO, "%s,%d (%u)\n", __func__, __LINE__, size);
		ret = -EINVAL;
	}
out:
#ifdef BES_SDIO_RXTX_TOGGLE
	if (unlikely(ret))
		self->tx_data_toggle--;
#endif
	return ret;
}

static void sdio_tx_work(struct work_struct *work)
{
	int ret, crc_retry = 0;
	u32 blks, cur_blk = 0, align, total_len = 0, scatters = 0;
	struct list_head proc_list;
	struct bes_sdio_tx_list_t *tx_buffer, *temp;
	struct sbus_priv *self = container_of(work, struct sbus_priv, tx_work);
	struct scatterlist *sg = NULL;
	int bes_sdio_tx_multiple_num;
	struct HI_MSG_HDR *pMsg;
	enum DRIVER_TO_MCU_MSG_ST driver_to_mcu = ST_EXIT;

	/* don't read/write sdio when sdio error */
	if(bes2600_chrdev_is_bus_error())
		return;

	if (bes2600_chrdev_is_signal_mode()) {
		sg = self->tx_sg;
		bes_sdio_tx_multiple_num = BES_SDIO_TX_MULTIPLE_NUM;
	} else {
		sg = self->tx_sg_nosignal;
		bes_sdio_tx_multiple_num = BES_SDIO_TX_MULTIPLE_NUM_NOSIGNAL;
	}

	INIT_LIST_HEAD(&proc_list);

	for (;;) {
		spin_lock(&self->tx_bufferlock);
		list_splice_tail_init(&self->tx_bufferlist, &proc_list);
		spin_unlock(&self->tx_bufferlock);
		if (list_empty(&proc_list))
			break;
		sg_init_table(sg, bes_sdio_tx_multiple_num + 1);
		list_for_each_entry_safe(tx_buffer, temp, &proc_list, node) {
			blks = (tx_buffer->len + self->func->cur_blksize - 1) / self->func->cur_blksize;
			align = blks * self->func->cur_blksize;
			if (blks >= 4) {
				align = 1632;
			}
			if (unlikely(blks >= 5)) {
				bes2600_err(BES2600_DBG_SDIO, "%s,%d skip error-len packet:%u,%d\n", __func__, __LINE__, tx_buffer->len, blks);
				list_del_init(&tx_buffer->node);
				kmem_cache_free(self->tx_bufferlistpool, tx_buffer);
				continue;
			}
			bes2600_dbg(BES2600_DBG_SDIO, "%s,%p,%u->%u\n", __func__, tx_buffer->buf, tx_buffer->len, align);
			if (!cur_blk)
				cur_blk = blks;
			else if (cur_blk != blks)
				goto flush_previous;

			pMsg = (struct HI_MSG_HDR *)tx_buffer->buf;
			if (unlikely(IS_DRIVER_VENDOR_CMD(pMsg->MsgId))) {
				if (driver_to_mcu == ST_EXIT) {
					driver_to_mcu = ST_ENTER;
					goto flush_previous;
				}
			}

			total_len += align;
			sg_set_buf(&sg[scatters], tx_buffer->buf, align);
			++scatters;
/*del_node:*/
			list_del_init(&tx_buffer->node);
			kmem_cache_free(self->tx_bufferlistpool, tx_buffer);
			self->tx_proc_cnt++;
			if (unlikely(IS_DRIVER_VENDOR_CMD(pMsg->MsgId))) {
				if (driver_to_mcu == ST_ENTER) {
					driver_to_mcu = ST_EXIT;
					break;
				}
			}
			if (scatters >= bes_sdio_tx_multiple_num) {
				break;
			}
		}
flush_previous:
		if (likely(scatters)) {
			if (WARN_ON(total_len & 0x3))
				break;
			else
				total_len |= (cur_blk - 1);
			sdio_claim_host(self->func);
			if (self->retune_protected == false) {
				sdio_retune_hold_now(self->func);
				self->retune_protected = true;
			}
			do {
				ret = bes_sdio_memcpy_to_io_helper(self->func, total_len, sg, scatters);
				if (likely(ret != -84)) {
					crc_retry = 0;
					break;
				} else {
					crc_retry++;
					bes2600_err(BES2600_DBG_SDIO, "%s sdio write crc error(%d)\n", __func__, crc_retry);
				}
			} while (crc_retry <= 10);
			sdio_release_host(self->func);
			queue_work(self->sdio_wq, &self->rx_work);
			if (ret) {
				bes2600_err(BES2600_DBG_SDIO, "%s,%d err=%d,%d,%d\n", __func__, __LINE__, ret, scatters, cur_blk);
				sdio_work_debug(self);
				bes2600_chrdev_wifi_force_close(self->core);
			}
			scatters = 0;
			total_len = 0;
			cur_blk = 0;
			self->tx_xfer_cnt++;
			self->last_tx_data_timestamp = jiffies;
		}
	}
}

static int bes2600_sdio_pipe_send(struct sbus_priv *self, u8 pipe, u32 len, u8 *buf)
{
	struct bes_sdio_tx_list_t * desc = NULL;

	if(bes2600_chrdev_is_bus_error()) {
		bes2600_tx_loop_pipe_send(self->core, buf, len);
		return 0;
	}

	desc = kmem_cache_alloc(self->tx_bufferlistpool, GFP_KERNEL);
	if (!desc)
		return -ENOMEM;
	INIT_LIST_HEAD(&desc->node);
	desc->buf = buf;
	desc->len = len;
	if (!buf || !len)
		return -EINVAL;

	spin_lock(&self->tx_bufferlock);
	list_add_tail(&desc->node, &self->tx_bufferlist);
	self->tx_data_cnt++;
	spin_unlock(&self->tx_bufferlock);
	queue_work(self->sdio_wq, &self->tx_work);
	return 0;

}
#endif

static int bes2600_sdio_misc_init(struct sbus_priv *self, struct bes2600_common *ar)
{
#ifdef BES_SDIO_RXTX_TOGGLE
	self->rx_data_toggle = 0;
	self->tx_data_toggle = 0;
	self->next_toggle = 0;
#endif
#ifdef BES_SDIO_RX_MULTIPLE_ENABLE
	spin_lock_init(&self->rx_queue_lock);
	skb_queue_head_init(&self->rx_queue);
	self->rx_buffer = (u8 *)__get_dma_pages(GFP_KERNEL, get_order(1632 * BES_SDIO_RX_MULTIPLE_NUM));
	if (!self->rx_buffer)
		return -ENOMEM;
	INIT_WORK(&self->rx_work, sdio_rx_work);
#endif
#ifdef BES_SDIO_TX_MULTIPLE_ENABLE
	INIT_LIST_HEAD(&self->tx_bufferlist);
	spin_lock_init(&self->tx_bufferlock);
	self->tx_buffer = (u8 *)kmalloc(512, GFP_KERNEL);
	if (!self->tx_buffer) {
		goto err2;
	}
	self->tx_bufferlistpool = kmem_cache_create("sdio_tx_bufferlistpool", sizeof(struct bes_sdio_tx_list_t), 0, SLAB_HWCACHE_ALIGN, NULL);
	if (!self->tx_bufferlistpool)
		goto err1;
	self->sdio_wq = alloc_workqueue("bes_sdio", WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_CPU_INTENSIVE, 2);
	if (!self->sdio_wq)
		goto err0;
	INIT_WORK(&self->tx_work, sdio_tx_work);
	return 0;
err0:
	kmem_cache_destroy(self->tx_bufferlistpool);
err1:
	kfree(self->tx_buffer);
err2:
	free_pages((unsigned long)self->rx_buffer, get_order(1632 * BES_SDIO_RX_MULTIPLE_NUM));
	return -ENOMEM;
#endif
	return 0;
}

#if defined(PLAT_ALLWINNER) || defined (PLAT_ROCKCHIP) || defined(PLAT_GENERIC)
static struct bes2600_platform_data_sdio bes_sdio_plat_data = {
#if defined(BES2600_INDEPENDENT_EVB)
	.reset = GPIOA(9),
	.powerup = GPIOC(3),
	.wakeup = -1,
#elif defined(BES2600_INTEGRATED_MODULE_V1)
	.reset = GPIOA(0),
	.powerup = -1,
	.wakeup = -1,
#elif defined(BES2600_INTEGRATED_MODULE_V2)
	.reset = GPIOM(2),
	.powerup = -1,
	.wakeup = GPIOM(5),
#elif defined(PLAT_ROCKCHIP)
	.reset = -1,
	.powerup = -1,
	.wakeup = -1,
#elif defined(PLAT_GENERIC)
	.reset = -1,
	.powerup = -1,
	.wakeup = -1,
#endif
};
#endif

struct bes2600_platform_data_sdio *bes2600_get_platform_data(void)
{
#if defined(PLAT_ALLWINNER) || defined(PLAT_ROCKCHIP) || defined(PLAT_GENERIC)
	return &bes_sdio_plat_data;
#else
	return NULL;
#endif
}

static void bes2600_get_gpio_from_dts(int *gpio_num, const char *gpio_name)
{
	int wakeup_gpio;
	enum of_gpio_flags flags;
	struct device_node *wireless_node;
	wireless_node = of_find_node_with_property(NULL, gpio_name);
	if(wireless_node != NULL){
		wakeup_gpio = of_get_named_gpio_flags(wireless_node, gpio_name, 0, &flags);
		if (gpio_is_valid(wakeup_gpio))
			*gpio_num = wakeup_gpio;
	}else{
		bes2600_err(BES2600_DBG_SDIO, "find node for %s failed\n", gpio_name);
	}
}

static int bes2600_platform_data_init(void)
{
	int ret = 0;
	struct bes2600_platform_data_sdio *pdata = bes2600_get_platform_data();
	if (pdata == NULL)
		return 0;

		/* Ensure I/Os are pulled low */
	if (gpio_is_valid(pdata->reset)) {
		ret = gpio_request(pdata->reset, "bes2600_wlan_reset");
		if (ret) {
			bes2600_err(BES2600_DBG_SDIO, "can't reqest reset_gpio:%d\n", ret);
			goto exit;
		} else {
			gpio_direction_output(pdata->reset, 0);
		}
	} else {
		bes2600_err(BES2600_DBG_SDIO, "reset is invalid\n");
	}

	bes2600_get_gpio_from_dts(&pdata->powerup, "WIFI,poweren_gpio");
	if (gpio_is_valid(pdata->powerup)) {
		ret = gpio_request(pdata->powerup, "bes2600_wlan_powerup");
		if (ret) {
			bes2600_err(BES2600_DBG_SDIO, "can't request powerup_gpio:%d\n", ret);
			goto exit;
		} else {
			gpio_direction_output(pdata->powerup, 0);
		}
	} else {
		bes2600_err(BES2600_DBG_SDIO, "powerup is invalid\n");
	}

	bes2600_get_gpio_from_dts(&pdata->wakeup, "WIFI,host_wakeup_wifi");
	if (gpio_is_valid(pdata->wakeup)) {
		ret = gpio_request(pdata->wakeup, "bes2600_wakeup");
		if (ret) {
			bes2600_err(BES2600_DBG_SDIO, "can't request wakeup_gpio:%d\n", ret);
			goto exit;
		} else {
			gpio_direction_output(pdata->wakeup, 0);
		}
	} else {
		bes2600_err(BES2600_DBG_SDIO, "wakeup is invalid\n");
	}

	bes2600_get_gpio_from_dts(&pdata->host_wakeup, "WIFI,host_wake_irq");
	if (gpio_is_valid(pdata->host_wakeup)) {
		ret = gpio_request(pdata->host_wakeup, "bes2600_host_irq");
		if (ret) {
			bes2600_err(BES2600_DBG_SDIO, "can't reqest host_wake_gpio:%d\n", ret);
			goto exit;
		} else {
			gpio_direction_input(pdata->host_wakeup);
		}
	} else {
		bes2600_err(BES2600_DBG_SDIO, "host_wakeup is invalid\n");
	}

	pdata->wlan_bt_hostwake_registered = false;
exit:
	return ret;
}

static void bes2600_platform_data_deinit(void)
{
	const struct bes2600_platform_data_sdio *pdata = bes2600_get_platform_data();
	if (pdata == NULL) {
		return;
	}

	if (gpio_is_valid(pdata->reset)) {
		gpio_free(pdata->reset);
	}
	if (gpio_is_valid(pdata->powerup)) {
		gpio_free(pdata->powerup);
	}
	if (gpio_is_valid(pdata->wakeup)) {
		gpio_free(pdata->wakeup);
	}
	if (gpio_is_valid(pdata->host_wakeup)) {
		gpio_free(pdata->host_wakeup);
	}
}

static int bes2600_sdio_reset(struct sbus_priv *self)
{
	const struct bes2600_platform_data_sdio *plat_data = bes2600_get_platform_data();

	bes2600_info(BES2600_DBG_SDIO, "%s ...\n", __func__);

	if (plat_data == NULL)
		return 0;

	if (plat_data->reset) {
		gpio_set_value(plat_data->reset, 1);
		mdelay(50);
		gpio_set_value(plat_data->reset, 0);
	}
	return 0;
}

static int bes2600_sdio_readb_safe(struct sdio_func *func, unsigned int addr)
{
	int ret = 0;
	u8 val = 0;
	u8 retry = 0;

	do {
		val = sdio_readb(func, addr, &ret);
	} while((ret < 0) && ++retry < 30);

	bes2600_err_with_cond(ret, BES2600_DBG_SDIO, "%s failed, ret:%d\n", __func__, ret);

	return (ret < 0) ? ret : val;
}

static int bes2600_sdio_writeb_safe(struct sdio_func *func, unsigned int addr, u8 val)
{
	int ret;
	u8 retry = 0;

	do {
		sdio_writeb(func, val, addr, &ret);
	} while((ret < 0) && ++retry < 30);

	bes2600_err_with_cond(ret, BES2600_DBG_SDIO, "%s failed, ret:%d\n", __func__, ret);

	return ret;
}

static void bes2600_gpio_wakeup_mcu(struct sbus_priv *self, int flag)
{
	bool gpio_wakeup = false;
	const struct bes2600_platform_data_sdio *pdata = bes2600_get_platform_data();
	if (pdata == NULL)
		return;

	bes2600_dbg(BES2600_DBG_SDIO, "%s with %d\n", __func__, flag);

	mutex_lock(&self->io_mutex);

	/* error check */
	if((self->gpio_wakup_flags & BIT(flag)) != 0) {
		bes2600_err(BES2600_DBG_SDIO,
			"repeat set gpio_wake_flag, sub_sys:%d", flag);
		mutex_unlock(&self->io_mutex);
		return;
	}

	/* check if this is the first subsystem that need mcu to keep awake */
	gpio_wakeup = (self->gpio_wakup_flags == 0);

	/* do wakeup mcu operation */
	if(gpio_wakeup) {
		bes2600_dbg(BES2600_DBG_SDIO, "pull high gpio by flag:%d\n", flag);
		if (gpio_is_valid(pdata->wakeup)) {
			gpio_set_value(pdata->wakeup, 1);
			msleep(2);
		} else {
			bes2600_err(BES2600_DBG_SDIO,
				"%s, wakeup gpio is invalid\n", __func__);
		}
	}

	/* set flag of gpio_wakeup_flags */
	self->gpio_wakup_flags |= BIT(flag);

	mutex_unlock(&self->io_mutex);
}

static void bes2600_gpio_allow_mcu_sleep(struct sbus_priv *self, int flag)
{
	bool gpio_sleep = false;
	const struct bes2600_platform_data_sdio *pdata = bes2600_get_platform_data();
	if (pdata == NULL)
		return;

	bes2600_dbg(BES2600_DBG_SDIO, "%s with %d\n", __func__, flag);

	mutex_lock(&self->io_mutex);

	/* error check */
	if((self->gpio_wakup_flags & BIT(flag)) == 0) {
		bes2600_err(BES2600_DBG_SDIO,
			"repeat clear gpio_wake_flag, sub_sys:%d", flag);
		mutex_unlock(&self->io_mutex);
		return;
	}

	/* clear flag of gpio_wakeup_flags */
	self->gpio_wakup_flags &= ~BIT(flag);

	/* check if this is the last subsystem that need mcu to keep awake */
	gpio_sleep = (self->gpio_wakup_flags == 0);

	/* do wakeup mcu operation */
	if(gpio_sleep) {
		bes2600_dbg(BES2600_DBG_SDIO, "pull low gpio by flag:%d\n", flag);
		if (gpio_is_valid(pdata->wakeup)) {
			gpio_set_value(pdata->wakeup, 0);
		} else {
			bes2600_err(BES2600_DBG_SDIO,
				"%s, wakeup gpio is invalid\n", __func__);
		}
	}

	mutex_unlock(&self->io_mutex);
}

int bes2600_sdio_active(struct sbus_priv *self, int sub_system)
{
	u16 cfg;
	u8 cfm = 0;
	int ret = 0, retries = 0;
	u8 tmp_val = 0;
	u32 cnt = 0;
	u32 delay_cnt = 2;

	/* nosignal mode only allow SUBSYSTEM_WIFI */
	if (!bes2600_chrdev_is_signal_mode() && sub_system != SUBSYSTEM_WIFI)
		return -EINVAL;

	/* don't read/write sdio when sdio error */
	if(bes2600_chrdev_is_bus_error())
		return 0;

	/* prevent concurrent access */
	mutex_lock(&self->sbus_mutex);

	/* set config and confirm value */
	if (sub_system == SUBSYSTEM_MCU) {
		cfg = BES_HOST_INT | BES_SUBSYSTEM_MCU_ACTIVE;
		cfm = BES_SLAVE_STATUS_MCU_WAKEUP_READY;
		delay_cnt = 2;
	} else if (sub_system == SUBSYSTEM_WIFI) {
		cfg = BES_HOST_INT | BES_SUBSYSTEM_WIFI_ACTIVE;
		cfm = BES_SLAVE_STATUS_WIFI_READY;
		delay_cnt = 25;
	} else if(sub_system == SUBSYSTEM_BT) {
		cfg = BES_HOST_INT | BES_SUBSYSTEM_BT_ACTIVE;
		cfm = BES_SLAVE_STATUS_BT_READY;
		delay_cnt = 25;
	} else if(sub_system == SUBSYSTEM_BT_LP) {
		cfg = BES_HOST_INT | BES_SUBSYSTEM_BT_WAKEUP;
		cfm = BES_SLAVE_STATUS_BT_WAKE_READY;
		delay_cnt = 2;
	} else {
		mutex_unlock(&self->sbus_mutex);
		return -EINVAL;
	}

	/* set fw_started flag in advance */
	if(sub_system == SUBSYSTEM_WIFI) {
		self->fw_started = true;
	}

	/* wait until device ready */
	do {
		sdio_claim_host(self->func);
		ret = bes2600_sdio_readb_safe(self->func, BES_SLAVE_STATUS_REG_ID);
		sdio_release_host(self->func);
		bes2600_dbg(BES2600_DBG_SDIO, "active wait mcu ready cnt:%d, reg:%d\n", cnt++, ret);
		if(ret < 0) {
			goto err;
		}
	} while((ret & BES_SLAVE_STATUS_MCU_READY) == 0);

	do {
		/* claim sdio host */
		sdio_claim_host(self->func);

		/* write first segment */
		tmp_val = (cfg >> 8) & 0xff;
		ret = bes2600_sdio_writeb_safe(self->func, BES_HOST_INT_REG_ID + 1, tmp_val);
		if(ret < 0) {
			sdio_release_host(self->func);
			bes2600_err(BES2600_DBG_SDIO, "active write 1st seg failed\n");
			goto err;
		}

		/* write second segment */
		tmp_val = cfg & 0xff;
		ret = bes2600_sdio_writeb_safe(self->func, BES_HOST_INT_REG_ID, tmp_val);
		if(ret < 0) {
			sdio_release_host(self->func);
			bes2600_err(BES2600_DBG_SDIO, "active write 2nd seg failed\n");
			goto err;
		}

		/* release sdio host */
		sdio_release_host(self->func);

		/* wait device to response */
		msleep(delay_cnt);

		/* read device response result */
		sdio_claim_host(self->func);
		ret = bes2600_sdio_readb_safe(self->func, BES_SLAVE_STATUS_REG_ID);
		sdio_release_host(self->func);
		if(ret < 0) {
			bes2600_err(BES2600_DBG_SDIO, "active read response failed\n");
			goto err;
		}
		bes2600_dbg(BES2600_DBG_SDIO, "active resp cnt:%d, reg:%d, sub_sys:%d\n", retries, ret, sub_system);
	} while ((cfm != 0) && (ret & cfm) == 0 && ++retries <= 200);	// check if cfm bit is set

	if (retries > 200) {
		bes2600_err(BES2600_DBG_SDIO, "bes2600_sdio_active failed, subsys:%d\n", sub_system);
		/* open wifi failed, restore fw_started flag */
		if(sub_system == SUBSYSTEM_WIFI) {
			self->fw_started = false;
		}

		mutex_unlock(&self->sbus_mutex);
		return -EFAULT;
	} else {
		ret = 0;
	}

#ifdef BES2600_GPIO_WAKEUP_AP
	if (sub_system == SUBSYSTEM_WIFI ||
		sub_system == SUBSYSTEM_BT)
		ret = bes2600_gpio_wakeup_ap_config(self);
#else
	ret = 0;
#endif
	/* prevent concurrent access */
	mutex_unlock(&self->sbus_mutex);

	return ret;
err:
	mutex_unlock(&self->sbus_mutex);
	bes2600_chrdev_wifi_force_close(self->core);
	return -ENODEV;
}

static void bes2600_sdio_empty_work(struct sbus_priv *self)
{
#ifdef BES_SDIO_RX_MULTIPLE_ENABLE
	struct sk_buff *skb;
#endif
#ifdef BES_SDIO_TX_MULTIPLE_ENABLE
	struct bes_sdio_tx_list_t *tx_buffer, *temp;
#endif

#ifdef BES_SDIO_RX_MULTIPLE_ENABLE
	cancel_work_sync(&self->rx_work);
	while (1) {
		skb = skb_dequeue(&self->rx_queue);
		if (skb)
			dev_kfree_skb(skb);
		else
			break;
	}
	self->rx_last_ctrl = 0;
	self->rx_total_ctrl_cnt = 0;
	self->rx_continuous_ctrl_cnt = 0;
	self->rx_remain_ctrl_cnt = 0;
	self->rx_zero_ctrl_cnt = 0;
	self->rx_data_cnt = 0;
	self->rx_xfer_cnt = 0;
	self->rx_proc_cnt = 0;
#endif

#ifdef BES_SDIO_TX_MULTIPLE_ENABLE
	cancel_work_sync(&self->tx_work);
	list_for_each_entry_safe(tx_buffer, temp, &self->tx_bufferlist, node) {
		list_del_init(&tx_buffer->node);
		kmem_cache_free(self->tx_bufferlistpool, tx_buffer);
	}
	self->tx_data_cnt = 0;
	self->tx_xfer_cnt = 0;
	self->tx_proc_cnt = 0;
#endif

#ifdef BES_SDIO_RXTX_TOGGLE
	self->rx_data_toggle = 0;
	self->tx_data_toggle = 0;
	self->next_toggle = 0;
#endif
}

#ifdef BES2600_GPIO_WAKEUP_AP
static void bes2600_wlan_bt_hostwake_unregister(void);
#endif

int bes2600_sdio_deactive(struct sbus_priv *self, int sub_system)
{
	u16 cfg = 0;
	u8 cfm = 0;
	u8 tmp_val = 0;
	u16 retries = 0;
	u32 cnt = 0;
	u32 delay_cnt = 2;
	int ret;

	/* don't read/write sdio when sdio error */
	if(bes2600_chrdev_is_bus_error())
		return 0;

	/* notify device deactive event */
	if (bes2600_chrdev_is_signal_mode()) {
		/* prevent concurrent access */
		mutex_lock(&self->sbus_mutex);

		/* set config and confirm value */
		if (sub_system == SUBSYSTEM_MCU) {
			cfg = BES_HOST_INT | BES_SUBSYSTEM_MCU_DEACTIVE;
			cfm = BES_SLAVE_STATUS_MCU_WAKEUP_READY;
		} else if (sub_system == SUBSYSTEM_WIFI) {
			cfg = BES_HOST_INT | BES_SUBSYSTEM_WIFI_DEACTIVE;
			cfm = BES_SLAVE_STATUS_WIFI_READY;
		} else if(sub_system == SUBSYSTEM_BT) {
			cfg = BES_HOST_INT | BES_SUBSYSTEM_BT_DEACTIVE;
			cfm = BES_SLAVE_STATUS_BT_READY;
		} else if(sub_system == SUBSYSTEM_BT_LP) {
			cfg = BES_HOST_INT | BES_SUBSYSTEM_BT_SLEEP;
			cfm = BES_SLAVE_STATUS_BT_WAKE_READY;
		} else {
			mutex_unlock(&self->sbus_mutex);
			return -EINVAL;
		}

		/* wait until device ready */
		do {
			sdio_claim_host(self->func);
			ret = bes2600_sdio_readb_safe(self->func, BES_SLAVE_STATUS_REG_ID);
			sdio_release_host(self->func);
			bes2600_dbg(BES2600_DBG_SDIO, "deactive wait mcu ready cnt:%d, reg:%d\n", cnt++, ret);

			if(ret < 0) {
				goto err;
			}
		} while((ret & BES_SLAVE_STATUS_MCU_READY) == 0);

		do {
			/* claim sdio host */
			sdio_claim_host(self->func);

			/* write first segment */
			tmp_val = (cfg >> 8) & 0xff;
			ret = bes2600_sdio_writeb_safe(self->func, BES_HOST_INT_REG_ID + 1, tmp_val);
			if(ret < 0) {
				sdio_release_host(self->func);
				bes2600_err(BES2600_DBG_SDIO, "deactive write 1st seg failed\n");
				goto err;
			}

			/* write second segment */
			tmp_val = cfg & 0xff;
			ret = bes2600_sdio_writeb_safe(self->func, BES_HOST_INT_REG_ID, tmp_val);
			if(ret < 0) {
				sdio_release_host(self->func);
				bes2600_err(BES2600_DBG_SDIO, "deactive write 2nd seg failed\n");
				goto err;
			}

			/* release sdio host */
			sdio_release_host(self->func);

			/* wait device to response */
			msleep(delay_cnt);

			/* read device response result */
			sdio_claim_host(self->func);
			ret = bes2600_sdio_readb_safe(self->func, BES_SLAVE_STATUS_REG_ID);
			sdio_release_host(self->func);
			if(ret < 0) {
				bes2600_err(BES2600_DBG_SDIO, "deactive read response failed\n");
				if (sub_system == SUBSYSTEM_MCU) {
					/* cmd52 may return error when 2600 is sleeping */
					ret = 0;
					break;
				} else {
					goto err;
				}
			}
			bes2600_dbg(BES2600_DBG_SDIO, "deactive resp cnt:%d, reg:%d, sub_sys:%d\n", retries, ret, sub_system);
		} while((cfm != 0) && (ret & cfm) != 0 && ++retries < 200);

		/* set fw_started flag to false */
		if(bes2600_chrdev_is_signal_mode()
		   && sub_system == SUBSYSTEM_WIFI)
			self->fw_started = false;

		/* reset sdio send and receive control variable */
		if(sub_system == SUBSYSTEM_WIFI) {
			bes2600_sdio_empty_work(self);
		}

		/* prevent concurrent access */
		mutex_unlock(&self->sbus_mutex);

		return (ret < 0) ? ret : 0;
	} else {
		return 0;
	}

err:
	mutex_unlock(&self->sbus_mutex);
	bes2600_chrdev_wifi_force_close(self->core);
	return -ENODEV;
}

static int bes2600_sdio_power_up(void)
{
	const struct bes2600_platform_data_sdio *pdata = bes2600_get_platform_data();
	int ret;

	ret = bes2600_sdio_on(pdata);
	if (ret)
		goto err_on;


#ifdef PLAT_ALLWINNER
	mdelay(10);
	//sw_mci_rescan_card(AW_SDIOID, 1);
	sunxi_mmc_rescan_card(sunxi_wlan_get_bus_index());
	bes2600_info(BES2600_DBG_SDIO, "%s: power up, rescan card.\n", __FUNCTION__);
#endif

	return 0;

err_on:
	return ret;
}

static void bes2600_sdio_power_down(struct sbus_priv *self)
{
#ifdef POWER_DOWN_BY_MSG
	u32 cfg = BES_HOST_INT | BES_SUBSYSTEM_SYSTEM_CLOSE;
	u8 tmp_val = 0;
	int ret = 0;

	sdio_claim_host(self->func);
	tmp_val = (cfg >> 8) & 0xff;
	sdio_writeb(self->func, tmp_val, BES_HOST_INT_REG_ID + 1, &ret);
	tmp_val = cfg & 0xff;
	sdio_writeb(self->func, tmp_val, BES_HOST_INT_REG_ID, &ret);
	sdio_release_host(self->func);
#else
#if defined(PLAT_ROCKCHIP)
	rockchip_wifi_power(0);
#endif

#if defined(PLAT_ALLWINNER)
	sunxi_wlan_set_power(false);
#endif

#if defined(PLAT_GENERIC)
	gpio_direction_output(self->pdata->powerup, 0);
#endif
#endif

	msleep(10);

	self->func->card->host->caps &= ~MMC_CAP_NONREMOVABLE;
	schedule_work(&self->sdio_scan_work);

}

static int bes2600_sdio_power_switch(struct sbus_priv *self, int on)
{
	int ret = 0;
	if(on) {
		ret = bes2600_sdio_power_up();
	} else {
		bes2600_sdio_power_down(self);
	}

	return ret;
}

static struct sbus_ops bes2600_sdio_sbus_ops = {
	.sbus_memcpy_fromio	= bes2600_sdio_memcpy_fromio,
	.sbus_memcpy_toio	= bes2600_sdio_memcpy_toio,
	.lock			= bes2600_sdio_lock,
	.unlock			= bes2600_sdio_unlock,
	.irq_subscribe		= bes2600_sdio_irq_subscribe,
	.irq_unsubscribe	= bes2600_sdio_irq_unsubscribe,
	.reset			= bes2600_sdio_reset,
	.align_size		= bes2600_sdio_align_size,
	.set_block_size		= bes2600_sdio_set_block_size,
	.sbus_reg_read		= bes2600_sdio_reg_read,
	.sbus_reg_write		= bes2600_sdio_reg_write,
	.init				= bes2600_sdio_misc_init,
#ifdef BES_SDIO_RX_MULTIPLE_ENABLE
	.pipe_read			= bes2600_sdio_pipe_read,
#endif
#ifdef BES_SDIO_TX_MULTIPLE_ENABLE
	.pipe_send			= bes2600_sdio_pipe_send,
#endif
	.sbus_active        = bes2600_sdio_active,
	.sbus_deactive      = bes2600_sdio_deactive,
	.power_switch       = bes2600_sdio_power_switch,
	.gpio_wake	    = bes2600_gpio_wakeup_mcu,
	.gpio_sleep         = bes2600_gpio_allow_mcu_sleep,
};

static void bes2600_sdio_en_lp_cb(struct bes2600_common *hw_priv)
{
	long unsigned int old_ts, new_ts;
	struct sbus_priv *self = hw_priv->sbus_priv;

	do {
		old_ts = self->last_irq_timestamp;
		flush_work(&self->rx_work);
		new_ts = self->last_irq_timestamp;
	} while(old_ts != new_ts);
}

/* Probe Function to be called by SDIO stack when device is discovered */
static int bes2600_sdio_probe(struct sdio_func *func,
			      const struct sdio_device_id *id)
{
	struct sbus_priv *self;
	int status;

	bes2600_info(BES2600_DBG_SDIO, "Probe called:%p,%d\n", func, func->num);
	if (func->num > 1)
		return 0;

	func->card->host->caps |= MMC_CAP_NONREMOVABLE;

	self = kzalloc(sizeof(*self), GFP_KERNEL);
	if (!self) {
		bes2600_dbg(BES2600_DBG_SDIO, "Can't allocate SDIO sbus_priv.");
		return -ENOMEM;
	}
#ifdef PLAT_ALLWINNER_SUN6I
	aw_gpio_irq_handle = 0;
#endif
	spin_lock_init(&self->lock);
	self->pdata = bes2600_get_platform_data();
	self->func = func;
	self->dev = &func->dev;
	self->gpio_wakup_flags = 0;
	self->retune_protected = false;
	mutex_init(&self->io_mutex);
	mutex_init(&self->sbus_mutex);
	INIT_WORK(&self->sdio_scan_work, sdio_scan_work);
#ifdef BES_SDIO_RXTX_TOGGLE
	self->fw_started = false;
#endif
	bes2600_gpio_wakeup_mcu(self, GPIO_WAKE_FLAG_SDIO_PROBE);

	sdio_set_drvdata(func, self);
	sdio_claim_host(func);
	sdio_enable_func(func);
	sdio_release_host(func);

	bes2600_reg_set_object(&bes2600_sdio_sbus_ops, self);
	status = bes2600_load_firmware(&bes2600_sdio_sbus_ops, self);
	bes2600_info_with_cond((status > 0), BES2600_DBG_SDIO,
			"interrupt init process beacuse device be closed.\n");
	if(status > 0)	// for wifi closed case
		goto out;
	else if(status < 0)	// for download fail case
		goto err;

	status = bes2600_register_net_dev(self);
	if (status) {
		goto err;
	}

out:
	bes2600_chrdev_set_sbus_priv_data(self);
	bes2600_gpio_allow_mcu_sleep(self, GPIO_WAKE_FLAG_SDIO_PROBE);
	return 0;

err:
	bes2600_err(BES2600_DBG_SDIO, "%s failed, func:%d\n", __func__, func->num);
	func->card->host->caps &= ~MMC_CAP_NONREMOVABLE;
	sdio_claim_host(func);
	sdio_disable_func(func);
	sdio_release_host(func);
	bes2600_gpio_allow_mcu_sleep(self, GPIO_WAKE_FLAG_SDIO_PROBE);
	sdio_set_drvdata(func, NULL);
	bes2600_reg_set_object(NULL, NULL);
	bes2600_chrdev_set_sbus_priv_data(NULL);
	kfree(self);
	return 0;
}

int bes2600_register_net_dev(struct sbus_priv *bus_priv)
{
	int status = 0;
	BUG_ON(!bus_priv);
	status = bes2600_core_probe(&bes2600_sdio_sbus_ops,
			      bus_priv, bus_priv->dev, &bus_priv->core);
	if(!status)
		bes2600_pwr_register_en_lp_cb(bus_priv->core, bes2600_sdio_en_lp_cb);

	return status;
}

int bes2600_unregister_net_dev(struct sbus_priv *bus_priv)
{
	BUG_ON(!bus_priv);
	if (bus_priv->core) {
		bes2600_core_release(bus_priv->core);
		bes2600_pwr_unregister_en_lp_cb(bus_priv->core, bes2600_sdio_en_lp_cb);
		bus_priv->core = NULL;

		if (bus_priv->sdio_wq) {
			flush_workqueue(bus_priv->sdio_wq);
			destroy_workqueue(bus_priv->sdio_wq);
			bus_priv->sdio_wq = NULL;
		}

		if (bus_priv->rx_buffer) {
			free_pages((unsigned long)bus_priv->rx_buffer, get_order(1632 * BES_SDIO_RX_MULTIPLE_NUM));
			bus_priv->rx_buffer = NULL;
		}

#ifdef BES_SDIO_TX_MULTIPLE_ENABLE
		if (bus_priv->tx_buffer) {
			kfree(bus_priv->tx_buffer);
			bus_priv->tx_buffer = NULL;
		}

		if (bus_priv->tx_bufferlistpool) {
			kmem_cache_destroy(bus_priv->tx_bufferlistpool);
			bus_priv->tx_bufferlistpool = NULL;
		}
#endif
	}
	return 0;
}

bool bes2600_is_net_dev_created(struct sbus_priv *bus_priv)
{
	BUG_ON(!bus_priv);
	return (bus_priv->core != NULL);
}

/* Disconnect Function to be called by SDIO stack when
 * device is disconnected */
static void bes2600_sdio_disconnect(struct sdio_func *func)
{
	struct sbus_priv *self = sdio_get_drvdata(func);
	const struct bes2600_platform_data_sdio *pdata = bes2600_get_platform_data();

	func->card->host->caps &= ~MMC_CAP_NONREMOVABLE;
	bes2600_info(BES2600_DBG_SDIO, "%s called:%p,%d\n", __func__, func, func->num);

	if (self) {
		bes2600_unregister_net_dev(self);
#ifndef CONFIG_BES2600_USE_GPIO_IRQ
		sdio_claim_host(func);
		sdio_release_irq(func);
		sdio_release_host(func);
#else
		free_irq(irq->start, self);
#endif  //CONFIG_BES2600_USE_GPIO_IRQ
		sdio_claim_host(func);
		sdio_disable_func(func);
		sdio_release_host(func);
		bes2600_sdio_off(pdata);
		bes2600_reg_set_object(NULL, NULL);
		bes2600_chrdev_set_sbus_priv_data(NULL);
		sdio_set_drvdata(func, NULL);
		if (self->retune_protected == true) {
			sdio_retune_release(func);
		}
		kfree(self);
	}
}

#ifdef BES2600_GPIO_WAKEUP_AP

#if defined(PLAT_ALLWINNER)
extern int sunxi_wlan_get_oob_irq_flags(void);
extern int sunxi_wlan_get_oob_irq(void);
#elif defined(PLAT_ROCKCHIP)
extern int rockchip_wifi_get_oob_irq_flag(void);
extern int rockchip_wifi_get_oob_irq(void);
#endif

static irqreturn_t bes2600_wlan_bt_hostwake_thread(int irq, void *dev_id)
{
	struct bes2600_platform_data_sdio *pdata = bes2600_get_platform_data();

	bes2600_info(BES2600_DBG_SDIO, "bes2600_wlan_hostwake:%d\n", dev_id == (void *)pdata);

	if (dev_id == (void *)pdata) {
		pdata->wlan_bt_hostwake_registered = false;
		free_irq(irq, dev_id);
		return IRQ_HANDLED;
	} else {
		return IRQ_NONE;
	}
}

static int bes2600_wlan_bt_hostwake_register(void)
{
	int ret = 0;
	struct bes2600_platform_data_sdio *pdata = bes2600_get_platform_data();

#if defined(PLAT_ALLWINNER)
	int irq_flags = sunxi_wlan_get_oob_irq_flags();
	int irq = sunxi_wlan_get_oob_irq();
#elif defined(PLAT_ROCKCHIP)
	int irq_flags = rockchip_wifi_get_oob_irq_flag();
	int irq = rockchip_wifi_get_oob_irq();
#endif

	if (pdata->wlan_bt_hostwake_registered == true) {
		bes2600_err(BES2600_DBG_SDIO, "wlan hostwake register repeatedly.\n");
		return -1;
	}

#if defined(PLAT_ALLWINNER) || defined(PLAT_ROCKCHIP)
	irq_flags |= IRQF_ONESHOT;
	ret = request_threaded_irq(irq, NULL, bes2600_wlan_bt_hostwake_thread,
		irq_flags, "bes2600_wlan_hostwake", pdata);
	if (ret) {
		bes2600_err(BES2600_DBG_SDIO, "request_irq failed with %d\n", ret);
		return ret;
	}
#endif

	pdata->wlan_bt_hostwake_registered = true;
	return ret;
}

static void bes2600_wlan_bt_hostwake_unregister(void)
{
	struct bes2600_platform_data_sdio *pdata = bes2600_get_platform_data();

#if defined(PLAT_ALLWINNER)
	int irq = sunxi_wlan_get_oob_irq();
#elif defined(PLAT_ROCKCHIP)
	int irq = rockchip_wifi_get_oob_irq();
#endif

	if (pdata->wlan_bt_hostwake_registered == false)
		return;

	pdata->wlan_bt_hostwake_registered = false;
#if defined(PLAT_ALLWINNER) || defined(PLAT_ROCKCHIP)
	free_irq(irq, pdata);
#endif
}

static int bes2600_gpio_wakeup_ap_config(struct sbus_priv *self)
{
	u8 wakeup_cfg = 0;
	int ret = 0, irq_flags = 0, irq = 0;

    if (!bes2600_chrdev_is_signal_mode())
        return 0;

#if defined(PLAT_ALLWINNER)
	irq_flags = sunxi_wlan_get_oob_irq_flags();
	irq = sunxi_wlan_get_oob_irq();
#elif defined(PLAT_ROCKCHIP)
	irq_flags = rockchip_wifi_get_oob_irq_flag();
	irq = rockchip_wifi_get_oob_irq();
#endif

	if (irq_flags & IRQF_TRIGGER_HIGH) {
		wakeup_cfg = BES_AP_WAKEUP_GPIO_HIGH | BES_AP_WAKEUP_CFG_VALID;
	} else if (irq_flags & IRQF_TRIGGER_LOW) {
		wakeup_cfg = BES_AP_WAKEUP_GPIO_LOW | BES_AP_WAKEUP_CFG_VALID;
	} else if (irq_flags & IRQF_TRIGGER_RISING) {
		wakeup_cfg = BES_AP_WAKEUP_GPIO_RISE | BES_AP_WAKEUP_CFG_VALID;
	} else if (irq_flags & IRQF_TRIGGER_FALLING) {
		wakeup_cfg = BES_AP_WAKEUP_GPIO_FALL | BES_AP_WAKEUP_CFG_VALID;
	}

	if (wakeup_cfg & BES_AP_WAKEUP_CFG_VALID)
		wakeup_cfg |= (BES_AP_WAKEUP_TYPE_GPIO << BES_AP_WAKEUP_TYPE_SHIFT);

	bes2600_info(BES2600_DBG_SDIO, "%s config:%x\n", __func__, wakeup_cfg);

	sdio_claim_host(self->func);
	sdio_writeb(self->func, wakeup_cfg, BES_AP_WAKEUP_REG_ID, &ret);
	if (!ret) {
		sdio_writeb(self->func, 0, BES_HOST_INT_REG_ID + 1, &ret);
	}
	if (!ret) {
		sdio_writeb(self->func, (BES_HOST_INT | BES_AP_WAKEUP_CFG), BES_HOST_INT_REG_ID, &ret);
	}
	sdio_release_host(self->func);
	if (ret) {
		bes2600_err(BES2600_DBG_SDIO, "%s failed:%d\n", __func__, ret);
		free_irq(irq, &bes_sdio_plat_data);
		return ret;
	}

	return 0;
}
#endif

int bes2600_sdio_prepare(struct device *dev)
{
	struct sdio_func *func = dev_to_sdio_func(dev);
	struct sbus_priv *self = sdio_get_drvdata(func);

	bes2600_info(BES2600_DBG_SDIO, "%s (%p,%d)enter\n", __func__, func, func->num);

	if (func->num > 1)
		return 0;

	if(bes2600_sdio_sbus_ops.gpio_wake)
		bes2600_sdio_sbus_ops.gpio_wake(self, GPIO_WAKE_FLAG_HOST_SUSPEND);

	return 0;
}

static int bes2600_sdio_suspend(struct device *dev)
{
	int ret;
	struct sdio_func *func = dev_to_sdio_func(dev);
	struct sbus_priv *self = sdio_get_drvdata(func);

	bes2600_info(BES2600_DBG_SDIO, "%s (%p,%d)enter\n", __func__, func, func->num);
	if (func->num > 1)
		return 0;

#ifndef CONFIG_BES2600_WOWLAN
	if(bes2600_chrdev_check_system_close() == false)
		return -EBUSY;
#endif

	/* Notify SDIO that BES2600 will remain powered during suspend */
	ret = sdio_set_host_pm_flags(func, MMC_PM_KEEP_POWER);
	if (ret) {
		bes2600_err(BES2600_DBG_PM, "Error setting SDIO pm flags: %i\n", ret);
		return ret;
	}

	if (bes2600_chrdev_is_bt_opened() == true) {
		if ((ret = bes2600_sdio_deactive(self, SUBSYSTEM_BT_LP))) {
			bes2600_err(BES2600_DBG_PM, "bt sleep in suspend failed:%d.\n", ret);
			return ret;
		}
	}

#ifdef BES2600_GPIO_WAKEUP_AP
	return bes2600_wlan_bt_hostwake_register();
#endif

	return 0;
}

static int bes2600_sdio_suspend_noirq(struct device *dev)
{
	struct sdio_func *func = dev_to_sdio_func(dev);
	struct sbus_priv *self = sdio_get_drvdata(func);

	bes2600_info(BES2600_DBG_SDIO, "%s (%p,%d)enter\n", __func__, func, func->num);

	if (func->num > 1)
		return 0;

	if(self->core &&
	   (work_pending(&self->rx_work) || atomic_read(&self->core->bh_rx))) {
		bes2600_info(BES2600_DBG_SDIO, "%s: Suspend interrupted.\n", __func__);
		return -EAGAIN;
	}

	if(bes2600_sdio_sbus_ops.gpio_sleep)
		bes2600_sdio_sbus_ops.gpio_sleep(self, GPIO_WAKE_FLAG_HOST_SUSPEND);

	if (self->retune_protected == true)
		bes2600_warn(BES2600_DBG_SDIO, "retune is closed while ap sleep.\n");

	return 0;
}

int bes2600_sdio_resume_noirq(struct device *dev)
{
	struct sdio_func *func = dev_to_sdio_func(dev);
	struct sbus_priv *self = sdio_get_drvdata(func);

	bes2600_info(BES2600_DBG_SDIO, "%s (%p,%d)enter\n", __func__, func, func->num);

	if (func->num > 1)
		return 0;

	if(bes2600_sdio_sbus_ops.gpio_wake)
		bes2600_sdio_sbus_ops.gpio_wake(self, GPIO_WAKE_FLAG_HOST_RESUME);

	return 0;
}

static int bes2600_sdio_resume(struct device *dev)
{
	struct sdio_func *func = dev_to_sdio_func(dev);

	bes2600_info(BES2600_DBG_SDIO, "%s (%p,%d)enter\n", __func__, func, func->num);

	if (func->num > 1)
		return 0;

#ifdef BES2600_GPIO_WAKEUP_AP
	bes2600_wlan_bt_hostwake_unregister();
#endif

	return 0;
}

static void bes2600_sdio_complete(struct device *dev)
{
	struct sdio_func *func = dev_to_sdio_func(dev);
	struct sbus_priv *self = sdio_get_drvdata(func);

	bes2600_info(BES2600_DBG_SDIO, "%s (%p,%d)enter\n", __func__, func, func->num);

	if (func->num > 1)
		return;

	/* wakeup bt if bt is on */
	bes2600_chrdev_wakeup_bt();

	/* clear resume gpio wake flag */
	if(bes2600_sdio_sbus_ops.gpio_sleep)
		bes2600_sdio_sbus_ops.gpio_sleep(self, GPIO_WAKE_FLAG_HOST_RESUME);
}

static const struct dev_pm_ops bes2600_pm_ops = {
	.prepare = bes2600_sdio_prepare,
	.suspend = bes2600_sdio_suspend,
	.suspend_noirq = bes2600_sdio_suspend_noirq,
	.resume_noirq = bes2600_sdio_resume_noirq,
	.resume = bes2600_sdio_resume,
	.complete = bes2600_sdio_complete,
};

static struct sdio_driver sdio_driver = {
	.name		= "bes2600_wlan",
	.id_table	= bes2600_sdio_ids,
	.probe		= bes2600_sdio_probe,
	.remove		= bes2600_sdio_disconnect,
	.drv = {
		.pm = &bes2600_pm_ops,
	}
};

/* Init Module function -> Called by insmod */
static int __init bes2600_sdio_init(void)
{
	int ret;
	const struct bes2600_platform_data_sdio *pdata = NULL;

	bes2600_info(BES2600_DBG_SDIO, "------Driver: bes2600.ko version :%s\n", BES2600_DRV_VERSION);

	bes2600_chrdev_update_signal_mode();
	bes2600_dbg(BES2600_DBG_SDIO, "%s type:%d sig_mode:%d\n", __func__,
			bes2600_chrdev_get_fw_type(), bes2600_chrdev_is_signal_mode());

	if ((ret = bes2600_platform_data_init()))
		goto exit;

	pdata = bes2600_get_platform_data();

	ret = bes2600_sdio_on(pdata);
	if (ret)
		goto err_on;

	ret = bes2600_chrdev_init(&bes2600_sdio_sbus_ops);
	if(ret)
		goto err_chardev;

#ifdef PLAT_ALLWINNER
	mdelay(10);
	//sw_mci_rescan_card(AW_SDIOID, 1);
	sunxi_mmc_rescan_card(sunxi_wlan_get_bus_index());
	bes2600_info(BES2600_DBG_SDIO, "%s: power up, rescan card.\n", __FUNCTION__);
#endif

	ret = sdio_register_driver(&sdio_driver);
	if (ret)
		goto err_reg;

	return 0;

err_reg:
	bes2600_chrdev_free();
err_chardev:
	bes2600_sdio_off(pdata);
err_on:
	bes2600_platform_data_deinit();
exit:
	return ret;
}

/* Called at Driver Unloading */
static void __exit bes2600_sdio_exit(void)
{
	const struct bes2600_platform_data_sdio *pdata = bes2600_get_platform_data();
	struct sbus_priv *priv =  bes2600_chrdev_get_sbus_priv_data();
	bes2600_info(BES2600_DBG_SDIO, "%s called\n", __func__);

	sdio_unregister_driver(&sdio_driver);
	bes2600_chrdev_free();
	if(!priv) {
		bes2600_sdio_off(pdata);
	}
	bes2600_platform_data_deinit();
}

module_init(bes2600_sdio_init);
module_exit(bes2600_sdio_exit);
