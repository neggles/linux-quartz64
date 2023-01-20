/*
 * Low-level device IO routines for BES2600 drivers
 *
 * Copyright (c) 2022, Bestechnic
 * Author:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/types.h>

#include "bes2600.h"
#include "hwio.h"
#include "sbus.h"

 /* Sdio addr is 4*spi_addr */
#define SPI_REG_ADDR_TO_SDIO(spi_reg_addr) ((spi_reg_addr) << 2)
#define SDIO_ADDR17BIT(buf_id, mpf, rfu, reg_id_ofs) \
				((((buf_id)    & 0x1F) << 7) \
				| (((mpf)        & 1) << 6) \
				| (((rfu)        & 1) << 5) \
				| (((reg_id_ofs) & 0x1F) << 0))
#define MAX_RETRY		3

static struct sbus_ops *bes2600_subs_ops = NULL;
static struct sbus_priv *bes2600_sbus_priv = NULL;

static int __bes2600_reg_read(u16 addr, void *buf, size_t buf_len, int buf_id)
{
	u16 addr_sdio;
	u32 sdio_reg_addr_17bit ;

	/* Check if buffer is aligned to 4 byte boundary */
	if (WARN_ON(((unsigned long)buf & 3) && (buf_len > 4))) {
		bes2600_err(BES2600_DBG_SBUS,
			   "%s: buffer is not aligned.\n", __func__);
		return -EINVAL;
	}

	/* Convert to SDIO Register Address */
	addr_sdio = SPI_REG_ADDR_TO_SDIO(addr);
	sdio_reg_addr_17bit = SDIO_ADDR17BIT(buf_id, 0, 0, addr_sdio);

	BUG_ON(!bes2600_subs_ops);
	return bes2600_subs_ops->sbus_memcpy_fromio(bes2600_sbus_priv,
					sdio_reg_addr_17bit,
					buf, buf_len);
}

static int __bes2600_reg_write(u16 addr, const void *buf, size_t buf_len, int buf_id)
{
	u16 addr_sdio;
	u32 sdio_reg_addr_17bit ;

#if 0
	/* Check if buffer is aligned to 4 byte boundary */
	if (WARN_ON(((unsigned long)buf & 3) && (buf_len > 4))) {
		bes2600_dbg(BES2600_DBG_SBUS, "%s: buffer is not aligned.\n",
				__func__);
		return -EINVAL;
	}
#endif

	/* Convert to SDIO Register Address */
	addr_sdio = SPI_REG_ADDR_TO_SDIO(addr);
	sdio_reg_addr_17bit = SDIO_ADDR17BIT(buf_id, 0, 0, addr_sdio);

	BUG_ON(!bes2600_subs_ops);
	return bes2600_subs_ops->sbus_memcpy_toio(bes2600_sbus_priv,
					sdio_reg_addr_17bit,
					buf, buf_len);
}

static inline int __bes2600_reg_read_32(u16 addr, u32 *val)
{
	return __bes2600_reg_read(addr, val, sizeof(val), 0);
}

static inline int __bes2600_reg_write_32(u16 addr, u32 val)
{
	return __bes2600_reg_write(addr, &val, sizeof(val), 0);
}

void bes2600_reg_set_object(struct sbus_ops *ops, struct sbus_priv *priv)
{
	bes2600_subs_ops = ops;
	bes2600_sbus_priv = priv;
}

int bes2600_reg_read(u32 addr, void *buf, size_t buf_len)
{
	int ret;
	BUG_ON(!bes2600_subs_ops);
	bes2600_subs_ops->lock(bes2600_sbus_priv);
	ret = bes2600_subs_ops->sbus_reg_read(bes2600_sbus_priv, addr, buf, buf_len);
	bes2600_subs_ops->unlock(bes2600_sbus_priv);
	return ret;
}

int bes2600_reg_write(u32 addr, const void *buf, size_t buf_len)
{
	int ret;
	BUG_ON(!bes2600_subs_ops);
	bes2600_subs_ops->lock(bes2600_sbus_priv);
	ret = bes2600_subs_ops->sbus_reg_write(bes2600_sbus_priv, addr, buf, buf_len);
	bes2600_subs_ops->unlock(bes2600_sbus_priv);
	return ret;
}

int bes2600_data_read(void *buf, size_t buf_len)
{
	int ret, retry = 1;
	BUG_ON(!bes2600_subs_ops);
	bes2600_subs_ops->lock(bes2600_sbus_priv);
#ifndef CONFIG_BES2600_WLAN_BES
	{
		int buf_id_rx = hw_priv->buf_id_rx;
		while (retry <= MAX_RETRY) {
			ret = __bes2600_reg_read(hw_priv,
					ST90TDS_IN_OUT_QUEUE_REG_ID, buf,
					buf_len, buf_id_rx + 1);
			if (!ret) {
				buf_id_rx = (buf_id_rx + 1) & 3;
				hw_priv->buf_id_rx = buf_id_rx;
				break;
			} else {
				retry++;
				mdelay(1);
				bes2600_err(BES2600_DBG_SBUS, "%s,error :[%d]\n",
						__func__, ret);
			}
		}
	}
#else
	while (retry <= MAX_RETRY) {
		ret = bes2600_subs_ops->sbus_memcpy_fromio(bes2600_sbus_priv,
				BES_TX_DATA_ADDR, buf, buf_len);
		if (ret) {
			retry ++;
			mdelay(1);
			bes2600_dbg(BES2600_DBG_SBUS, "%s error :[%d]\n",
					__func__, ret);
		} else {
			break;
		}
	}
#endif
	bes2600_subs_ops->unlock(bes2600_sbus_priv);
	return ret;
}

int bes2600_data_write(const void *buf, size_t buf_len)
{
	int ret, retry = 1;
	u32 addr = 0;
#ifdef CONFIG_BES2600_WLAN_SPI
	struct HI_MSG_HDR {
		u16 MsgLen;
		u16 MsgId;
	} *pMsg;
#endif

	BUG_ON(!bes2600_subs_ops);
	bes2600_subs_ops->lock(bes2600_sbus_priv);
#ifndef CONFIG_BES2600_WLAN_BES
	{
		int buf_id_tx = hw_priv->buf_id_tx;
		while (retry <= MAX_RETRY) {
			ret = __bes2600_reg_write(hw_priv,
					ST90TDS_IN_OUT_QUEUE_REG_ID, buf,
					buf_len, buf_id_tx);
			if (!ret) {
				buf_id_tx = (buf_id_tx + 1) & 31;
				hw_priv->buf_id_tx = buf_id_tx;
				break;
			} else {
				retry++;
				mdelay(1);
				bes2600_err(BES2600_DBG_SBUS, "%s,error :[%d]\n",
						__func__, ret);
			}
		}
	}
#else
#ifdef CONFIG_BES2600_WLAN_SPI
	#define IS_DRIVER_VENDOR_CMD(X) ((X & 0x0C00) == 0x0C00)
	pMsg = (struct HI_MSG_HDR *)buf;
	if (IS_DRIVER_VENDOR_CMD(pMsg->MsgId)) {
		addr = BES_MISC_DATA_ADDR;
		pr_err("mcu message detected, %x\n", BES_MISC_DATA_ADDR);
	}
#endif
	while (retry <= MAX_RETRY) {
		ret = bes2600_subs_ops->sbus_memcpy_toio(bes2600_sbus_priv, addr, buf, buf_len);
		if (ret) {
			retry++;
			mdelay(1);
			bes2600_dbg(BES2600_DBG_SBUS, "%s,error :[%d]\n",
					__func__, ret);
		} else {
			break;
		}
	}
#endif
	bes2600_subs_ops->unlock(bes2600_sbus_priv);
	return ret;
}

int bes2600_indirect_read(u32 addr, void *buf, size_t buf_len, u32 prefetch, u16 port_addr)
{
	u32 val32 = 0;
	int i, ret;

	if ((buf_len / 2) >= 0x1000) {
		bes2600_err(BES2600_DBG_SBUS,
				"%s: Can't read more than 0xfff words.\n",
				__func__);
		WARN_ON(1);
		return -EINVAL;
		goto out;
	}

	bes2600_subs_ops->lock(bes2600_sbus_priv);
	/* Write address */
	ret = __bes2600_reg_write_32(ST90TDS_SRAM_BASE_ADDR_REG_ID, addr);
	if (ret < 0) {
		bes2600_err(BES2600_DBG_SBUS,
				"%s: Can't write address register.\n",
				__func__);
		goto out;
	}

	/* Read CONFIG Register Value - We will read 32 bits */
	ret = __bes2600_reg_read_32(ST90TDS_CONFIG_REG_ID, &val32);
	if (ret < 0) {
		bes2600_err(BES2600_DBG_SBUS,
				"%s: Can't read config register.\n",
				__func__);
		goto out;
	}

	/* Set PREFETCH bit */
	ret = __bes2600_reg_write_32(ST90TDS_CONFIG_REG_ID, val32 | prefetch);
	if (ret < 0) {
		bes2600_err(BES2600_DBG_SBUS,
				"%s: Can't write prefetch bit.\n",
				__func__);
		goto out;
	}

	/* Check for PRE-FETCH bit to be cleared */
	for (i = 0; i < 20; i++) {
		ret = __bes2600_reg_read_32(ST90TDS_CONFIG_REG_ID, &val32);
		if (ret < 0) {
			bes2600_err(BES2600_DBG_SBUS,
					"%s: Can't check prefetch bit.\n",
					__func__);
			goto out;
		}
		if (!(val32 & prefetch))
			break;

		mdelay(i);
	}

	if (val32 & prefetch) {
		bes2600_err(BES2600_DBG_SBUS,
				"%s: Prefetch bit is not cleared.\n",
				__func__);
		goto out;
	}

	/* Read data port */
	ret = __bes2600_reg_read(port_addr, buf, buf_len, 0);
	if (ret < 0) {
		bes2600_err(BES2600_DBG_SBUS,
				"%s: Can't read data port.\n",
				__func__);
		goto out;
	}

out:
	bes2600_subs_ops->unlock(bes2600_sbus_priv);
	return ret;
}

int bes2600_apb_write(u32 addr, const void *buf, size_t buf_len)
{
	int ret;

	if ((buf_len / 2) >= 0x1000) {
		bes2600_err(BES2600_DBG_SBUS,
				"%s: Can't wrire more than 0xfff words.\n",
				__func__);
		WARN_ON(1);
		return -EINVAL;
	}

	bes2600_subs_ops->lock(bes2600_sbus_priv);

	/* Write address */
	ret = __bes2600_reg_write_32(ST90TDS_SRAM_BASE_ADDR_REG_ID, addr);
	if (ret < 0) {
		bes2600_err(BES2600_DBG_SBUS,
				"%s: Can't write address register.\n",
				__func__);
		goto out;
	}

	/* Write data port */
	ret = __bes2600_reg_write(ST90TDS_SRAM_DPORT_REG_ID, buf, buf_len, 0);
	if (ret < 0) {
		bes2600_err(BES2600_DBG_SBUS, "%s: Can't write data port.\n",
				__func__);
		goto out;
	}

out:
	bes2600_subs_ops->unlock(bes2600_sbus_priv);
	return ret;
}

#if defined(BES2600_DETECTION_LOGIC)
int bes2600_ahb_write(u32 addr, const void *buf, size_t buf_len)
{
        int ret;
	bes2600_info(BES2600_DBG_SBUS,"%s: ENTER\n",__func__);
        if ((buf_len / 2) >= 0x1000) {
                bes2600_dbg(BES2600_DBG_SBUS,
                                "%s: Can't wrire more than 0xfff words.\n",
                                __func__);
                WARN_ON(1);
		bes2600_info(BES2600_DBG_SBUS, "%s:EXIT (1) \n",__func__);
                return -EINVAL;
        }

        bes2600_subs_ops->lock(bes2600_sbus_priv);

        /* Write address */
        ret = __bes2600_reg_write_32(priv, ST90TDS_SRAM_BASE_ADDR_REG_ID, addr);
        if (ret < 0) {
                bes2600_dbg(BES2600_DBG_SBUS,
                                "%s: Can't write address register.\n",
                                __func__);
                goto out;
        }

        /* Write data port */
        ret = __bes2600_reg_write(priv, ST90TDS_AHB_DPORT_REG_ID,
                                        buf, buf_len, 0);
        if (ret < 0) {
                bes2600_dbg(BES2600_DBG_SBUS, "%s: Can't write data port.\n",
                                __func__);
                goto out;
        }

out:
        bes2600_subs_ops->unlock(priv->bes2600_sbus_priv);
        return ret;
}
#endif

int __bes2600_irq_enable(int enable)
{
	return 0;
}
