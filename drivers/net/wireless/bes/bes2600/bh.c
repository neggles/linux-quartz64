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
#include <net/mac80211.h>
#include <linux/kthread.h>
#include <uapi/linux/ip.h>

#include "bes2600.h"
#include "bh.h"
#include "hwio.h"
#include "wsm.h"
#include "sbus.h"
#include "debug.h"
#include "epta_coex.h"
#include "bes_chardev.h"
#include "txrx_opt.h"

static int bes2600_bh(void *arg);

#ifdef CONFIG_BES2600_WLAN_SDIO
extern void sdio_work_debug(struct sbus_priv *self);
#endif

/* TODO: Verify these numbers with WSM specification. */
#define DOWNLOAD_BLOCK_SIZE_WR	(0x1000 - 4)
/* an SPI message cannot be bigger than (2"12-1)*2 bytes
 * "*2" to cvt to bytes */
#define MAX_SZ_RD_WR_BUFFERS	(DOWNLOAD_BLOCK_SIZE_WR*2)
#define PIGGYBACK_CTRL_REG	(2)
#define EFFECTIVE_BUF_SIZE	(MAX_SZ_RD_WR_BUFFERS - PIGGYBACK_CTRL_REG)

/* Suspend state privates */
enum bes2600_bh_pm_state {
	BES2600_BH_RESUMED = 0,
	BES2600_BH_SUSPEND,
	BES2600_BH_SUSPENDED,
	BES2600_BH_RESUME,
};

typedef int (*bes2600_wsm_handler)(struct bes2600_common *hw_priv,
	u8 *data, size_t size);

#ifdef MCAST_FWDING
int wsm_release_buffer_to_fw(struct bes2600_vif *priv, int count);
#endif

static void bes2600_bh_work(struct work_struct *work)
{
	struct bes2600_common *priv =
	container_of(work, struct bes2600_common, bh_work);
	bes2600_bh(priv);
}

int bes2600_register_bh(struct bes2600_common *hw_priv)
{
	int err = 0;
	/* Realtime workqueue */
	hw_priv->bh_workqueue = alloc_workqueue("bes2600_bh",
				WQ_MEM_RECLAIM | WQ_HIGHPRI
				| WQ_CPU_INTENSIVE, 1);

	if (!hw_priv->bh_workqueue)
		return -ENOMEM;

	INIT_WORK(&hw_priv->bh_work, bes2600_bh_work);

	bes2600_info(BES2600_DBG_BH, "[BH] register.\n");

#ifdef WIFI_BT_COEXIST_EPTA_ENABLE
#ifdef WIFI_BT_COEXIST_EPTA_FDD
	coex_init_mode(hw_priv, WIFI_COEX_MODE_FDD_BIT);
#else
	coex_init_mode(hw_priv, 0);
#endif
#endif
	atomic_set(&hw_priv->bh_rx, 0);
	atomic_set(&hw_priv->bh_tx, 0);
	atomic_set(&hw_priv->bh_term, 0);
	atomic_set(&hw_priv->bh_suspend, BES2600_BH_RESUMED);
	hw_priv->buf_id_tx = 0;
	hw_priv->buf_id_rx = 0;
	init_waitqueue_head(&hw_priv->bh_wq);
	init_waitqueue_head(&hw_priv->bh_evt_wq);

	err = !queue_work(hw_priv->bh_workqueue, &hw_priv->bh_work);
	WARN_ON(err);
	return err;
}

void bes2600_unregister_bh(struct bes2600_common *hw_priv)
{
#ifdef WIFI_BT_COEXIST_EPTA_ENABLE
	coex_deinit_mode(hw_priv);
#endif

	atomic_add(1, &hw_priv->bh_term);
	wake_up(&hw_priv->bh_wq);

	flush_workqueue(hw_priv->bh_workqueue);

	destroy_workqueue(hw_priv->bh_workqueue);
	hw_priv->bh_workqueue = NULL;

	bes2600_info(BES2600_DBG_BH, "[BH] unregistered.\n");
}

void bes2600_irq_handler(struct bes2600_common *hw_priv)
{
	bes2600_dbg(BES2600_DBG_BH, "[BH] irq.\n");
	if(!hw_priv) {
		bes2600_warn(BES2600_DBG_BH, "%s hw private data is null", __func__);
		return;
	}

	if (hw_priv->bh_error) {
		bes2600_err(BES2600_DBG_BH, "%s bh error", __func__);
		return;
	}

	if (atomic_add_return(1, &hw_priv->bh_rx) == 1)
		wake_up(&hw_priv->bh_wq);
}
EXPORT_SYMBOL(bes2600_irq_handler);

void bes2600_bh_wakeup(struct bes2600_common *hw_priv)
{
	bes2600_dbg(BES2600_DBG_BH,  "[BH] wakeup.\n");
	if (WARN_ON(hw_priv->bh_error))
		return;

	if (atomic_add_return(1, &hw_priv->bh_tx) == 1)
		wake_up(&hw_priv->bh_wq);
}
EXPORT_SYMBOL(bes2600_bh_wakeup);

int bes2600_bh_suspend(struct bes2600_common *hw_priv)
{
#ifdef MCAST_FWDING
	int i =0;
	struct bes2600_vif *priv = NULL;
#endif

	bes2600_dbg(BES2600_DBG_BH, "[BH] suspend.\n");
	if (hw_priv->bh_error) {
		wiphy_warn(hw_priv->hw->wiphy, "BH error -- can't suspend\n");
		return -EINVAL;
	}

#ifdef MCAST_FWDING
 	bes2600_for_each_vif(hw_priv, priv, i) {
		if (!priv)
			continue;
		if ( (priv->multicast_filter.enable)
			&& (priv->join_status == BES2600_JOIN_STATUS_AP) ) {
			wsm_release_buffer_to_fw(priv,
				(hw_priv->wsm_caps.numInpChBufs - 1));
			break;
		}
	}
#endif

	atomic_set(&hw_priv->bh_suspend, BES2600_BH_SUSPEND);
	wake_up(&hw_priv->bh_wq);
	return wait_event_timeout(hw_priv->bh_evt_wq, hw_priv->bh_error ||
		(BES2600_BH_SUSPENDED == atomic_read(&hw_priv->bh_suspend)),
		 1 * HZ) ? 0 : -ETIMEDOUT;
}
EXPORT_SYMBOL(bes2600_bh_suspend);

int bes2600_bh_resume(struct bes2600_common *hw_priv)
{
	int ret;

#ifdef MCAST_FWDING
	int i =0;
	struct bes2600_vif *priv = NULL;
#endif

	bes2600_dbg(BES2600_DBG_BH, "[BH] resume.\n");
	if (hw_priv->bh_error) {
		wiphy_warn(hw_priv->hw->wiphy, "BH error -- can't resume\n");
		return -EINVAL;
	}

	atomic_set(&hw_priv->bh_suspend, BES2600_BH_RESUME);
	wake_up(&hw_priv->bh_wq);
	ret = wait_event_timeout(hw_priv->bh_evt_wq, hw_priv->bh_error ||
		(BES2600_BH_RESUMED == atomic_read(&hw_priv->bh_suspend)),
		1 * HZ) ? 0 : -ETIMEDOUT;

#ifdef MCAST_FWDING
	bes2600_for_each_vif(hw_priv, priv, i) {
		if (!priv)
			continue;
		if ((priv->join_status == BES2600_JOIN_STATUS_AP)
				&& (priv->multicast_filter.enable)) {
			u8 count = 0;
			WARN_ON(wsm_request_buffer_request(priv, &count));
			bes2600_dbg(BES2600_DBG_BH, "[BH] BH resume. Reclaim Buff %d \n",count);
			break;
		}
	}
#endif

	return ret;
}
EXPORT_SYMBOL(bes2600_bh_resume);

static inline void wsm_alloc_tx_buffer(struct bes2600_common *hw_priv)
{
	++hw_priv->hw_bufs_used;
}

int wsm_release_tx_buffer(struct bes2600_common *hw_priv, int count)
{
	int ret = 0;
	int hw_bufs_used = hw_priv->hw_bufs_used;

	hw_priv->hw_bufs_used -= count;

	if (WARN_ON(hw_priv->hw_bufs_used < 0))
		ret = -1;
	/* Tx data patch stops when all but one hw buffers are used.
	   So, re-start tx path in case we find hw_bufs_used equals
	   numInputChBufs - 1.
	 */
	else if (hw_bufs_used >= (hw_priv->wsm_caps.numInpChBufs - 1))
		ret = 1;
	if (!hw_priv->hw_bufs_used) {
		bes2600_pwr_clear_busy_event(hw_priv, BES_PWR_LOCK_ON_LMAC_RSP);
		wake_up(&hw_priv->bh_evt_wq);
	}
	return ret;
}
EXPORT_SYMBOL(wsm_release_tx_buffer);

int wsm_release_vif_tx_buffer(struct bes2600_common *hw_priv, int if_id,
				int count)
{
	int ret = 0;

	hw_priv->hw_bufs_used_vif[if_id] -= count;

	if (!hw_priv->hw_bufs_used_vif[if_id])
		wake_up(&hw_priv->bh_evt_wq);

	if (WARN_ON(hw_priv->hw_bufs_used_vif[if_id] < 0))
		ret = -1;
	return ret;
}
#ifdef MCAST_FWDING
int wsm_release_buffer_to_fw(struct bes2600_vif *priv, int count)
{
	int i;
	u8 flags;
	struct wsm_buf *buf;
	size_t buf_len;
	struct wsm_hdr *wsm;
	struct bes2600_common *hw_priv = priv->hw_priv;

#if 1
	if (priv->join_status != BES2600_JOIN_STATUS_AP) {
		return 0;
	}
#endif
	bes2600_dbg(BES2600_DBG_BH, "Rel buffer to FW %d, %d\n", count, hw_priv->hw_bufs_used);

	for (i = 0; i < count; i++) {
		if ((hw_priv->hw_bufs_used + 1) < hw_priv->wsm_caps.numInpChBufs) {
			flags = i ? 0: 0x1;

			wsm_alloc_tx_buffer(hw_priv);

			buf = &hw_priv->wsm_release_buf[i];
			buf_len = buf->data - buf->begin;

			/* Add sequence number */
			wsm = (struct wsm_hdr *)buf->begin;
			BUG_ON(buf_len < sizeof(*wsm));

			wsm->id &= __cpu_to_le32(
				~WSM_TX_SEQ(WSM_TX_SEQ_MAX));
			wsm->id |= cpu_to_le32(
				WSM_TX_SEQ(hw_priv->wsm_tx_seq[WSM_TXRX_SEQ_IDX(wsm->id)]));

			bes2600_dbg(BES2600_DBG_BH, "REL %d\n", hw_priv->wsm_tx_seq[WSM_TXRX_SEQ_IDX(wsm->id)]);
			if (WARN_ON(bes2600_data_write(hw_priv,
				buf->begin, buf_len))) {
				break;
			}
			hw_priv->buf_released = 1;
			hw_priv->wsm_tx_seq[WSM_TXRX_SEQ_IDX(wsm->id)] =
				(hw_priv->wsm_tx_seq[WSM_TXRX_SEQ_IDX(wsm->id)] + 1) & WSM_TX_SEQ_MAX;
		} else
			break;
	}

	if (i == count) {
		return 0;
	}

	/* Should not be here */
	bes2600_err(BES2600_DBG_BH, "[BH] Less HW buf %d,%d.\n", hw_priv->hw_bufs_used,
			hw_priv->wsm_caps.numInpChBufs);
	WARN_ON(1);

	return -1;
}
#endif

#if 0
static struct sk_buff *bes2600_get_skb(struct bes2600_common *hw_priv, size_t len)
{
	struct sk_buff *skb;
	size_t alloc_len = (len > SDIO_BLOCK_SIZE) ? len : SDIO_BLOCK_SIZE;

	if (len > SDIO_BLOCK_SIZE || !hw_priv->skb_cache) {
		skb = dev_alloc_skb(alloc_len
				+ WSM_TX_EXTRA_HEADROOM
				+ 8  /* TKIP IV */
				+ 12 /* TKIP ICV + MIC */
				- 2  /* Piggyback */);
		/* In AP mode RXed SKB can be looped back as a broadcast.
		 * Here we reserve enough space for headers. */
		skb_reserve(skb, WSM_TX_EXTRA_HEADROOM
				+ 8 /* TKIP IV */
				- WSM_RX_EXTRA_HEADROOM);
	} else {
		skb = hw_priv->skb_cache;
		hw_priv->skb_cache = NULL;
	}
	return skb;
}

static void bes2600_put_skb(struct bes2600_common *hw_priv, struct sk_buff *skb)
{
	if (hw_priv->skb_cache)
		dev_kfree_skb(skb);
	else
		hw_priv->skb_cache = skb;
}

static int bes2600_bh_read_ctrl_reg(struct bes2600_common *hw_priv,
					  u16 *ctrl_reg)
{
	int ret;

	ret = bes2600_reg_read_16(hw_priv,
			ST90TDS_CONTROL_REG_ID, ctrl_reg);
	if (ret) {
		ret = bes2600_reg_read_16(hw_priv,
				ST90TDS_CONTROL_REG_ID, ctrl_reg);
		if (ret)
			bes2600_err(BES2600_DBG_BH, "[BH] Failed to read control register.\n");
	}

	return ret;
}

static int bes2600_device_wakeup(struct bes2600_common *hw_priv)
{
	u16 ctrl_reg;
	int ret;

	bes2600_dbg(BES2600_DBG_BH, "[BH] Device wakeup.\n");

	/* To force the device to be always-on, the host sets WLAN_UP to 1 */
	ret = bes2600_reg_write_16(hw_priv, ST90TDS_CONTROL_REG_ID,
			ST90TDS_CONT_WUP_BIT);
	if (WARN_ON(ret))
		return ret;

	ret = bes2600_bh_read_ctrl_reg(hw_priv, &ctrl_reg);
	if (WARN_ON(ret))
		return ret;

	/* If the device returns WLAN_RDY as 1, the device is active and will
	 * remain active. */
	if (ctrl_reg & ST90TDS_CONT_RDY_BIT) {
		bes2600_dbg(BES2600_DBG_BH, "[BH] Device awake.\n");
		return 1;
	}

	return 0;
}

#endif

/* Must be called from BH thraed. */
void bes2600_enable_powersave(struct bes2600_vif *priv,
			     bool enable)
{
	bes2600_dbg(BES2600_DBG_BH, "[BH] Powerave is %s.\n",
			enable ? "enabled" : "disabled");
	priv->powersave_enabled = enable;
}

#if 0
#define INTERRUPT_WORKAROUND
static int bes2600_bh(void *arg)
{
	struct bes2600_common *hw_priv = arg;
	struct bes2600_vif *priv = NULL;
	struct sk_buff *skb_rx = NULL;
	size_t read_len = 0;
	int rx, tx, term, suspend;
	struct wsm_hdr *wsm;
	size_t wsm_len;
	int wsm_id;
	u8 wsm_seq;
	int rx_resync = 1;
	u16 ctrl_reg = 0;
	int tx_allowed;
	int pending_tx = 0;
	int tx_burst;
	int rx_burst = 0;
	long status;
#if defined(CONFIG_BES2600_WSM_DUMPS)
	size_t wsm_dump_max = -1;
#endif
	u32 dummy;
	bool powersave_enabled;
	int i;
	int vif_selected;

	for (;;) {
		powersave_enabled = 1;
		spin_lock(&hw_priv->vif_list_lock);
		bes2600_for_each_vif(hw_priv, priv, i) {
#ifdef P2P_MULTIVIF
			if ((i = (CW12XX_MAX_VIFS - 1)) || !priv)
#else
			if (!priv)
#endif
				continue;
			powersave_enabled &= !!priv->powersave_enabled;
		}
		spin_unlock(&hw_priv->vif_list_lock);
		if (!hw_priv->hw_bufs_used
				&& powersave_enabled
				&& !hw_priv->device_can_sleep
				&& !atomic_read(&hw_priv->recent_scan)) {
			status = HZ/8;
			bes2600_dbg(BES2600_DBG_BH, "[BH] No Device wakedown.\n");
#ifndef FPGA_SETUP
			WARN_ON(bes2600_reg_write_16(hw_priv,
						ST90TDS_CONTROL_REG_ID, 0));
			hw_priv->device_can_sleep = true;
#endif
		} else if (hw_priv->hw_bufs_used)
			/* Interrupt loss detection */
			status = HZ/8;
		else
			status = HZ/8;

		/* Dummy Read for SDIO retry mechanism*/
		if (((atomic_read(&hw_priv->bh_rx) == 0) &&
				(atomic_read(&hw_priv->bh_tx) == 0)))
			bes2600_reg_read(hw_priv, ST90TDS_CONFIG_REG_ID,
					&dummy, sizeof(dummy));
#if defined(CONFIG_BES2600_WSM_DUMPS_SHORT)
		wsm_dump_max = hw_priv->wsm_dump_max_size;
#endif /* CONFIG_BES2600_WSM_DUMPS_SHORT */

#ifdef INTERRUPT_WORKAROUND
				/* If a packet has already been txed to the device then read the
				   control register for a probable interrupt miss before going
				   further to wait for interrupt; if the read length is non-zero
				   then it means there is some data to be received */
				if (hw_priv->hw_bufs_used) {
					bes2600_bh_read_ctrl_reg(hw_priv, &ctrl_reg);
					if(ctrl_reg & ST90TDS_CONT_NEXT_LEN_MASK)
					{
						rx = 1;
						goto test;
					}
				}
#endif

		status = wait_event_interruptible_timeout(hw_priv->bh_wq, ({
				rx = atomic_xchg(&hw_priv->bh_rx, 0);
				tx = atomic_xchg(&hw_priv->bh_tx, 0);
				term = atomic_xchg(&hw_priv->bh_term, 0);
				suspend = pending_tx ?
					0 : atomic_read(&hw_priv->bh_suspend);
				(rx || tx || term || suspend || hw_priv->bh_error);
			}), status);

		if (status < 0 || term || hw_priv->bh_error)
			break;

#ifdef INTERRUPT_WORKAROUND
		if (!status) {
			bes2600_bh_read_ctrl_reg(hw_priv, &ctrl_reg);
			if(ctrl_reg & ST90TDS_CONT_NEXT_LEN_MASK)
			{
				bes2600_err(BES2600_DBG_BH, "MISS 1\n");
				rx = 1;
				goto test;
			}
		}
#endif
		if (!status && hw_priv->hw_bufs_used) {
			unsigned long timestamp = jiffies;
			long timeout;
			bool pending = false;
			int i;

			wiphy_warn(hw_priv->hw->wiphy, "Missed interrupt?\n");
			rx = 1;

			/* Get a timestamp of "oldest" frame */
			for (i = 0; i < 4; ++i)
				pending |= bes2600_queue_get_xmit_timestamp(
						&hw_priv->tx_queue[i],
						&timestamp, -1,
						hw_priv->pending_frame_id);

			/* Check if frame transmission is timed out.
			 * Add an extra second with respect to possible
			 * interrupt loss. */
			timeout = timestamp +
					WSM_CMD_LAST_CHANCE_TIMEOUT +
					1 * HZ  -
					jiffies;

			/* And terminate BH tread if the frame is "stuck" */
			if (pending && timeout < 0) {
				//wiphy_warn(priv->hw->wiphy,
				//	"Timeout waiting for TX confirm.\n");
				bes2600_info(BES2600_DBG_BH, "bes2600_bh: Timeout waiting for TX confirm.\n");
				break;
			}

#if defined(CONFIG_BES2600_DUMP_ON_ERROR)
			BUG_ON(1);
#endif /* CONFIG_BES2600_DUMP_ON_ERROR */
		} else if (!status) {
			if (!hw_priv->device_can_sleep
					&& !atomic_read(&hw_priv->recent_scan)) {
				bes2600_dbg(BES2600_DBG_BH, "[BH] Device wakedown. Timeout.\n");
#ifndef FPGA_SETUP
				WARN_ON(bes2600_reg_write_16(hw_priv,
						ST90TDS_CONTROL_REG_ID, 0));
				hw_priv->device_can_sleep = true;
#endif
			}
			continue;
		} else if (suspend) {
			bes2600_dbg(BES2600_DBG_BH, "[BH] Device suspend.\n");
			powersave_enabled = 1;
			spin_lock(&hw_priv->vif_list_lock);
			bes2600_for_each_vif(hw_priv, priv, i) {
#ifdef P2P_MULTIVIF
				if ((i = (CW12XX_MAX_VIFS - 1)) || !priv)
#else
				if (!priv)
#endif
					continue;
				powersave_enabled &= !!priv->powersave_enabled;
			}
			spin_unlock(&hw_priv->vif_list_lock);
			if (powersave_enabled) {
				bes2600_dbg(BES2600_DBG_BH, "[BH] No Device wakedown. Suspend.\n");
#ifndef FPGA_SETUP
				WARN_ON(bes2600_reg_write_16(hw_priv,
						ST90TDS_CONTROL_REG_ID, 0));
				hw_priv->device_can_sleep = true;
#endif
			}

			atomic_set(&hw_priv->bh_suspend, BES2600_BH_SUSPENDED);
			wake_up(&hw_priv->bh_evt_wq);
			status = wait_event_interruptible(hw_priv->bh_wq,
					BES2600_BH_RESUME == atomic_read(
						&hw_priv->bh_suspend));
			if (status < 0) {
				wiphy_err(hw_priv->hw->wiphy,
					"%s: Failed to wait for resume: %ld.\n",
					__func__, status);
				break;
			}
			bes2600_dbg(BES2600_DBG_BH, "[BH] Device resume.\n");
			atomic_set(&hw_priv->bh_suspend, BES2600_BH_RESUMED);
			wake_up(&hw_priv->bh_evt_wq);
			atomic_add(1, &hw_priv->bh_rx);
			continue;
		}

test:
		tx += pending_tx;
		pending_tx = 0;

		if (rx) {
			size_t alloc_len;
			u8 *data;

#ifdef INTERRUPT_WORKAROUND
			if(!(ctrl_reg & ST90TDS_CONT_NEXT_LEN_MASK))
#endif
			if (WARN_ON(bes2600_bh_read_ctrl_reg(
					hw_priv, &ctrl_reg)))
				break;
rx:
			read_len = (ctrl_reg & ST90TDS_CONT_NEXT_LEN_MASK) * 2;
			if (!read_len) {
				rx_burst = 0;
				goto tx;
			}

			if (WARN_ON((read_len < sizeof(struct wsm_hdr)) ||
					(read_len > EFFECTIVE_BUF_SIZE))) {
				bes2600_dbg(BES2600_DBG_BH, "Invalid read len: %d",
					read_len);
				break;
			}

			/* Add SIZE of PIGGYBACK reg (CONTROL Reg)
			 * to the NEXT Message length + 2 Bytes for SKB */
			read_len = read_len + 2;

#if defined(CONFIG_BES2600_NON_POWER_OF_TWO_BLOCKSIZES)
			alloc_len = hw_priv->sbus_ops->align_size(
					hw_priv->sbus_priv, read_len);
#else /* CONFIG_BES2600_NON_POWER_OF_TWO_BLOCKSIZES */
			/* Platform's SDIO workaround */
			alloc_len = read_len & ~(SDIO_BLOCK_SIZE - 1);
			if (read_len & (SDIO_BLOCK_SIZE - 1))
				alloc_len += SDIO_BLOCK_SIZE;
#endif /* CONFIG_BES2600_NON_POWER_OF_TWO_BLOCKSIZES */

			/* Check if not exceeding BES2600 capabilities */
			if (WARN_ON_ONCE(alloc_len > EFFECTIVE_BUF_SIZE)) {
				bes2600_dbg(BES2600_DBG_BH, "Read aligned len: %d\n",
					alloc_len);
			}

			skb_rx = bes2600_get_skb(hw_priv, alloc_len);
			if (WARN_ON(!skb_rx))
				break;

			skb_trim(skb_rx, 0);
			skb_put(skb_rx, read_len);
			data = skb_rx->data;
			if (WARN_ON(!data))
				break;

			if (WARN_ON(bes2600_data_read(hw_priv, data, alloc_len)))
				break;

			/* Piggyback */
			ctrl_reg = __le16_to_cpu(
				((__le16 *)data)[alloc_len / 2 - 1]);

			wsm = (struct wsm_hdr *)data;
			wsm_len = __le32_to_cpu(wsm->len);
			if (WARN_ON(wsm_len > read_len))
				break;

#if defined(CONFIG_BES2600_WSM_DUMPS)
			if (unlikely(hw_priv->wsm_enable_wsm_dumps)) {
				u16 msgid, ifid;
				u16 *p = (u16 *)data;
				msgid = (*(p + 1)) & 0xC3F;
				ifid  = (*(p + 1)) >> 6;
				ifid &= 0xF;
				bes2600_dbg(BES2600_DBG_BH, "[DUMP] <<< msgid 0x%.4X ifid %d len %d\n",
							msgid, ifid, *p);
				print_hex_dump_bytes("<-- ",
					DUMP_PREFIX_NONE,
					data, min(wsm_len, wsm_dump_max));
			}
#endif /* CONFIG_BES2600_WSM_DUMPS */

			wsm_id  = __le32_to_cpu(wsm->id) & 0xFFF;
			wsm_seq = (__le32_to_cpu(wsm->id) >> 13) & 7;

			skb_trim(skb_rx, wsm_len);

			if (unlikely(wsm_id == 0x0800)) {
				wsm_handle_exception(hw_priv,
					 &data[sizeof(*wsm)],
					wsm_len - sizeof(*wsm));
				break;
			} else if (unlikely(!rx_resync)) {
				if (WARN_ON(wsm_seq != hw_priv->wsm_rx_seq)) {
#if defined(CONFIG_BES2600_DUMP_ON_ERROR)
					BUG_ON(1);
#endif /* CONFIG_BES2600_DUMP_ON_ERROR */
					break;
				}
			}
			hw_priv->wsm_rx_seq = (wsm_seq + 1) & 7;
			rx_resync = 0;

			if (wsm_id & 0x0400) {
				int rc = wsm_release_tx_buffer(hw_priv, 1);
				if (WARN_ON(rc < 0))
					break;
				else if (rc > 0)
					tx = 1;
			}

			/* bes2600_wsm_rx takes care on SKB livetime */
			if (WARN_ON(wsm_handle_rx(hw_priv, wsm_id, wsm,
						  &skb_rx)))
				break;

			if (skb_rx) {
				bes2600_put_skb(hw_priv, skb_rx);
				skb_rx = NULL;
			}

			read_len = 0;

			if (rx_burst) {
				bes2600_debug_rx_burst(hw_priv);
				--rx_burst;
				goto rx;
			}
		}

tx:
		BUG_ON(hw_priv->hw_bufs_used > hw_priv->wsm_caps.numInpChBufs);
		tx_burst = hw_priv->wsm_caps.numInpChBufs -
			hw_priv->hw_bufs_used;
		tx_allowed = tx_burst > 0;
		if (tx && tx_allowed) {
			size_t tx_len;
			u8 *data;
			int ret;

			if (hw_priv->device_can_sleep) {
				ret = bes2600_device_wakeup(hw_priv);
				if (WARN_ON(ret < 0))
					break;
				else if (ret)
					hw_priv->device_can_sleep = false;
				else {
					/* Wait for "awake" interrupt */
					pending_tx = tx;
					continue;
				}
			}

			wsm_alloc_tx_buffer(hw_priv);
			ret = wsm_get_tx(hw_priv, &data, &tx_len, &tx_burst,
						&vif_selected);
			if (ret <= 0) {
				wsm_release_tx_buffer(hw_priv, 1);
				if (WARN_ON(ret < 0))
					break;
			} else {
				wsm = (struct wsm_hdr *)data;
				BUG_ON(tx_len < sizeof(*wsm));
				BUG_ON(__le32_to_cpu(wsm->len) != tx_len);

#if 0 /* count is not implemented */
				if (ret > 1)
					atomic_add(1, &hw_priv->bh_tx);
#else
				atomic_add(1, &hw_priv->bh_tx);
#endif

#if defined(CONFIG_BES2600_NON_POWER_OF_TWO_BLOCKSIZES)
				if (tx_len <= 8)
					tx_len = 16;
				tx_len = hw_priv->sbus_ops->align_size(
						hw_priv->sbus_priv, tx_len);
#else /* CONFIG_BES2600_NON_POWER_OF_TWO_BLOCKSIZES */
				/* HACK!!! Platform limitation.
				* It is also supported by upper layer:
				* there is always enough space at the
				* end of the buffer. */
				if (tx_len & (SDIO_BLOCK_SIZE - 1)) {
					tx_len &= ~(SDIO_BLOCK_SIZE - 1);
					tx_len += SDIO_BLOCK_SIZE;
				}
#endif /* CONFIG_BES2600_NON_POWER_OF_TWO_BLOCKSIZES */

				/* Check if not exceeding BES2600
				    capabilities */
				if (WARN_ON_ONCE(
				    tx_len > EFFECTIVE_BUF_SIZE)) {
					bes2600_dbg(BES2600_DBG_BH, "Write aligned len:"
					" %d\n", tx_len);
				}

				wsm->id &= __cpu_to_le32(
						~WSM_TX_SEQ(WSM_TX_SEQ_MAX));
				wsm->id |= cpu_to_le32(WSM_TX_SEQ(
						hw_priv->wsm_tx_seq));

				if (WARN_ON(bes2600_data_write(hw_priv,
				    data, tx_len))) {
					wsm_release_tx_buffer(hw_priv, 1);
					break;
				}

				if (vif_selected != -1) {
					hw_priv->hw_bufs_used_vif[
							vif_selected]++;
				}

#if defined(CONFIG_BES2600_WSM_DUMPS)
				if (unlikely(hw_priv->wsm_enable_wsm_dumps)) {
					u16 msgid, ifid;
					u16 *p = (u16 *)data;
					msgid = (*(p + 1)) & 0x3F;
					ifid  = (*(p + 1)) >> 6;
					ifid &= 0xF;
					if (msgid == 0x0006) {
						bes2600_dbg(BES2600_DBG_BH, "[DUMP] >>> "
								"msgid 0x%.4X "
								"ifid %d len %d"
								" MIB 0x%.4X\n",
								msgid, ifid,
								*p, *(p + 2));
					} else {
						bes2600_dbg(BES2600_DBG_BH, "[DUMP] >>> "
								"msgid 0x%.4X "
								"ifid %d "
								"len %d\n",
								msgid, ifid,
								*p);
					}
					print_hex_dump_bytes("--> ",
						DUMP_PREFIX_NONE,
						data,
						min(__le32_to_cpu(wsm->len),
						 wsm_dump_max));
				}
#endif /* CONFIG_BES2600_WSM_DUMPS */

				wsm_txed(hw_priv, data);
				hw_priv->wsm_tx_seq = (hw_priv->wsm_tx_seq + 1)
						& WSM_TX_SEQ_MAX;

				if (tx_burst > 1) {
					bes2600_debug_tx_burst(hw_priv);
					++rx_burst;
					goto tx;
				}
			}
		}

		if (ctrl_reg & ST90TDS_CONT_NEXT_LEN_MASK)
			goto rx;
	}

	if (skb_rx) {
		bes2600_put_skb(hw_priv, skb_rx);
		skb_rx = NULL;
	}


	if (!term) {
		bes2600_dbg(BES2600_DBG_ERROR, "[BH] Fatal error, exitting.\n");
#if defined(CONFIG_BES2600_DUMP_ON_ERROR)
		BUG_ON(1);
#endif /* CONFIG_BES2600_DUMP_ON_ERROR */
		hw_priv->bh_error = 1;
#if defined(CONFIG_BES2600_USE_STE_EXTENSIONS)
		spin_lock(&hw_priv->vif_list_lock);
		bes2600_for_each_vif(hw_priv, priv, i) {
			if (!priv)
				continue;
			ieee80211_driver_hang_notify(priv->vif, GFP_KERNEL);
		}
		spin_unlock(&hw_priv->vif_list_lock);
		bes2600_pm_stay_awake(&hw_priv->pm_state, 3*HZ);
#endif
		/* TODO: schedule_work(recovery) */
#ifndef HAS_PUT_TASK_STRUCT
		/* The only reason of having this stupid code here is
		 * that __put_task_struct is not exported by kernel. */
		for (;;) {
			int status = wait_event_interruptible(hw_priv->bh_wq, ({
				term = atomic_xchg(&hw_priv->bh_term, 0);
				(term);
				}));

			if (status || term)
				break;
		}
#endif
	}
	return 0;
}
#else

#ifdef CONFIG_BES2600_WLAN_SDIO
extern int bes2600_bh_read_ctrl_reg(struct bes2600_common *priv, u32 *ctrl_reg);
#endif

#ifdef BES2600_RX_IN_BH
static int bes2600_bh_rx_helper(struct bes2600_common *priv, int *tx)
{
	struct sk_buff *skb = NULL;
	struct wsm_hdr *wsm;
	size_t wsm_len;
	u16 wsm_id;
	u8 wsm_seq;
	int rx = 0;
	u32 confirm_label = 0x0; /* wsm to mcu cmd cnfirm label */

#if defined(CONFIG_BES2600_WLAN_USB) || defined(CONFIG_BES2600_WLAN_SPI) || defined(BES_SDIO_RX_MULTIPLE_ENABLE)
	skb = (struct sk_buff *)priv->sbus_ops->pipe_read(priv->sbus_priv);
	if (!skb)
		return 0;
	rx = 1; // always consider rx pipe not empty
#else
	u32 ctrl_reg = 0;
	size_t read_len = 0;
//	int rx_resync = 1;
	size_t alloc_len;
	u8 *data;

	bes2600_bh_read_ctrl_reg(priv, &ctrl_reg);

	read_len = (ctrl_reg & BES_TX_NEXT_LEN_MASK);

	if (!read_len)
		return 0; /* No more work */

	if (WARN_ON((read_len < sizeof(struct wsm_hdr)) ||
		    (read_len > EFFECTIVE_BUF_SIZE))) {
		bes2600_err(BES2600_DBG_BH, "Invalid read len: %zu (%04x)",
			 read_len, ctrl_reg);
		goto err;
	}

	/* more 2 byte is not needed ? */
#if 0
	/* Add SIZE of PIGGYBACK reg (CONTROL Reg)
	 * to the NEXT Message length + 2 Bytes for SKB
	 */
	read_len = read_len + 2;
#endif

	alloc_len = priv->sbus_ops->align_size(
		priv->sbus_priv, read_len);

	/* Check if not exceeding BES2600 capabilities */
	if (WARN_ON_ONCE(alloc_len > EFFECTIVE_BUF_SIZE)) {
		bes2600_dbg(BES2600_DBG_BH, "Read aligned len: %zu\n",
			 alloc_len);
	}

	skb = dev_alloc_skb(alloc_len);
	if (WARN_ON(!skb))
		goto err;

	skb_trim(skb, 0);
	skb_put(skb, read_len);
	data = skb->data;
	if (WARN_ON(!data))
		goto err;

	if (WARN_ON(bes2600_data_read(priv, data, alloc_len))) {
		bes2600_err(BES2600_DBG_BH, "rx blew up, len %zu\n", alloc_len);
		goto err;
	}

	/* piggyback is not implemented,
	 * and only recieve data once
	 */
#if 0
	/* Piggyback */
	ctrl_reg = __le16_to_cpu(
		((__le16 *)data)[alloc_len / 2 - 1]);

	/* check if more data need to recv */
	if (ctrl_reg & ST90TDS_CONT_NEXT_LEN_MASK)
		rx = 1;
#else
	rx = 0;
#endif

#endif

	wsm = (struct wsm_hdr *)skb->data;
	wsm_len = __le16_to_cpu(wsm->len);
	if (WARN_ON(wsm_len > skb->len)) {
		bes2600_err(BES2600_DBG_BH, "wsm_len err %d %d\n", (int)wsm_len, (int)skb->len);
		goto err;
	}

	if (priv->wsm_enable_wsm_dumps)
		print_hex_dump_bytes("<-- ",
				     DUMP_PREFIX_NONE,
				     skb->data, wsm_len);

	wsm_id  = __le16_to_cpu(wsm->id) & 0xFFF;
	wsm_seq = (__le16_to_cpu(wsm->id) >> 13) & 7;
	bes2600_dbg(BES2600_DBG_BH, "bes2600_bh_rx_helper wsm_id:0x%04x seq:%d\n", wsm_id, wsm_seq);

	skb_trim(skb, wsm_len);

	if (wsm_id == 0x0800) {
		wsm_handle_exception(priv,
				     &skb->data[sizeof(*wsm)],
				     wsm_len - sizeof(*wsm));
		bes2600_err(BES2600_DBG_BH, "wsm exception.!\n");
		goto err;
	} else if ((wsm_seq != priv->wsm_rx_seq[WSM_TXRX_SEQ_IDX(wsm_id)])) {
		bes2600_err(BES2600_DBG_BH, "seq error! %u. %u. 0x%x.", wsm_seq, priv->wsm_rx_seq[WSM_TXRX_SEQ_IDX(wsm_id)], wsm_id);
		goto err;
	}

	priv->wsm_rx_seq[WSM_TXRX_SEQ_IDX(wsm_id)] = (wsm_seq + 1) & 7;

	if (IS_DRIVER_TO_MCU_CMD(wsm_id))
		confirm_label = __le32_to_cpu(((struct wsm_mcu_hdr *)wsm)->handle_label);

	if (WSM_CONFIRM_CONDITION(wsm_id, confirm_label)) {
		int rc = wsm_release_tx_buffer(priv, 1);
		if (WARN_ON(rc < 0))
			return rc;
		else if (rc > 0)
			*tx = 1;
	}

	/* bes2600_wsm_rx takes care on SKB livetime */
	//if (WARN_ON(wsm_handle_rx(priv, wsm_id, wsm, &skb)))
	if ((wsm_handle_rx(priv, wsm_id, wsm, &skb))) {
		bes2600_err(BES2600_DBG_BH, "wsm_handle_rx fail\n");
		goto err;
	}

	if (skb) {
		dev_kfree_skb(skb);
		skb = NULL;
	}
	return rx;

err:
	bes2600_err(BES2600_DBG_BH, "bes2600_bh_rx_helper err\n");
	if (skb) {
		dev_kfree_skb(skb);
		skb = NULL;
	}
	return -1;
}
#endif

static int bes2600_bh_tx_helper(struct bes2600_common *hw_priv,
			       int *pending_tx,
			       int *tx_burst)
{
	size_t tx_len;
	u8 *data;
	int ret;
	struct wsm_hdr *wsm;
	int vif_selected;

#ifdef CONFIG_BES2600_WLAN_USB
	u32 packet_id;
	u8 queueId;
	struct wsm_tx *wsm_info;
	struct bes2600_queue *queue;
#endif

	wsm_alloc_tx_buffer(hw_priv);
	ret = wsm_get_tx(hw_priv, &data, &tx_len, tx_burst, &vif_selected);
	if (ret <= 0) {
		wsm_release_tx_buffer(hw_priv, 1);
		if (WARN_ON(ret < 0)) {
			bes2600_err(BES2600_DBG_BH, "bh get tx failed.\n");
			return ret; /* Error */
		}
		return 0; /* No work */
	}

	wsm = (struct wsm_hdr *)data;
	BUG_ON(tx_len < sizeof(*wsm));
	BUG_ON(__le16_to_cpu(wsm->len) != tx_len);
#ifdef BES2600_HOST_TIMESTAMP_DEBUG
	tx_len += 4;
#endif

	atomic_add(1, &hw_priv->bh_tx);

	tx_len = hw_priv->sbus_ops->align_size(
		hw_priv->sbus_priv, tx_len);

	/* Check if not exceeding BES2600 capabilities */
	if (WARN_ON_ONCE(tx_len > EFFECTIVE_BUF_SIZE))
		bes2600_err(BES2600_DBG_BH,  "Write aligned len: %zu\n", tx_len);

	wsm->id &= __cpu_to_le16(0xffff ^ WSM_TX_SEQ(WSM_TX_SEQ_MAX));
	wsm->id |= __cpu_to_le16(WSM_TX_SEQ(hw_priv->wsm_tx_seq[WSM_TXRX_SEQ_IDX(wsm->id)]));

	//bes2600_dbg(BES2600_DBG_BH, "usb send buff len:%u.priv->hw_bufs_used:%d.\n", tx_len, priv->hw_bufs_used);
	bes2600_dbg(BES2600_DBG_BH, "%s id:0x%04x seq:%d\n", __func__,
		wsm->id, hw_priv->wsm_tx_seq[WSM_TXRX_SEQ_IDX(wsm->id)]);
#ifdef CONFIG_BES2600_WLAN_USB
	ret = hw_priv->sbus_ops->pipe_send(hw_priv, 1, tx_len, data);
	#if 0
	int count = 0;
	while(priv->hw_bufs_used > 1)
	{
		mdelay(1);
		count++;
		if(count>2)
			break;
	}
	#endif
	if(ret < 0) {
		/* requeue packet when send fail */
		wsm_info = (struct wsm_tx *)data;
		packet_id =  __le32_to_cpu(wsm_info->packetID);
		queueId = bes2600_queue_get_queue_id(packet_id);
		queue = &hw_priv->tx_queue[queueId];
#ifdef CONFIG_BES2600_TESTMODE
		bes2600_queue_requeue(hw_priv, queue, packet_id, false);
#else
		bes2600_queue_requeue(queue, packet_id, false);
#endif
		wsm_release_tx_buffer(hw_priv, 1);
		return 0;
	}else if (vif_selected != -1) {
		hw_priv->hw_bufs_used_vif[vif_selected]++;
	}
#else
#ifndef BES_SDIO_TX_MULTIPLE_ENABLE
	if (WARN_ON(bes2600_data_write(data, tx_len))) {
#else
	if (WARN_ON(hw_priv->sbus_ops->pipe_send(hw_priv->sbus_priv, 1, tx_len, data))) {
#endif
		bes2600_err(BES2600_DBG_BH,  "tx blew up, len %zu\n", tx_len);
		wsm_release_tx_buffer(hw_priv, 1);
		return -1; /* Error */
	}

	if (vif_selected != -1)
		hw_priv->hw_bufs_used_vif[vif_selected] ++;
#endif

	if (hw_priv->wsm_enable_wsm_dumps)
		print_hex_dump_bytes("--> ",
				     DUMP_PREFIX_NONE,
				     data,
				     __le16_to_cpu(wsm->len));

	wsm_txed(hw_priv, data);

	hw_priv->wsm_tx_seq[WSM_TXRX_SEQ_IDX(wsm->id)] =
		(hw_priv->wsm_tx_seq[WSM_TXRX_SEQ_IDX(wsm->id)] + 1) & WSM_TX_SEQ_MAX;

	if (*tx_burst > 1) {
		bes2600_debug_tx_burst(hw_priv);
		return 1; /* Work remains */
	}

	return 0;
}

#ifdef KEY_FRAME_SW_RETRY

static inline bool
ieee80211_is_tcp_pkt(struct sk_buff *skb)
{

	if (!skb) {
		return false;
	}

	if (skb->protocol == cpu_to_be16(ETH_P_IP)) {
		struct iphdr *iph = (struct iphdr *)skb_network_header(skb);
		if (iph->protocol == IPPROTO_TCP) { // TCP
			bes2600_dbg(BES2600_DBG_BH, "################ %s line =%d.\n",__func__,__LINE__);
			return true;
		}
	}
	return false;
}


static int bes2600_need_retry_type(struct sk_buff *skb, int status)
{
	int ret = 0;
	if (!skb) {
		bes2600_info(BES2600_DBG_BH, "################ %s line =%d.\n",__func__,__LINE__);
		return -1;
	}

	if (skb->protocol == cpu_to_be16(ETH_P_IP)) {
		if (ieee80211_is_tcp_pkt(skb)) {
			ret = 1;
		}
	}
	if (status !=  WSM_STATUS_RETRY_EXCEEDED)
		ret = 0;
	return ret;
}

int bes2600_bh_sw_process(struct bes2600_common *hw_priv,
			 struct wsm_tx_confirm *tx_confirm)
{
	struct bes2600_txpriv *txpriv;
	struct sk_buff *skb = NULL;
	unsigned long timestamp = 0;
	struct bes2600_queue *queue;
	u8 queue_id, queue_gen;

#ifdef KEY_FRAME_SW_RETRY
	long delta_time;
#endif
	if (!tx_confirm) {
		bes2600_err(BES2600_DBG_BH,  "%s tx_confirm is NULL\n", __func__);
		return 0;
	}
	queue_id = bes2600_queue_get_queue_id(tx_confirm->packetID);
	queue = &hw_priv->tx_queue[queue_id];

	if (!queue) {
		bes2600_err(BES2600_DBG_BH,  "%s queue is NULL\n", __func__);
		return 0;
	}

	/* don't retry if the connection is already disconnected */
	queue_gen = bes2600_queue_get_generation(tx_confirm->packetID);
	if(queue_gen != queue->generation)
		return -1;

	bes2600_queue_get_skb_and_timestamp(queue, tx_confirm->packetID,
						&skb, &txpriv, &timestamp);
	if (skb == NULL) {
		bes2600_err(BES2600_DBG_BH,  "%s skb is NULL\n", __func__);
		return -1;
	}
	if (timestamp > jiffies)
		delta_time = jiffies + ((unsigned long)0xffffffff - timestamp);
	else
		delta_time =  jiffies - timestamp;
	bes2600_add_tx_delta_time(delta_time);
	bes2600_add_tx_ac_delta_time(queue_id, delta_time);

	if (bes2600_need_retry_type(skb, tx_confirm->status) == 0)
		return -1;

	if (delta_time > 1000)
		return -1;

	if (txpriv->retry_count < CW1200_MAX_SW_RETRY_CNT ) {
		struct bes2600_vif *priv =
		__cw12xx_hwpriv_to_vifpriv(hw_priv, txpriv->if_id);
		txpriv->retry_count++;

		bes2600_tx_status(priv,skb);

		bes2600_pwr_set_busy_event_with_timeout_async(
			hw_priv, BES_PWR_LOCK_ON_TX, BES_PWR_EVENT_TX_TIMEOUT);

		bes2600_sw_retry_requeue(hw_priv, queue, tx_confirm->packetID, true);
		return 0;
	} else {
		txpriv->retry_count = 0;
	}

	return -1;
}
#endif

#define BH_RX_CONT_LIMIT	3
#define BH_TX_CONT_LIMIT	20
static int bes2600_bh(void *arg)
{
	struct bes2600_common *hw_priv = arg;
	int rx, tx, term, suspend;
	int tx_allowed;
	int pending_tx = 0;
	int tx_burst;
	long status;
	int ret;

	int tx_cont = 0;
	int rx_cont = 0;

	for (;;) {
		rx_cont = 0;
		tx_cont = 0;

		if (!hw_priv->hw_bufs_used &&
		    !bes2600_pwr_device_is_idle(hw_priv) &&
		    !atomic_read(&hw_priv->recent_scan)) {
			status = 5 * HZ;
		} else if (hw_priv->hw_bufs_used) {
			/* Interrupt loss detection */
			status = 5 * HZ;
		} else {
			status = MAX_SCHEDULE_TIMEOUT;
		}

		status = wait_event_interruptible_timeout(hw_priv->bh_wq, ({
				rx = atomic_xchg(&hw_priv->bh_rx, 0);
				tx = atomic_xchg(&hw_priv->bh_tx, 0);
				term = atomic_xchg(&hw_priv->bh_term, 0);
				suspend = pending_tx ?
					0 : atomic_read(&hw_priv->bh_suspend);
				(rx || tx || term || suspend || hw_priv->bh_error);
			}), status);

		//bes2600_err(BES2600_DBG_BH,  "[BH] - rx: %d, tx: %d, term: %d, bh_err: %d, suspend: %d, bufused: %d, status: %ld\n",
				//rx, tx, term, suspend, hw_priv->bh_error, hw_priv->hw_bufs_used, status);

		/* Did an error occur? */
		if ((status < 0 && status != -ERESTARTSYS) ||
		    term || hw_priv->bh_error) {
			break;
		}
		if (!status) {  /* wait_event timed out */
			#ifdef CONFIG_BES2600_WLAN_BES
			unsigned long timestamp = jiffies;
			long timeout;
			int pending = 0;
			int i;
			#endif
			/* Check to see if we have any outstanding frames */
			if (hw_priv->hw_bufs_used && (!rx || !tx)) {
				bes2600_err(BES2600_DBG_BH,  "usedbuf:%u. rx:%u. tx:%u.\n", hw_priv->hw_bufs_used, rx, tx);
				#ifdef CONFIG_BES2600_WLAN_SDIO
				sdio_work_debug(hw_priv->sbus_priv);
				#endif
				#ifdef CONFIG_BES2600_WLAN_BES
				bes2600_err(BES2600_DBG_BH,  "Missed interrupt? (%d frames outstanding)\n",
					   hw_priv->hw_bufs_used);
				rx = 1;

				/* Get a timestamp of "oldest" frame */
				for (i = 0; i < 4; ++i)
					pending += bes2600_queue_get_xmit_timestamp(
						&hw_priv->tx_queue[i],
						&timestamp, i,
						hw_priv->pending_frame_id);

				/* Check if frame transmission is timed out.
				 * Add an extra second with respect to possible
				 * interrupt loss.
				 */
				timeout = timestamp +
					WSM_CMD_LAST_CHANCE_TIMEOUT +
					1 * HZ  -
					jiffies;

				/* And terminate BH thread if the frame is "stuck" */
				if (pending && timeout < 0) {
					wiphy_warn(hw_priv->hw->wiphy,
						   "Timeout waiting for TX confirm (%d/%d pending, %ld vs %lu).\n",
						   hw_priv->hw_bufs_used, pending,
						   timestamp, jiffies);
					break;
				}
				#endif

				bes2600_chrdev_wifi_force_close(hw_priv);
			}
#ifdef BES2600_RX_IN_BH
			goto rx;
#else
			goto done;
#endif
		} else if (suspend) {
			bes2600_dbg(BES2600_DBG_BH,  "[BH] Device suspend.\n");

			atomic_set(&hw_priv->bh_suspend, BES2600_BH_SUSPENDED);
			wake_up(&hw_priv->bh_evt_wq);
			status = wait_event_interruptible(hw_priv->bh_wq,
							  BES2600_BH_RESUME == atomic_read(&hw_priv->bh_suspend));
			if (status < 0) {
				wiphy_err(hw_priv->hw->wiphy,
					  "Failed to wait for resume: %ld.\n",
					  status);
				break;
			}
			bes2600_dbg(BES2600_DBG_BH,  "[BH] Device resume.\n");
			atomic_set(&hw_priv->bh_suspend, BES2600_BH_RESUMED);
			wake_up(&hw_priv->bh_evt_wq);
			atomic_add(1, &hw_priv->bh_rx);
			goto done;
		}

	rx:
		tx += pending_tx;
		pending_tx = 0;
#ifdef BES2600_RX_IN_BH
#ifdef CONFIG_BES2600_WLAN_SPI
		if (rx) {
#endif
		ret = bes2600_bh_rx_helper(hw_priv, &tx);
		if (ret < 0) {
			bes2600_err(BES2600_DBG_BH, "bes2600_bh_rx_helper fail\n");
			#ifdef CONFIG_BES2600_WLAN_SDIO
			sdio_work_debug(hw_priv->sbus_priv);
			#endif
			// break; // rx error
			bes2600_chrdev_wifi_force_close(hw_priv);
		}
		else if (ret == 1) {
			rx = 1; // continue rx
			rx_cont++;
		}
		else
			rx = 0; // wait for a new rx event
		if (rx && (rx_cont < BH_RX_CONT_LIMIT))
			goto rx;
		rx_cont = 0;
#ifdef CONFIG_BES2600_WLAN_SPI
		}
#endif
#endif
	tx:
		if (1) {
			tx = 0;

			BUG_ON(hw_priv->hw_bufs_used > hw_priv->wsm_caps.numInpChBufs);
			tx_burst = hw_priv->wsm_caps.numInpChBufs - hw_priv->hw_bufs_used;
			tx_allowed = tx_burst > 0;

			if (!tx_allowed) {
				/* Buffers full.  Ensure we process tx
				 * after we handle rx..
				 */
				#ifndef CONFIG_BES2600_WLAN_SDIO
				bes2600_err(BES2600_DBG_BH,  "bh tx not allowed.\n");
				#endif
				pending_tx = tx;
				goto done_rx;
			}
			ret = bes2600_bh_tx_helper(hw_priv, &pending_tx, &tx_burst);
			if (ret < 0) {
				bes2600_err(BES2600_DBG_BH, "bes2600_bh_tx_helper fail\n");
				#ifdef CONFIG_BES2600_WLAN_SDIO
				sdio_work_debug(hw_priv->sbus_priv);
				#endif
				break;
			}
			if (ret > 0) {
				/* More to transmit */
				tx_cont++;
				tx = ret;
			}

			if (tx && tx_cont < BH_TX_CONT_LIMIT)
				goto tx;
			tx_cont = 0;
#if 0
			/* Re-read ctrl reg */
			if (bes2600_bh_read_ctrl_reg(priv, &ctrl_reg))
				break;
#endif
		}

	done_rx:
		if (hw_priv->bh_error)
			break;
		//if (ctrl_reg & ST90TDS_CONT_NEXT_LEN_MASK)
		if (rx)
			goto rx;
		if (tx)
			goto tx;

	done:
		/* Re-enable device interrupts */
		//hw_priv->sbus_ops->lock(hw_priv->sbus_priv);
		//__bes2600_irq_enable(1);
		//hw_priv->sbus_ops->unlock(hw_priv->sbus_priv);
		asm volatile ("nop");
	}

	/* Explicitly disable device interrupts */
	hw_priv->sbus_ops->lock(hw_priv->sbus_priv);
	__bes2600_irq_enable(0);
	hw_priv->sbus_ops->unlock(hw_priv->sbus_priv);

	if (!term) {
		bes2600_err(BES2600_DBG_BH,  "[BH] Fatal error, exiting.\n");
		#ifdef CONFIG_BES2600_WLAN_SDIO
		sdio_work_debug(hw_priv->sbus_priv);
		#endif
		hw_priv->bh_error = 1;
		/* TODO: schedule_work(recovery) */
	}
	return 0;
}
#endif
