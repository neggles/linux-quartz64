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
#include "bes2600.h"
#include "wsm.h"
#include "queue.h"

struct tx_loop_table
{
        u16 cmd;
        void (*proc)(struct bes2600_common *hw_priv, u8 *buf, u32 len);
};

static void bes2600_tx_loop_build_lmac_tx_cfm(struct bes2600_common *hw_priv, u8 *buf, u32 len);

void bes2600_tx_loop_init(struct bes2600_common *hw_priv)
{
        hw_priv->tx_loop.enabled = false;
        hw_priv->tx_loop.start_lmac_seq = 0;
        hw_priv->tx_loop.start_mcu_seq = 0;
        spin_lock_init(&hw_priv->tx_loop.tx_loop_lock);
        skb_queue_head_init(&hw_priv->tx_loop.rx_queue);
}

struct sk_buff *bes2600_tx_loop_read(struct bes2600_common *hw_priv)
{
        struct sk_buff *skb;
        struct wsm_hdr *wsm;

        if(hw_priv == NULL)
                return NULL;

	skb = skb_dequeue(&hw_priv->tx_loop.rx_queue);
        if(skb != NULL) {
                wsm = (struct wsm_hdr *)skb->data;
                bes2600_dbg(BES2600_DBG_TXLOOP, "tx loop pipe read msg_id:0x%04x seq:%d\n", 
                                WSM_MSG_ID_GET(wsm->id), WSM_MSG_SEQ_GET(wsm->id));
        }

	return skb;
}

static void bes2600_tx_loop_item_pending_item(struct bes2600_common *hw_priv, struct sk_buff *skb)
{
        bes2600_dbg(BES2600_DBG_TXLOOP, "tx loop confirm pending skb.\n");
        bes2600_tx_loop_build_lmac_tx_cfm(hw_priv, skb->data, skb->data_len);
}

void bes2600_tx_loop_record_wsm_cmd(struct bes2600_common *hw_priv, u8 *wsm_cmd)
{
        hw_priv->tx_loop.wsm_cmd_ptr = wsm_cmd;
}

void bes2600_tx_loop_clear_wsm_cmd(struct bes2600_common *hw_priv)
{
        hw_priv->tx_loop.wsm_cmd_ptr = NULL;
}

void bes2600_tx_loop_set_enable(struct bes2600_common *hw_priv)
{
        int i = 0;

        if(hw_priv == NULL)
                return;

        if(hw_priv->tx_loop.enabled)
                return;

        WARN_ON(1);
        hw_priv->tx_loop.enabled = true;
        hw_priv->tx_loop.start_lmac_seq = hw_priv->wsm_rx_seq[0];
        hw_priv->tx_loop.start_mcu_seq = hw_priv->wsm_rx_seq[1];

        if(hw_priv->tx_loop.wsm_cmd_ptr) {
                bes2600_tx_loop_pipe_send(hw_priv, hw_priv->tx_loop.wsm_cmd_ptr, 8);
        }

        for (i = 0; i < 4; i++) {
                bes2600_queue_iterate_pending_packet(&hw_priv->tx_queue[i],
				                bes2600_tx_loop_item_pending_item);
        }

        if (atomic_read(&hw_priv->bh_rx) > 0)
		wake_up(&hw_priv->bh_wq);

}

static void bes2600_tx_loop_build_lmac_generic_cfm(struct bes2600_common *hw_priv, u8 *buf, u32 len)
{
        struct sk_buff *out_skb;
        struct wsm_hdr *rx_wsm, *tx_wsm;
        u32 msg_len = sizeof(struct wsm_hdr) + 4;
        u16 msg_id = 0;

        tx_wsm = (struct wsm_hdr *)buf;

        out_skb = dev_alloc_skb(msg_len);
        if(IS_ERR_OR_NULL(out_skb)) {
                bes2600_err(BES2600_DBG_TXLOOP, "%s, alloc mem fail.\n", __func__);
                return;
        }

        bes2600_dbg(BES2600_DBG_TXLOOP, "%s cmd 0x%04x len:%d\n",
                                __func__, (tx_wsm->id & WSM_MSG_ID_MASK), msg_len);
        skb_put(out_skb, msg_len);
        rx_wsm = (struct wsm_hdr *)out_skb->data;
        msg_id = (tx_wsm->id & WSM_MSG_ID_MASK);
        msg_id |= 0x400;        // set confirm flag
        msg_id |= WSM_TX_SEQ(hw_priv->tx_loop.start_lmac_seq);
        rx_wsm->id = __cpu_to_le16(msg_id);
        rx_wsm->len = __cpu_to_le16(msg_len);
        *((u32 *)&rx_wsm[1]) = __cpu_to_le32(WSM_STATUS_SUCCESS);

        spin_lock(&hw_priv->tx_loop.tx_loop_lock);
        hw_priv->tx_loop.start_lmac_seq = (hw_priv->tx_loop.start_lmac_seq + 1) & 7;
        skb_queue_tail(&hw_priv->tx_loop.rx_queue, out_skb);
        spin_unlock(&hw_priv->tx_loop.tx_loop_lock);

        atomic_add_return(1, &hw_priv->bh_rx);
}

static void bes2600_tx_loop_build_lmac_tx_cfm(struct bes2600_common *hw_priv, u8 *buf, u32 len)
{
        struct sk_buff *out_skb;
        struct wsm_hdr *rx_wsm;
        struct wsm_tx *tx_wsm;
        struct wsm_tx_confirm *cfm;
        u32 msg_len = sizeof(struct wsm_hdr) + sizeof(struct wsm_tx_confirm);
        u16 msg_id = 0;

        tx_wsm = (struct wsm_tx *)buf;

        out_skb = dev_alloc_skb(msg_len);
        if(IS_ERR_OR_NULL(out_skb)) {
                bes2600_err(BES2600_DBG_TXLOOP, "%s, alloc mem fail.\n", __func__);
                return;
        }

        bes2600_dbg(BES2600_DBG_TXLOOP, "%s cmd 0x%04x len:%d\n",
                                __func__, (tx_wsm->hdr.id & WSM_MSG_ID_MASK), msg_len);
        skb_put(out_skb, msg_len);
        rx_wsm = (struct wsm_hdr *)out_skb->data;
        msg_id = (tx_wsm->hdr.id & WSM_MSG_ID_MASK);
        msg_id |= 0x400;        // set confirm flag
        msg_id |= WSM_TX_SEQ(hw_priv->tx_loop.start_lmac_seq);
        rx_wsm->id = __cpu_to_le16(msg_id);
        rx_wsm->len = __cpu_to_le16(msg_len);

        cfm = (struct wsm_tx_confirm *)&rx_wsm[1];
        cfm->packetID = tx_wsm->packetID;
        cfm->status = WSM_STATUS_SUCCESS;
        cfm->txedRate = tx_wsm->maxTxRate;
        cfm->ackFailures = 0;
        cfm->flags = WSM_TX_STATUS_NORMAL_ACK;
        cfm->txQueueDelay = 5;
        cfm->mediaDelay = 3;

        spin_lock(&hw_priv->tx_loop.tx_loop_lock);
        hw_priv->tx_loop.start_lmac_seq = (hw_priv->tx_loop.start_lmac_seq + 1) & 7;
        skb_queue_tail(&hw_priv->tx_loop.rx_queue, out_skb);
        spin_unlock(&hw_priv->tx_loop.tx_loop_lock);

        atomic_add_return(1, &hw_priv->bh_rx);
}

static void bes2600_tx_loop_buid_config_cfm(struct bes2600_common *hw_priv, u8 *buf, u32 len)
{
        struct sk_buff *out_skb;
        struct wsm_hdr *rx_wsm;
        struct wsm_tx *tx_wsm;
        u32 msg_len = sizeof(struct wsm_hdr) + sizeof(struct wsm_configuration) + 4;
        u16 msg_id = 0;

        tx_wsm = (struct wsm_tx *)buf;

        out_skb = dev_alloc_skb(msg_len);
        if(IS_ERR_OR_NULL(out_skb)) {
                bes2600_err(BES2600_DBG_TXLOOP, "%s, alloc mem fail.\n", __func__);
                return;
        }

        bes2600_dbg(BES2600_DBG_TXLOOP, "%s cmd 0x%04x len:%d\n",
                                __func__, (tx_wsm->hdr.id & WSM_MSG_ID_MASK), msg_len);
        skb_put(out_skb, msg_len);
        rx_wsm = (struct wsm_hdr *)out_skb->data;
        msg_id = (tx_wsm->hdr.id & WSM_MSG_ID_MASK);
        msg_id |= 0x400;        // set confirm flag
        msg_id |= WSM_TX_SEQ(hw_priv->tx_loop.start_lmac_seq);
        rx_wsm->id = __cpu_to_le16(msg_id);
        rx_wsm->len = __cpu_to_le16(msg_len);
        *(u32 *)&rx_wsm[1] = WSM_STATUS_SUCCESS;

        spin_lock(&hw_priv->tx_loop.tx_loop_lock);
        hw_priv->tx_loop.start_lmac_seq = (hw_priv->tx_loop.start_lmac_seq + 1) & 7;
        skb_queue_tail(&hw_priv->tx_loop.rx_queue, out_skb);
        spin_unlock(&hw_priv->tx_loop.tx_loop_lock);

        atomic_add_return(1, &hw_priv->bh_rx);
}

static void bes2600_tx_loop_build_read_mib_cfm(struct bes2600_common *hw_priv, u8 *buf, u32 len)
{
        struct sk_buff *out_skb;
        struct wsm_hdr *rx_wsm;
        struct wsm_hdr *tx_wsm = (struct wsm_hdr *)buf;
        struct wsm_mib *mib = (struct wsm_mib *)hw_priv->wsm_cmd.arg;
        u32 *status;
        u16 *mib_id, *size;
        u32 msg_len = sizeof(struct wsm_hdr) + 4 /* status */ + 2 /* mib_id */ + mib->buf_size;
        u16 msg_id = 0;

        out_skb = dev_alloc_skb(msg_len);
        if(IS_ERR_OR_NULL(out_skb)) {
                bes2600_err(BES2600_DBG_TXLOOP, "%s, alloc mem fail.\n", __func__);
                return;
        }

        bes2600_dbg(BES2600_DBG_TXLOOP, "%s cmd 0x%04x len:%d\n",
                                __func__, (tx_wsm->id & WSM_MSG_ID_MASK), msg_len);
        skb_put(out_skb, msg_len);
        rx_wsm = (struct wsm_hdr *)out_skb->data;
        msg_id = (tx_wsm->id & WSM_MSG_ID_MASK);
        msg_id |= 0x400;        // set confirm flag
        msg_id |= WSM_TX_SEQ(hw_priv->tx_loop.start_lmac_seq);
        rx_wsm->id = __cpu_to_le16(msg_id);
        rx_wsm->len = __cpu_to_le16(msg_len);

        status = (u32 *)&rx_wsm[1];
        *status = WSM_STATUS_SUCCESS;

        mib_id = (u16 *)&status[1];
        *mib_id = mib->mibId;

        size = (u16 *)&mib_id[1];
        *size = mib->buf_size;

        spin_lock(&hw_priv->tx_loop.tx_loop_lock);
        hw_priv->tx_loop.start_lmac_seq = (hw_priv->tx_loop.start_lmac_seq + 1) & 7;
        skb_queue_tail(&hw_priv->tx_loop.rx_queue, out_skb);
        spin_unlock(&hw_priv->tx_loop.tx_loop_lock);

        atomic_add_return(1, &hw_priv->bh_rx);
}

static void bes2600_tx_loop_build_join_cfm(struct bes2600_common *hw_priv, u8 *buf, u32 len)
{
        struct sk_buff *out_skb;
        struct wsm_hdr *rx_wsm;
        struct wsm_hdr *tx_wsm = (struct wsm_hdr *)buf;
        u16 msg_id = 0;
        u32 msg_len = sizeof(struct wsm_hdr) + 4 /* status */ + 8 /* power_level */;

        out_skb = dev_alloc_skb(msg_len);
        if(IS_ERR_OR_NULL(out_skb)) {
                bes2600_err(BES2600_DBG_TXLOOP, "%s, alloc mem fail.\n", __func__);
                return;
        }

        bes2600_dbg(BES2600_DBG_TXLOOP, "%s cmd 0x%04x len:%d\n",
                                __func__, (tx_wsm->id & WSM_MSG_ID_MASK), msg_len);
        skb_put(out_skb, msg_len);
        rx_wsm = (struct wsm_hdr *)out_skb->data;
        msg_id = (tx_wsm->id & WSM_MSG_ID_MASK);
        msg_id |= 0x400;        // set confirm flag
        msg_id |= WSM_TX_SEQ(hw_priv->tx_loop.start_lmac_seq);
        rx_wsm->id = __cpu_to_le16(msg_id);
        rx_wsm->len = __cpu_to_le16(msg_len);
        *(u32 *)&rx_wsm[1] = WSM_STATUS_SUCCESS;

        spin_lock(&hw_priv->tx_loop.tx_loop_lock);
        hw_priv->tx_loop.start_lmac_seq = (hw_priv->tx_loop.start_lmac_seq + 1) & 7;
        skb_queue_tail(&hw_priv->tx_loop.rx_queue, out_skb);
        spin_unlock(&hw_priv->tx_loop.tx_loop_lock);

        atomic_add_return(1, &hw_priv->bh_rx);
}

static void bes2600_tx_loop_build_rfcmd_cfm(struct bes2600_common *hw_priv, u8 *buf, u32 len)
{
        struct sk_buff *out_skb;
        struct wsm_mcu_hdr *rx_wsm;
        struct wsm_hdr *tx_wsm = (struct wsm_hdr *)buf;
        u16 msg_id = 0;
        u32 msg_len = sizeof(struct wsm_mcu_hdr);

        out_skb = dev_alloc_skb(msg_len);
        if(IS_ERR_OR_NULL(out_skb)) {
                bes2600_err(BES2600_DBG_TXLOOP, "%s, alloc mem fail.\n", __func__);
                return;
        }

        bes2600_dbg(BES2600_DBG_TXLOOP, "%s cmd 0x%04x len:%d\n",
                                        __func__, (tx_wsm->id & WSM_MSG_ID_MASK), msg_len);
        skb_put(out_skb, msg_len);
        rx_wsm = (struct wsm_mcu_hdr *)out_skb->data;
        msg_id = (tx_wsm->id & WSM_MSG_ID_MASK);
        msg_id |= WSM_TX_SEQ(hw_priv->tx_loop.start_mcu_seq);
        rx_wsm->hdr.id = __cpu_to_le16(msg_id);
        rx_wsm->hdr.len = __cpu_to_le16(msg_len);
        rx_wsm->handle_label = WSM_TO_MCU_CMD_CONFIRM_LABEL;
        rx_wsm->cmd_type = (tx_wsm->id & WSM_MSG_ID_MASK);

        spin_lock(&hw_priv->tx_loop.tx_loop_lock);
        hw_priv->tx_loop.start_mcu_seq = (hw_priv->tx_loop.start_mcu_seq + 1) & 7;
        skb_queue_tail(&hw_priv->tx_loop.rx_queue, out_skb);
        spin_unlock(&hw_priv->tx_loop.tx_loop_lock);

        atomic_add_return(1, &hw_priv->bh_rx);
}

static struct tx_loop_table tx_loop_tbl[] = {
        {.cmd = 0x0004, .proc = bes2600_tx_loop_build_lmac_tx_cfm},
        {.cmd = 0x0009, .proc = bes2600_tx_loop_buid_config_cfm},
        {.cmd = 0x0005, .proc = bes2600_tx_loop_build_read_mib_cfm},
        {.cmd = 0x0006, .proc = bes2600_tx_loop_build_lmac_generic_cfm},
        {.cmd = 0x000B, .proc = bes2600_tx_loop_build_join_cfm},
        {.cmd = 0x0007, .proc = bes2600_tx_loop_build_lmac_generic_cfm},
        {.cmd = 0x0008, .proc = bes2600_tx_loop_build_lmac_generic_cfm},
        {.cmd = 0x000A, .proc = bes2600_tx_loop_build_lmac_generic_cfm},
        {.cmd = 0x000C, .proc = bes2600_tx_loop_build_lmac_generic_cfm},
        {.cmd = 0x000D, .proc = bes2600_tx_loop_build_lmac_generic_cfm},
        {.cmd = 0x0010, .proc = bes2600_tx_loop_build_lmac_generic_cfm},
        {.cmd = 0x0011, .proc = bes2600_tx_loop_build_lmac_generic_cfm},
        {.cmd = 0x0012, .proc = bes2600_tx_loop_build_lmac_generic_cfm},
        {.cmd = 0x0013, .proc = bes2600_tx_loop_build_lmac_generic_cfm},
        {.cmd = 0x0016, .proc = bes2600_tx_loop_build_lmac_generic_cfm},
        {.cmd = 0x0017, .proc = bes2600_tx_loop_build_lmac_generic_cfm},
        {.cmd = 0x0018, .proc = bes2600_tx_loop_build_lmac_generic_cfm},
        {.cmd = 0x0019, .proc = bes2600_tx_loop_build_lmac_generic_cfm},
        {.cmd = 0x001A, .proc = bes2600_tx_loop_build_lmac_generic_cfm},
        {.cmd = 0x001B, .proc = bes2600_tx_loop_build_lmac_generic_cfm},
        {.cmd = 0x001C, .proc = bes2600_tx_loop_build_lmac_generic_cfm},
        {.cmd = 0x0029, .proc = bes2600_tx_loop_build_lmac_generic_cfm},
        {.cmd = 0x0C25, .proc = bes2600_tx_loop_build_rfcmd_cfm}
};

static void bes2600_tx_loop_build_scan_compl_ind(struct bes2600_common *hw_priv)
{
        struct sk_buff *out_skb;
        struct wsm_hdr *rx_wsm;
        struct wsm_scan_complete *scan_compl;
        u16 msg_id = 0;
        u32 msg_len = sizeof(struct wsm_hdr) + sizeof(struct wsm_scan_complete);

        out_skb = dev_alloc_skb(msg_len);
        if(IS_ERR_OR_NULL(out_skb)) {
                bes2600_info(BES2600_DBG_TXLOOP, "%s, alloc mem fail.\n", __func__);
                return;
        }

        bes2600_dbg(BES2600_DBG_TXLOOP, "%s len:%d\n", __func__, msg_len);
        skb_put(out_skb, msg_len);
        rx_wsm = (struct wsm_hdr *)out_skb->data;
        msg_id |= 0x806;        // set indication flag
        msg_id |= WSM_TX_SEQ(hw_priv->tx_loop.start_lmac_seq);
        rx_wsm->id = __cpu_to_le16(msg_id);
        rx_wsm->len = __cpu_to_le16(msg_len);

        scan_compl = (struct wsm_scan_complete *)&rx_wsm[1];
        scan_compl->status = WSM_STATUS_SUCCESS;
        scan_compl->psm = WSM_PSM_PS;
        scan_compl->numChannels = 2;

        spin_lock(&hw_priv->tx_loop.tx_loop_lock);
        hw_priv->tx_loop.start_lmac_seq = (hw_priv->tx_loop.start_lmac_seq + 1) & 7;
        skb_queue_tail(&hw_priv->tx_loop.rx_queue, out_skb);
        spin_unlock(&hw_priv->tx_loop.tx_loop_lock);

        atomic_add_return(1, &hw_priv->bh_rx);
}

static void bes2600_tx_loop_build_pm_ind(struct bes2600_common *hw_priv)
{
        struct sk_buff *out_skb;
        struct wsm_hdr *rx_wsm;
        struct wsm_set_pm_complete *pm_compl;
        u16 msg_id = 0;
        u32 msg_len = sizeof(struct wsm_hdr) + sizeof(struct wsm_set_pm_complete);

        out_skb = dev_alloc_skb(msg_len);
        if(IS_ERR_OR_NULL(out_skb)) {
                bes2600_info(BES2600_DBG_TXLOOP, "%s, alloc mem fail.\n", __func__);
                return;
        }

        bes2600_dbg(BES2600_DBG_TXLOOP, "%s len:%d\n", __func__, msg_len);
        skb_put(out_skb, msg_len);
        rx_wsm = (struct wsm_hdr *)out_skb->data;
        msg_id |= 0x806;        // set indication flag
        msg_id |= WSM_TX_SEQ(hw_priv->tx_loop.start_lmac_seq);
        rx_wsm->id = __cpu_to_le16(msg_id);
        rx_wsm->len = __cpu_to_le16(msg_len);

        pm_compl = (struct wsm_set_pm_complete *)&rx_wsm[1];
        pm_compl->status = WSM_STATUS_SUCCESS;
        pm_compl->psm = WSM_PSM_PS;

        spin_lock(&hw_priv->tx_loop.tx_loop_lock);
        hw_priv->tx_loop.start_lmac_seq = (hw_priv->tx_loop.start_lmac_seq + 1) & 7;
        skb_queue_tail(&hw_priv->tx_loop.rx_queue, out_skb);
        spin_unlock(&hw_priv->tx_loop.tx_loop_lock);

        atomic_add_return(1, &hw_priv->bh_rx);
}

static void bes2600_tx_loop_build_rfcmd_ind(struct bes2600_common *hw_priv, u8 *buf, u32 len)
{
        struct sk_buff *out_skb;
        struct wsm_mcu_hdr *rx_wsm;
        struct wsm_hdr *tx_wsm = (struct wsm_hdr *)buf;
        u16 msg_id = 0;
        u32 msg_len = sizeof(struct wsm_mcu_hdr);

        out_skb = dev_alloc_skb(msg_len);
        if(IS_ERR_OR_NULL(out_skb)) {
                bes2600_err(BES2600_DBG_TXLOOP, "%s, alloc mem fail.\n", __func__);
                return;
        }

        bes2600_dbg(BES2600_DBG_TXLOOP, "%s len:%d\n",__func__, msg_len);
        skb_put(out_skb, msg_len);
        rx_wsm = (struct wsm_mcu_hdr *)out_skb->data;
        msg_id = (tx_wsm->id & WSM_MSG_ID_MASK);
        msg_id |= WSM_TX_SEQ(hw_priv->tx_loop.start_mcu_seq);
        rx_wsm->hdr.id = __cpu_to_le16(msg_id);
        rx_wsm->hdr.len = __cpu_to_le16(msg_len);
        rx_wsm->handle_label = WSM_TO_MCU_CMD_INDICATION_LABEL;
        rx_wsm->cmd_type = (tx_wsm->id & WSM_MSG_ID_MASK);

        spin_lock(&hw_priv->tx_loop.tx_loop_lock);
        hw_priv->tx_loop.start_mcu_seq = (hw_priv->tx_loop.start_mcu_seq + 1) & 7;
        skb_queue_tail(&hw_priv->tx_loop.rx_queue, out_skb);
        spin_unlock(&hw_priv->tx_loop.tx_loop_lock);

        atomic_add_return(1, &hw_priv->bh_rx);
}

void bes2600_tx_loop_pipe_send(struct bes2600_common *hw_priv, u8 *buf, u32 len)
{
        int i = 0;
        int tbl_size = ARRAY_SIZE(tx_loop_tbl);
        struct wsm_hdr *tx_wsm = (struct wsm_hdr *)buf;
        u16 cmd_id = tx_wsm->id & WSM_MSG_ID_MASK;

        /* don't need to tx loop if wifi is unregistered */
        if(hw_priv == NULL)
                return;

        bes2600_dbg(BES2600_DBG_TXLOOP, "tx loop pipe send cmd:0x%04x seq:%d\n",
                                                cmd_id, WSM_MSG_SEQ_GET(tx_wsm->id));

        /* select build confirm function based on command id */
        for(i = 0; i < tbl_size; i++) {
                if(cmd_id == tx_loop_tbl[i].cmd) {
                        tx_loop_tbl[i].proc(hw_priv, buf, len);
                        break;
                }
        }

        /* build indication for special command */
        if(cmd_id == 0x0007) {
                bes2600_tx_loop_build_scan_compl_ind(hw_priv);
        } else if(cmd_id == 0x0010) {
                bes2600_tx_loop_build_pm_ind(hw_priv);
        } else if(cmd_id == 0x0C25) {
                bes2600_tx_loop_build_rfcmd_ind(hw_priv, buf, len);
        }
}