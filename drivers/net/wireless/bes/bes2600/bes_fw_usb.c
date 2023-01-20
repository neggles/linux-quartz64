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
#include "bes_fw_common.h"
#include "bes2600.h"
#include "hwio.h"
#include "sbus.h"
#include "bes2600_driver_mode.h"
#include <linux/string.h>

struct platform_fw_t {
	struct completion completion_tx;
        struct completion completion_rx;
	const struct sbus_ops *sbus_ops;
	struct sbus_priv *sbus_priv;
};

static void bes_fw_irq_handler(void *priv)
{
	struct platform_fw_t *fw_data = (struct platform_fw_t *)priv;
        struct bes2600_common *hw_priv = (struct bes2600_common *)fw_data->priv;
        u32 ctrl_reg, status_reg;

        // read status and control register
        hw_priv->sbus_ops->sbus_reg_read(hw_priv->sbus_priv, BES_USB_CONTROL_REG, &ctrl_reg, 1);
        hw_priv->sbus_ops->sbus_reg_read(hw_priv->sbus_priv, BES_USB_STATUS_REG, &status_reg, 1);
        bes2600_dbg(BES2600_DBG_DOWNLOAD, "%s ctrl_reg:0x%08x status_reg:0x%08x\n", __func__, ctrl_reg, status_reg);

        // notify tx done event
        if((ctrl_reg & BES_USB_FW_TX_DONE) != 0 &&
           (status_reg & BES_USB_FW_TX_DONE) != 0) {
                status_reg &= ~BES_USB_FW_TX_DONE;
                hw_priv->sbus_ops->sbus_reg_write(hw_priv->sbus_priv, BES_USB_STATUS_REG, &status_reg, 1);
                complete(&fw_data->completion_tx);
        }

        // notify rx indication event
        if((ctrl_reg & BES_USB_FW_RX_INDICATION) != 0 &&
           (status_reg & BES_USB_FW_RX_INDICATION) != 0) {
                status_reg &= ~BES_USB_FW_RX_INDICATION;
                hw_priv->sbus_ops->sbus_reg_write(hw_priv->sbus_priv, BES_USB_STATUS_REG, &status_reg, 1);
                complete(&fw_data->completion_rx);
        }
}

static int bes_usb_fw_write(struct platform_fw_t *fw_data, u8* data, size_t len)
{
        size_t length = 0;
        int ret = 0;
        long time_left;
        u32 control_reg = 0;

        // align data size, makes it suite for usb transfer
        length = fw_data->sbus_ops->align_size(fw_data->sbus_priv, len);

        // enable tx done notification
        fw_data->sbus_ops->sbus_reg_read(fw_data->sbus_priv, BES_USB_CONTROL_REG, &control_reg, 1);
        control_reg |= BES_USB_FW_TX_DONE;
        fw_data->sbus_ops->sbus_reg_write(fw_data->sbus_priv, BES_USB_CONTROL_REG, &control_reg, 1);

        // send firmware data to device
        ret = fw_data->sbus_ops->pipe_send(fw_data, BES2600_USB_PIPE_TX_WLAN, length, data);
        if(ret < 0) {
                fw_data->sbus_ops->sbus_reg_read(fw_data->sbus_priv, BES_USB_CONTROL_REG, &control_reg, 1);
                control_reg &= ~BES_USB_FW_TX_DONE;
                fw_data->sbus_ops->sbus_reg_write(fw_data->sbus_priv, BES_USB_CONTROL_REG, &control_reg, 1);
                return ret;
        }

        // wait for sending done of firmware data
        time_left = wait_for_completion_interruptible_timeout(&fw_data->completion_tx, 5*HZ);
        if(time_left == 0)
                ret = -ETIMEDOUT;
        else if(time_left < 0)
                ret = time_left;

        // turn off tx done notification
        fw_data->sbus_ops->sbus_reg_read(fw_data->sbus_priv, BES_USB_CONTROL_REG, &control_reg, 1);
        control_reg &= ~BES_USB_FW_TX_DONE;
        fw_data->sbus_ops->sbus_reg_write(fw_data->sbus_priv, BES_USB_CONTROL_REG, &control_reg, 1);

        return ret;
}

static int bes_firmware_download(struct platform_fw_t *fw_data, const char *fw_name, bool auto_run)
{
	u8 frame_num = 0;
	u8 last_frame_num = 0;

	u16 tx_size = 8192;

	u32 length = 0;
	u32 code_length = 0;

	int ret;

	const u8 *fw_ver_ptr;
	const u8 *data_p;
	u8 *short_buf, *long_buf;
	struct page *record;
	const struct firmware *fw_bin;
        struct sk_buff *skb = NULL;

	struct fw_msg_hdr_t header;
	struct fw_info_t fw_info;
	struct download_fw_t download_addr;
	struct fw_crc_t crc32_t;
	struct run_fw_t run_addr;

        // get firmware data
	ret = request_firmware(&fw_bin, fw_name, NULL);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "request firmware err:%d\n", ret);
		return ret;
	}

        // parse firmware information
	bes2600_info(BES2600_DBG_DOWNLOAD, "%s fw.size=%ld\n", __func__, fw_bin->size);
	bes_parse_fw_info(fw_bin->data, fw_bin->size, &fw_info.addr, &crc32_t.crc32);
	bes2600_info(BES2600_DBG_DOWNLOAD, "------load addr  :0x%08X\n", fw_info.addr);
	bes2600_info(BES2600_DBG_DOWNLOAD, "------data crc   :0x%08X\n", crc32_t.crc32);
	code_length = fw_bin->size - CODE_DATA_USELESS_SIZE;
	bes2600_info(BES2600_DBG_DOWNLOAD, "------code size  :%d\n", code_length);

	fw_ver_ptr = bes2600_get_firmware_version_info(fw_bin->data, fw_bin->size);
	if(fw_ver_ptr == NULL)
		bes2600_err(BES2600_DBG_DOWNLOAD, "------Firmware version get failed\n");
	else
        	bes2600_info(BES2600_DBG_DOWNLOAD, "------Firmware: %s version :%s\n", fw_name ,fw_ver_ptr);

	fw_info.len = code_length;
	data_p = fw_bin->data;

        // construct download information frame
	header.type = FRAME_HEADER_DOWNLOAD_INFO;
	header.seq = frame_num;
	header.len = sizeof(struct fw_info_t);
	last_frame_num = frame_num;
	frame_num++;

	short_buf = kzalloc(512, GFP_KERNEL);
	if (!short_buf)
		return -ENOMEM;
	memcpy(short_buf, (u8 *)&header, sizeof(struct fw_msg_hdr_t));
	memcpy(short_buf + sizeof(struct fw_msg_hdr_t), (u8 *)&fw_info, sizeof(struct fw_info_t));
	length = BES_FW_MSG_TOTAL_LEN(header);

	if (tx_size > length) {
		bes2600_info(BES2600_DBG_DOWNLOAD, "%s", "tx download firmware info\n");
	} else {
		bes2600_err(BES2600_DBG_DOWNLOAD, "%s:%d bes slave has no enough buffer%d/%d\n", __func__, __LINE__, tx_size, length);
		goto err1;
	}

        // send firmware information frame to device and wait tx done
        ret = bes_usb_fw_write(fw_data, short_buf, length);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "tx download firmware info err:%d\n", ret);
		goto err1;
	}

        // wait rx indication
        ret = wait_for_completion_interruptible_timeout(&fw_data->completion_rx, HZ / 5);
        if(ret <= 0) {
                bes2600_err(BES2600_DBG_DOWNLOAD, "usb receive download firmware info response timeout or interrupt\n");
                goto err1;
        }

        // read device response
        skb = fw_data->sbus_ops->pipe_read(fw_data->sbus_priv);
        WARN_ON(!skb);

	//check device rx status
	ret = bes_frame_rsp_check(skb->data, last_frame_num);
        dev_kfree_skb(skb);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "rsp download firmware info err:%d\n", ret);
		goto err1;
	}

	// allocate pages for store download data frame
	record = alloc_pages(GFP_KERNEL, 5);
	long_buf = (u8 *)page_address(record);
	download_addr.addr = fw_info.addr;

        // download firmware data
	while (code_length) {
		if ((code_length + sizeof(struct fw_msg_hdr_t) + sizeof(struct download_fw_t)) < tx_size) {
			length = code_length + sizeof(struct download_fw_t);
		} else {
			length = tx_size - sizeof(struct fw_msg_hdr_t);
		}

		header.type = FRAME_HEADER_DOWNLOAD_DATA;
		header.seq = frame_num;
		header.len = length;
		last_frame_num = frame_num;
		frame_num++;

		memcpy(long_buf, (u8 *)&header, sizeof(struct fw_msg_hdr_t));
		memcpy(long_buf + sizeof(struct fw_msg_hdr_t), &download_addr.addr, sizeof(struct download_fw_t));
		length -= sizeof(struct download_fw_t);//real data length
		memcpy(long_buf + sizeof(struct fw_msg_hdr_t) + sizeof(struct download_fw_t), data_p, length);

		length += (sizeof(struct fw_msg_hdr_t) + sizeof(struct download_fw_t));

		bes2600_info(BES2600_DBG_DOWNLOAD, "tx_download_firmware_data:%x %d\n", download_addr.addr, length);


		ret = bes_usb_fw_write(fw_data, long_buf, length);
		if (ret) {
			bes2600_err(BES2600_DBG_DOWNLOAD, "tx download fw data err:%d\n", ret);
			goto err2;
		}
		length -= (sizeof(struct fw_msg_hdr_t) + sizeof(struct download_fw_t));

                ret = wait_for_completion_interruptible_timeout(&fw_data->completion_rx, HZ / 5);
                if(ret <= 0) {
                        bes2600_err(BES2600_DBG_DOWNLOAD, "usb receive download data response timeout or interrupt\n");
                        goto err1;
                }

		skb = hw_priv->sbus_ops->pipe_read(fw_data->sbus_priv);
                WARN_ON(!skb);

                //check device rx status
                ret = bes_frame_rsp_check(skb->data, last_frame_num);
                dev_kfree_skb(skb);
		if (ret) {
			bes2600_err(BES2600_DBG_DOWNLOAD, "rsp tx download fw err:%d\n", ret);
			goto err2;
		}

		code_length -= length;
		data_p += length;
		download_addr.addr += length;
		bes2600_info(BES2600_DBG_DOWNLOAD, "already tx fw size:%x/%x\n", download_addr.addr - fw_info.addr, fw_info.len);
	}

	//Notify Device:The firmware download is complete
        // construct firmware download end frame
	header.type = FRAME_HEADER_DOWNLOAD_END;
	header.seq = frame_num;
	header.len = sizeof(struct fw_crc_t);
	last_frame_num = frame_num;
	frame_num++;

	memcpy(short_buf, (u8 *)&header, sizeof(struct fw_msg_hdr_t));
	memcpy(short_buf + sizeof(struct fw_msg_hdr_t), (u8 *)&crc32_t.crc32, sizeof(struct fw_crc_t));
	length = BES_FW_MSG_TOTAL_LEN(header);

	bes2600_info(BES2600_DBG_DOWNLOAD, "tx download firmware complete command\n");

        // send frimware download end frame to device
	ret = bes_usb_fw_write(fw_data, short_buf, length);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "tx downlod firmware complete command err:%d\n", ret);
		goto err2;
	}

        // wait device response
	ret = wait_for_completion_interruptible_timeout(&fw_data->completion_rx, HZ / 5);
	if (ret <= 0) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "wait slave process download fw data err:%d\n", ret);
		goto err2;
	}

        // read response data
	skb = hw_priv->sbus_ops->pipe_read(fw_data->sbus_priv);
        WARN_ON(!skb);

        //check device rx status
        ret = bes_frame_rsp_check(skb->data, last_frame_num);
        dev_kfree_skb(skb);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "rsp download firmware complete err:%d\n", ret);
		goto err2;
	}

	if (auto_run == false) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "partial firmware(%s) is downloaded successfully\n", fw_name);
		goto err2;
	}

	//Notify Device:Run firmware
        // construct run code frame
	run_addr.addr = fw_info.addr;

	header.type = FRAME_HEADER_RUN_CODE;
	header.seq = frame_num;
	header.len = sizeof(struct run_fw_t);
	last_frame_num = frame_num;
	frame_num++;

	memcpy(short_buf, (u8 *)&header, sizeof(struct fw_msg_hdr_t));
	memcpy(short_buf + sizeof(struct fw_msg_hdr_t), (u8 *)&run_addr.addr, sizeof(struct run_fw_t));
	length = BES_FW_MSG_TOTAL_LEN(header);

	bes2600_info(BES2600_DBG_DOWNLOAD, "tx run firmware command:0x%X\n", run_addr.addr);

        // send run code frame to device
	ret = bes_usb_fw_write(fw_data, short_buf, length);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "tx run firmware command err:%d\n", ret);
		goto err2;
	}

        // wait device response
	ret = wait_for_completion_interruptible_timeout(&fw_data->completion_rx, HZ / 5);
	if (ret <= 0) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "wait run code err:%d\n", ret);
		goto err2;
	}

        // read response data
	skb = hw_priv->sbus_ops->pipe_read(hw_priv);
        WARN_ON(!skb);

        //check device rx status
        ret = bes_frame_rsp_check(skb->data, last_frame_num);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "rsp run firmware command err:%d\n", ret);
		goto err2;
	}

	bes2600_info(BES2600_DBG_DOWNLOAD, "firmware is downloaded successfully and is already running\n");

err2:
	__free_pages(record, 5);

err1:
	kfree(short_buf);
	release_firmware(fw_bin);

	return ret;
}

int bes2600_load_firmware_usb(struct sbus_ops *ops, struct sbus_priv *priv)
{
	int ret;
	struct platform_fw_t *temp_fw_data;
        u32 control_reg = 0;

	temp_fw_data = kzalloc(sizeof(struct platform_fw_t), GFP_KERNEL);
	if (!temp_fw_data)
		return -ENOMEM;

	init_completion(&temp_fw_data->completion_rx);
        init_completion(&temp_fw_data->completion_tx);
	temp_fw_data->sbus_ops = ops;
	temp_fw_data->sbus_priv = priv;

        // enable rx indication
        temp_fw_data->sbus_ops->sbus_reg_read(temp_fw_data->sbus_priv, BES_USB_CONTROL_REG, &control_reg, 1);
        control_reg |= BES_USB_FW_RX_INDICATION;
        temp_fw_data->sbus_ops->sbus_reg_write(temp_fw_data->sbus_priv, BES_USB_CONTROL_REG, &control_reg, 1);

        // subscribe irq handler
	temp_fw_data->sbus_ops->irq_subscribe(temp_fw_data->sbus_priv,
			(sbus_irq_handler)bes_fw_irq_handler, temp_fw_data);

        // download firmware
	if (bes2600_chrdev_get_fw_type() == BES2600_FW_TYPE_WIFI_SIGNAL) {
		ret = bes_firmware_download(temp_fw_data, BES2600_LOAD_FW_NAME, false);
		if (!ret)
			ret = bes_firmware_download(temp_fw_data, BES2600_LOAD_BOOT_NAME, true);
	} else if (bes2600_chrdev_get_fw_type() == BES2600_FW_TYPE_WIFI_NO_SIGNAL) {
		ret = bes_firmware_download(temp_fw_data, BES2600_LOAD_NOSIGNAL_FW_NAME, false);
		if (!ret)
			ret = bes_firmware_download(temp_fw_data, BES2600_LOAD_BOOT_NAME, true);
	} else {
		ret = bes_firmware_download(temp_fw_data, BES2600_LOAD_BTRF_FW_NAME, true);
	}

        // unsubscribe irq handler
	temp_fw_data->sbus_ops->irq_unsubscribe(temp_fw_data->sbus_priv);

        // disable rx indication
        temp_fw_data->sbus_ops->sbus_reg_read(temp_fw_data->sbus_priv, BES_USB_CONTROL_REG, &control_reg, 1);
        control_reg &= ~BES_USB_FW_RX_INDICATION;
        temp_fw_data->sbus_ops->sbus_reg_write(temp_fw_data->sbus_priv, BES_USB_CONTROL_REG, &control_reg, 1);

	kfree(temp_fw_data);

	return ret;
}