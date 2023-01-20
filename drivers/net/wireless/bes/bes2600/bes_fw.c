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
#include "bes_chardev.h"
#include <linux/string.h>
#include "bes2600_factory.h"

#if defined(FW_DOWNLOAD_BY_SDIO)
//#define BES_FW_BUILTIN
#ifdef BES_FW_BUILTIN
#include "bes_firmware.h"
#endif

struct platform_fw_t {
	struct delayed_work work_data;
	struct sdio_func *func;
	struct completion completion_data;
	const struct sbus_ops *sbus_ops;
	struct sbus_priv *sbus_priv;
};

static void bes_fw_irq_handler(void *priv)
{
	struct platform_fw_t *fw_data = (struct platform_fw_t *)priv;
	bes2600_dbg(BES2600_DBG_DOWNLOAD, "%s\n", __func__);
	complete(&fw_data->completion_data);
}

//#define BES_SLAVE_RX_DOUBLE_CHECK
static int bes_slave_rx_ready(struct platform_fw_t *fw_data, u8* buf_cnt,
					u16* buf_len, int timeout)
{
	int ret;
	unsigned long start = jiffies;

	do {
		ret = bes2600_reg_read(0x108, buf_cnt, 1);
		if (!(ret || buf_cnt)) {
			mdelay(50);
			continue;
		} else if (ret) {
			bes2600_err(BES2600_DBG_DOWNLOAD, "%s,%d err=%d\n", __func__, __LINE__, ret);
		} else {
			ret = bes2600_reg_read_16(0x109, buf_len);
		}
		break;
	} while(time_before(jiffies, start + timeout));

	return ret;
}

//#define BES_SLAVE_TX_DOUBLE_CHECK
//#define MISSED_INTERRUPT_WORKAROUND
static int bes_slave_tx_ready(struct platform_fw_t *fw_data, u16 *tx_len, int timeout)
{
	int ret, retry = 0;

	bes2600_dbg(BES2600_DBG_DOWNLOAD, "%s now=%ld\n", __func__, jiffies);

	msleep(2);

	ret = wait_for_completion_interruptible_timeout(&fw_data->completion_data, timeout);
	if (ret > 0) {
#ifdef MISSED_INTERRUPT_WORKAROUND
test_read_tx:
#endif
		do {
			ret = bes2600_reg_read_16(0, tx_len);
			if (!ret && (*tx_len))
				break;
			else
				bes2600_err(BES2600_DBG_DOWNLOAD,"%s,%d ret=%d tx_len=%x retry=%d\n",
						__func__, __LINE__, ret, *tx_len, retry);
			retry++;
		} while(retry <= 5);
		reinit_completion(&fw_data->completion_data);

	} else if(!ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "%s now=%ld delta=%d\n", __func__, jiffies, timeout);
#ifndef MISSED_INTERRUPT_WORKAROUND
		ret = -110;
#else
		goto test_read_tx;
#endif
	} else {
		// ret = -ERESTARTSYS, to be continued;
	}

	return ret;
}

int bes_host_slave_sync(struct bes2600_common *hw_priv)
{
	u8 val;
	int ret;

	ret = bes2600_reg_read(BES_HOST_INT_REG_ID, &val, 1);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "%s,%d err=%d\n", __func__, __LINE__, ret);
		return ret;
	}

	val |= BES_HOST_INT;
	ret = bes2600_reg_write(BES_HOST_INT_REG_ID, &val, 1);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "%s,%d err=%d\n", __func__, __LINE__, ret);
	}
	return ret;
}

//#define DATA_DUMP_OBSERVE

static int bes_firmware_download_write_reg(struct platform_fw_t *fw_data, u32 addr, u32 val)
{
	u8 frame_num = 0;
	u8 buf_cnt = 0;
	u16 tx_size = 0;
	u16 rx_size = 0;
	u32 length = 0;
	u8 *short_buf;
	int ret;

	struct fw_msg_hdr_t header;
	struct fw_info_t fw_info;
	struct download_fw_t download_addr;

	fw_info.addr = addr;
	fw_info.len = 4;

	ret = bes_slave_rx_ready(fw_data, &buf_cnt, &tx_size, HZ);
	if (!ret) {
		bes2600_dbg(BES2600_DBG_DOWNLOAD, "sdio slave rx buf cnt:%d,buf len max:%d\n", buf_cnt, tx_size);
	} else {
		bes2600_err(BES2600_DBG_DOWNLOAD, "wait bes sdio slave rx ready tiemout:%d\n", ret);
		return ret;
	}

	short_buf = kzalloc(512, GFP_KERNEL);
	if (!short_buf)
		return -ENOMEM;

	header.type = FRAME_HEADER_DOWNLOAD_INFO;
	header.seq = frame_num;
	header.len = sizeof(struct fw_info_t);
	frame_num++;
	memcpy(short_buf, (u8 *)&header, sizeof(struct fw_msg_hdr_t));
	memcpy(short_buf + sizeof(struct fw_msg_hdr_t), (u8 *)&fw_info, sizeof(struct fw_info_t));
	length = BES_FW_MSG_TOTAL_LEN(header);
	length = length > 512 ? length : 512;
	ret = bes2600_data_write(short_buf, length);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "tx download firmware info err:%d\n", ret);
		goto err;
	}

	ret = bes_slave_tx_ready(fw_data, &rx_size, HZ);
	if (!ret) {
		bes2600_dbg(BES2600_DBG_DOWNLOAD, "sdio slave tx ready %d bytes\n", rx_size);
	} else {
		bes2600_err(BES2600_DBG_DOWNLOAD, "wait slave process failed:%d\n", ret);
		goto err;
	}

	ret = bes2600_data_read(short_buf, rx_size);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "rx download firmware info rsp err:%d\n", ret);
		goto err;
	}

	header.type = FRAME_HEADER_DOWNLOAD_DATA;
	header.seq = frame_num;
	header.len = 8;
	frame_num++;

	download_addr.addr = fw_info.addr;

	memcpy(short_buf, (u8 *)&header, sizeof(struct fw_msg_hdr_t));
	memcpy(short_buf + sizeof(struct fw_msg_hdr_t), &download_addr.addr, sizeof(struct download_fw_t));
	memcpy(short_buf + sizeof(struct fw_msg_hdr_t) + sizeof(struct download_fw_t), &val, 4);
	length = BES_FW_MSG_TOTAL_LEN(header);

	length = length > 512 ? length : 512;
	ret = bes2600_data_write(short_buf, length);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "tx download fw data err:%d\n", ret);
		goto err;
	}
	ret = bes_slave_tx_ready(fw_data, &rx_size, HZ);
	if (!ret) {
		bes2600_dbg(BES2600_DBG_DOWNLOAD, "bes_slave ready tx %d bytes\n", rx_size);
	} else {
		bes2600_err(BES2600_DBG_DOWNLOAD, "wait slave process download fw data err:%d\n", ret);
		goto err;
	}

	ret = bes2600_data_read(short_buf, rx_size);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "rx tx download fw data rsp err:%d\n", ret);
		goto err;
	}

err:
	kfree(short_buf);
	return ret;
}

static int bes_firmware_download_write_mem(struct platform_fw_t *fw_data, const u32 addr, const u8 *data, const  u32 len)
{
	u8 frame_num = 0;
	u8 last_frame_num = 0;
	u8 buf_cnt = 0;

	u16 tx_size = 0;
	u16 rx_size = 0;

	u32 length = 0;
	u32 code_length = len;
	u32 retry_cnt = 0;
	int ret;

	const u8 *data_p;
	u8 *short_buf, *long_buf;
	struct page *record;

	struct fw_msg_hdr_t header;
	struct fw_info_t fw_info;
	struct download_fw_t download_addr;
	struct fw_crc_t crc32_t;

retry:
	fw_info.addr = addr;
	fw_info.len = len;
	data_p = data;

	crc32_t.crc32 = 0;
	crc32_t.crc32 ^= 0xffffffffL;
	crc32_t.crc32 = crc32_le(crc32_t.crc32, (u8 *)data, len);
	crc32_t.crc32 ^= 0xffffffffL;

	ret = bes_slave_rx_ready(fw_data, &buf_cnt, &tx_size, HZ);
	if (!ret) {
		bes2600_dbg(BES2600_DBG_DOWNLOAD, "sdio slave rx buf cnt:%d,buf len max:%d\n", buf_cnt, tx_size);
	} else {
		bes2600_info(BES2600_DBG_DOWNLOAD, "wait bes sdio slave rx ready tiemout:%d\n", ret);
		return ret;
	}

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
		bes2600_dbg(BES2600_DBG_DOWNLOAD, "%s", "tx download firmware info\n");
	} else {
		bes2600_info(BES2600_DBG_DOWNLOAD, "%s:%d bes slave has no enough buffer%d/%d\n", __func__, __LINE__, tx_size, length);
		goto err1;
	}

	length = length > 512 ? length : 512;
	ret = bes2600_data_write(short_buf, length);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "tx download firmware info err:%d\n", ret);
		goto err1;
	}

	ret = bes_slave_tx_ready(fw_data, &rx_size, HZ);
	if (!ret) {
		bes2600_dbg(BES2600_DBG_DOWNLOAD, "sdio slave tx ready %d bytes\n", rx_size);
	} else {
		bes2600_info(BES2600_DBG_DOWNLOAD, "wait slave process failed:%d\n", ret);
		goto err1;
	}

	ret = bes2600_data_read(short_buf, rx_size);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "rx download firmware info rsp err:%d\n", ret);
		goto err1;
	}

	//check device rx status
	ret = bes_frame_rsp_check(short_buf, last_frame_num);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "rsp download firmware info err:%d\n", ret);
		goto err1;
	}

	//download firmware
	record = alloc_pages(GFP_KERNEL, 5);
	long_buf = (u8 *)page_address(record);
	download_addr.addr = fw_info.addr;

	while (code_length) {

		ret = bes_slave_rx_ready(fw_data, &buf_cnt, &tx_size, HZ);
		if (ret) {
			goto err2;
		} else {
			bes2600_dbg(BES2600_DBG_DOWNLOAD, "bes salve rx ready %d bytes\n", tx_size);
		}


		if ((tx_size < 4) || (tx_size % 4)) {
			bes2600_err(BES2600_DBG_DOWNLOAD, "%s:%d tx size=%d\n", __func__, __LINE__, tx_size);
			ret = -203;
			goto err2;
		}

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

		bes2600_dbg(BES2600_DBG_DOWNLOAD, "tx_download_firmware_data:%x %d\n", download_addr.addr, length);

		ret = bes2600_data_write(long_buf, length > 512 ? length : 512);
		if (ret) {
			bes2600_err(BES2600_DBG_DOWNLOAD, "tx download fw data err:%d\n", ret);
			goto err2;
		}
		length -= (sizeof(struct fw_msg_hdr_t) + sizeof(struct download_fw_t));

		ret = bes_slave_tx_ready(fw_data, &rx_size, HZ);
		if (!ret) {
			bes2600_dbg(BES2600_DBG_DOWNLOAD, "bes_slave ready tx %d bytes\n", rx_size);
		} else {
			bes2600_err(BES2600_DBG_DOWNLOAD, "wait slave process download fw data err:%d\n", ret);
			goto err2;
		}

		ret = bes2600_data_read(short_buf, rx_size);
		if (ret) {
			bes2600_err(BES2600_DBG_DOWNLOAD, "rx tx download fw data rsp err:%d\n", ret);
			goto err2;
		}

		//check device rx status
		ret = bes_frame_rsp_check(short_buf, last_frame_num);
		if (ret) {
			bes2600_err(BES2600_DBG_DOWNLOAD, "rsp tx download fw err:%d\n", ret);
			goto err2;
		}

		code_length -= length;
		data_p += length;
		download_addr.addr += length;
		bes2600_dbg(BES2600_DBG_DOWNLOAD, "already tx fw size:%x/%x\n", download_addr.addr - fw_info.addr, fw_info.len);
	}

	//Notify Device:The firmware download is complete

	ret = bes_slave_rx_ready(fw_data, &buf_cnt, &tx_size, HZ);
	if (ret) {
		goto err2;
	} else {
		bes2600_dbg(BES2600_DBG_DOWNLOAD, "bes salve rx ready %d bytes\n", tx_size);
	}

	header.type = FRAME_HEADER_DOWNLOAD_END;
	header.seq = frame_num;
	header.len = sizeof(struct fw_crc_t);
	last_frame_num = frame_num;
	frame_num++;

	memcpy(short_buf, (u8 *)&header, sizeof(struct fw_msg_hdr_t));
	memcpy(short_buf + sizeof(struct fw_msg_hdr_t), (u8 *)&crc32_t.crc32, sizeof(struct fw_crc_t));
	length = BES_FW_MSG_TOTAL_LEN(header);

	bes2600_dbg(BES2600_DBG_DOWNLOAD, "%s", "tx download firmware complete command\n");

	length = length > 512 ? length : 512;
	ret = bes2600_data_write(short_buf, length);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "tx downlod firmware complete command err:%d\n", ret);
		goto err2;
	}

	ret = bes_slave_tx_ready(fw_data, &rx_size, HZ);
	if (!ret) {
		bes2600_dbg(BES2600_DBG_DOWNLOAD, "bes_slave ready tx %d bytes\n", rx_size);
	} else {
		bes2600_err(BES2600_DBG_DOWNLOAD, "wait slave process download fw data err:%d\n", ret);
		goto err2;
	}

	ret = bes2600_data_read(short_buf, rx_size);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "receive download firmware complete cmd rsp err:%d\n", ret);
		goto err2;
	}

	//check device rx status
	ret = bes_frame_rsp_check(short_buf, last_frame_num);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "rsp download firmware complete err:%d\n", ret);
		goto err2;
	}
err2:
	__free_pages(record, 5);
err1:
	kfree(short_buf);

	if (ret && retry_cnt < 3) {
		retry_cnt++;
		goto retry;
	}
	return ret;
}

int bes_firmware_download(struct platform_fw_t *fw_data, const char *fw_name, bool auto_run)
{
	u8 frame_num = 0;
	u8 last_frame_num = 0;
	u8 buf_cnt = 0;

	u16 tx_size = 0;
	u16 rx_size = 0;

	u32 length = 0;
	u32 code_length = 0;
	u32 retry_cnt = 0;
	int ret;
	const u8 *fw_ver_ptr;
	const u8 *data_p;
	u8 *short_buf, *long_buf;
	struct page *record;
#ifndef BES_FW_BUILTIN
	const struct firmware *fw_bin;
#endif

#ifdef DATA_DUMP_OBSERVE
	char *observe;
	size_t observe_len;
	loff_t observe_off = 0;
	mm_segment_t old_fs;
	struct file *observe_file = NULL;
#endif

	struct fw_msg_hdr_t header;
	struct fw_info_t fw_info;
	struct download_fw_t download_addr;
	struct fw_crc_t crc32_t;
	struct run_fw_t run_addr;

retry:
#ifndef BES_FW_BUILTIN
	ret = request_firmware(&fw_bin, fw_name, NULL);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "request firmware err:%d\n", ret);
		return ret;
	}
	bes2600_dbg(BES2600_DBG_DOWNLOAD, "%s fw.size=%ld\n", __func__, fw_bin->size);
#endif

#ifdef BES_FW_BUILTIN
	bes_parse_fw_info((u8 *)firmware_device, FIRMWARE_SIZE	, &fw_info.addr, &crc32_t.crc32);
#else
	bes_parse_fw_info(fw_bin->data, fw_bin->size, &fw_info.addr, &crc32_t.crc32);
#endif

	fw_ver_ptr = bes2600_get_firmware_version_info(fw_bin->data, fw_bin->size);
	if(fw_ver_ptr == NULL)
		bes2600_err(BES2600_DBG_DOWNLOAD, "------Firmware version get failed\n");
	else
		bes2600_info(BES2600_DBG_DOWNLOAD, "------Firmware: %s version :%s\n", fw_name ,fw_ver_ptr);

	bes2600_dbg(BES2600_DBG_DOWNLOAD, "------load addr  :0x%08X\n", fw_info.addr);
	bes2600_dbg(BES2600_DBG_DOWNLOAD, "------data crc   :0x%08X\n", crc32_t.crc32);

#ifdef BES_FW_BUILTIN
	code_length = FIRMWARE_SIZE - CODE_DATA_USELESS_SIZE;
#else
	code_length = fw_bin->size - CODE_DATA_USELESS_SIZE;
#endif
	bes2600_dbg(BES2600_DBG_DOWNLOAD, "------code size  :%d\n", code_length);

	fw_info.len = code_length;
#ifdef BES_FW_BUILTIN
	data_p = (u8 *)firmware_device;
#else
	data_p = fw_bin->data;
#endif

	ret = bes_slave_rx_ready(fw_data, &buf_cnt, &tx_size, HZ);
	if (!ret) {
		bes2600_dbg(BES2600_DBG_DOWNLOAD, "sdio slave rx buf cnt:%d,buf len max:%d\n", buf_cnt, tx_size);
	} else {
		bes2600_info(BES2600_DBG_DOWNLOAD, "wait bes sdio slave rx ready tiemout:%d\n", ret);
		return ret;
	}

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

	//mdelay(5000);
	bes2600_dbg_dump(BES2600_DBG_DOWNLOAD, "Fw Info:", short_buf, length);

	if (tx_size > length) {
		bes2600_dbg(BES2600_DBG_DOWNLOAD, "%s", "tx download firmware info\n");
	} else {
		bes2600_info(BES2600_DBG_DOWNLOAD, "%s:%d bes slave has no enough buffer%d/%d\n", __func__, __LINE__, tx_size, length);
		goto err1;
	}

	length = length > 512 ? length : 512;
	ret = bes2600_data_write(short_buf, length);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "tx download firmware info err:%d\n", ret);
		goto err1;
	}

#if 1
	ret = bes_slave_tx_ready(fw_data, &rx_size, HZ);
	if (!ret) {
		bes2600_dbg(BES2600_DBG_DOWNLOAD, "sdio slave tx ready %d bytes\n", rx_size);
	} else {
		bes2600_info(BES2600_DBG_DOWNLOAD, "wait slave process failed:%d\n", ret);
		goto err1;
	}
#ifdef BES_SLAVE_TX_DOUBLE_CHECK
	if (rx_size != 8)
		rx_size = 8;
#endif
#else
	mdelay(100);
	rx_size = 8;
#endif

	ret = bes2600_data_read(short_buf, rx_size);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "rx download firmware info rsp err:%d\n", ret);
		goto err1;
	}

	//check device rx status
	ret = bes_frame_rsp_check(short_buf, last_frame_num);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "rsp download firmware info err:%d\n", ret);
		goto err1;
	}

	//download firmware
	record = alloc_pages(GFP_KERNEL, 5);
	long_buf = (u8 *)page_address(record);
	download_addr.addr = fw_info.addr;

#ifdef DATA_DUMP_OBSERVE
	observe_file = filp_open("/lib/firmware/bes2002_fw_write.bin", O_CREAT | O_RDWR, 0);
	if (IS_ERR(observe_file)) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "create data_dump file err:%ld\n", IS_ERR(observe_file));
		observe_file = NULL;
	}
#endif

	while (code_length) {

#if 1
		ret = bes_slave_rx_ready(fw_data, &buf_cnt, &tx_size, HZ);
		if (ret) {
			goto err2;
		} else {
			bes2600_dbg(BES2600_DBG_DOWNLOAD, "bes salve rx ready %d bytes\n", tx_size);
		}
#endif
#ifdef BES_SLAVE_RX_DOUBLE_CHECK
		tx_size = 512;
#endif

		if ((tx_size < 4) || (tx_size % 4)) {
			bes2600_err(BES2600_DBG_DOWNLOAD, "%s:%d tx size=%d\n", __func__, __LINE__, tx_size);
			ret = -203;
			goto err2;
		}

		if ((code_length + sizeof(struct fw_msg_hdr_t) + sizeof(struct download_fw_t)) < tx_size) {
			length = code_length + sizeof(struct download_fw_t);
		} else {
			length = tx_size - sizeof(struct fw_msg_hdr_t);
		}

#if 0 // for SDIO_USE_V2
		if (length + sizeof(struct fw_msg_hdr_t) > func->cur_blksize) {
			length = (length + sizeof(struct fw_msg_hdr_t)) / func->cur_blksize * func->cur_blksize;
			length -= sizeof(struct fw_msg_hdr_t);
		}
#endif

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

		//mdelay(5000);
		bes2600_dbg(BES2600_DBG_DOWNLOAD, "tx_download_firmware_data:%x %d\n", download_addr.addr, length);

#ifdef DATA_DUMP_OBSERVE
		if (observe_file) {
			observe = (char *)(long_buf + sizeof(struct fw_msg_hdr_t) + sizeof(struct download_fw_t));
			observe_len = length - sizeof(struct fw_msg_hdr_t) - sizeof(struct download_fw_t);
			old_fs = get_fs();
			set_fs(KERNEL_DS);
			vfs_write(observe_file, observe, observe_len, &observe_off);
			set_fs(old_fs);
		}
#endif

		ret = bes2600_data_write(long_buf, length > 512 ? length : 512);
		if (ret) {
			bes2600_err(BES2600_DBG_DOWNLOAD, "tx download fw data err:%d\n", ret);
			goto err2;
		}
		length -= (sizeof(struct fw_msg_hdr_t) + sizeof(struct download_fw_t));

#if 1
		ret = bes_slave_tx_ready(fw_data, &rx_size, HZ);
		if (!ret) {
			bes2600_dbg(BES2600_DBG_DOWNLOAD, "bes_slave ready tx %d bytes\n", rx_size);
		} else {
			bes2600_err(BES2600_DBG_DOWNLOAD, "wait slave process download fw data err:%d\n", ret);
			goto err2;
		}
#ifdef BES_SLAVE_TX_DOUBLE_CHECK
	if (rx_size != 8)
		rx_size = 8;
#endif
#else
		mdelay(100);
		rx_size = 8;
#endif

		ret = bes2600_data_read(short_buf, rx_size);
		if (ret) {
			bes2600_err(BES2600_DBG_DOWNLOAD, "rx tx download fw data rsp err:%d\n", ret);
			goto err2;
		}

		//check device rx status
		ret = bes_frame_rsp_check(short_buf, last_frame_num);
		if (ret) {
			bes2600_err(BES2600_DBG_DOWNLOAD, "rsp tx download fw err:%d\n", ret);
			goto err2;
		}

		code_length -= length;
		data_p += length;
		download_addr.addr += length;
		bes2600_dbg(BES2600_DBG_DOWNLOAD, "already tx fw size:%x/%x\n", download_addr.addr - fw_info.addr, fw_info.len);
	}

	//Notify Device:The firmware download is complete

#if 1
	ret = bes_slave_rx_ready(fw_data, &buf_cnt, &tx_size, HZ);
	if (ret) {
		goto err2;
	} else {
		bes2600_dbg(BES2600_DBG_DOWNLOAD, "bes salve rx ready %d bytes\n", tx_size);
	}
#endif
#ifdef BES_SLAVE_RX_DOUBLE_CHECK
		tx_size = 512;
#endif

	header.type = FRAME_HEADER_DOWNLOAD_END;
	header.seq = frame_num;
	header.len = sizeof(struct fw_crc_t);
	last_frame_num = frame_num;
	frame_num++;

	memcpy(short_buf, (u8 *)&header, sizeof(struct fw_msg_hdr_t));
	memcpy(short_buf + sizeof(struct fw_msg_hdr_t), (u8 *)&crc32_t.crc32, sizeof(struct fw_crc_t));
	length = BES_FW_MSG_TOTAL_LEN(header);

	bes2600_dbg(BES2600_DBG_DOWNLOAD, "%s", "tx download firmware complete command\n");

	length = length > 512 ? length : 512;
	ret = bes2600_data_write(short_buf, length);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "tx downlod firmware complete command err:%d\n", ret);
		goto err2;
	}

#if 1
	ret = bes_slave_tx_ready(fw_data, &rx_size, HZ);
	if (!ret) {
		bes2600_dbg(BES2600_DBG_DOWNLOAD, "bes_slave ready tx %d bytes\n", rx_size);
	} else {
		bes2600_err(BES2600_DBG_DOWNLOAD, "wait slave process download fw data err:%d\n", ret);
		goto err2;
	}
#ifdef BES_SLAVE_TX_DOUBLE_CHECK
	if (rx_size != 8)
		rx_size = 8;
#endif
#else
	mdelay(100);
	rx_size = 8;
	bes2600_info(BES2600_DBG_DOWNLOAD, "enter sdio irqs:%d", enter_sdio_irqs);
#endif

	ret = bes2600_data_read(short_buf, rx_size);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "receive download firmware complete cmd rsp err:%d\n", ret);
		goto err2;
	}

	//check device rx status
	ret = bes_frame_rsp_check(short_buf, last_frame_num);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "rsp download firmware complete err:%d\n", ret);
		goto err2;
	}

	if (auto_run == false) {
		bes2600_info(BES2600_DBG_DOWNLOAD, "partial firmware(%s) is downloaded successfully\n", fw_name);
		goto err2;
	}

#if 1
	ret = bes_slave_rx_ready(fw_data, &buf_cnt, &tx_size, HZ);
	if (ret) {
		goto err2;
	} else {
		bes2600_dbg(BES2600_DBG_DOWNLOAD, "bes salve rx ready %d bytes\n", tx_size);
	}
#endif
#ifdef BES_SLAVE_RX_DOUBLE_CHECK
	tx_size = 512;
#endif

	//Notify Device:Run firmware
	run_addr.addr = fw_info.addr;

	header.type = FRAME_HEADER_RUN_CODE;
	header.seq = frame_num;
	header.len = sizeof(struct run_fw_t);
	last_frame_num = frame_num;
	frame_num++;

	memcpy(short_buf, (u8 *)&header, sizeof(struct fw_msg_hdr_t));
	memcpy(short_buf + sizeof(struct fw_msg_hdr_t), (u8 *)&run_addr.addr, sizeof(struct run_fw_t));
	length = BES_FW_MSG_TOTAL_LEN(header);

	bes2600_dbg(BES2600_DBG_DOWNLOAD, "tx run firmware command:0x%X\n", run_addr.addr);

	length = length > 512 ? length : 512;
	ret = bes2600_data_write(short_buf, length);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "tx run firmware command err:%d\n", ret);
		goto err2;
	}

#if 1
	ret = bes_slave_tx_ready(fw_data, &rx_size, HZ);
	if (!ret) {
		bes2600_dbg(BES2600_DBG_DOWNLOAD, "bes_slave ready tx %d bytes\n", rx_size);
	} else {
		bes2600_err(BES2600_DBG_DOWNLOAD, "wait slave process run fw cmd err:%d\n", ret);
		goto err2;
	}
#ifdef BES_SLAVE_TX_DOUBLE_CHECK
	if (rx_size != 8)
		rx_size = 8;
#endif
#else
	mdelay(100);
	rx_size = 8;
#endif

	ret = bes2600_data_read(short_buf, rx_size);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "rx run firmware command err:%d\n", ret);
		goto err2;
	}

	//check device rx status
	ret = bes_frame_rsp_check(short_buf, last_frame_num);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "rsp run firmware command err:%d\n", ret);
		goto err2;
	}

	bes2600_info(BES2600_DBG_DOWNLOAD, "%s", "firmware is downloaded successfully and is already running\n");
	msleep(500);

err2:
	__free_pages(record, 5);
#ifdef DATA_DUMP_OBSERVE
	if (observe_file) {
		filp_close(observe_file, NULL);
	}
#endif
err1:
	kfree(short_buf);
#ifndef BES_FW_BUILTIN
	release_firmware(fw_bin);
#endif
	if (ret && retry_cnt < 3) {
		retry_cnt++;
		goto retry;
	}
	return ret;
}

static int bes_read_dpd_data(struct platform_fw_t *fw_data)
{
	u16 dpd_size = 0;
	int ret = 0;
	u8 *dpd_buf = NULL;
	u8 mcu_status = 0;
	unsigned long wait_timeout;

	/* wait for device ready */
	wait_timeout = jiffies + 15 * HZ;
	do {
		msleep(100);
		ret = bes2600_reg_read(BES_SLAVE_STATUS_REG_ID, &mcu_status, 1);
	} while(((ret == 0) || (ret == -84)) &&
	        !(mcu_status & BES_SLAVE_STATUS_DPD_READY) &&
		time_before(jiffies, wait_timeout));

	/* check if read dpd error */
	if(ret < 0 || time_after(jiffies, wait_timeout)) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "wait dpd data ready failed:%d\n", ret);
		return -1;
	}

	/* wait dpd read ready */
	ret = bes_slave_tx_ready(fw_data, &dpd_size, HZ);
	if (ret)  {
		bes2600_err(BES2600_DBG_DOWNLOAD, "wait dpd data failed:%d\n", ret);
		return -1;
	}

	/* read dpd data */
	dpd_buf = bes2600_chrdev_get_dpd_buffer(dpd_size);
	if(!dpd_buf) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "allocate dpd buffer failed.\n");
		return -1;
	}

	ret = bes2600_data_read(dpd_buf, dpd_size);
	bes2600_info(BES2600_DBG_DOWNLOAD, "read dpd data size:%d\n", dpd_size);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "read dpd data failed:%d\n", ret);
		bes2600_chrdev_free_dpd_data();
		return -1;
	}

	/* update dpd data */
	ret = bes2600_chrdev_update_dpd_data();

	return ret;
}

#ifdef BES2600_DUMP_FW_DPD_LOG
struct dpd_log_head_para {
	/* log offset, and file save is limited to 10 times */
	u32 count;
	u32 offset[11];
	u32 overlap;
	u32 pre_head_s;
	u32 file_size;
	u32 file_size_pre;
};
#define DPD_LOG_SAVE_NUM_MAX 10
#define HEAD_BUF_MAX 305
#define HEAD_BUF_CONST_CHAR_NUM 95
#define DPD_LOG_LABEL_NUM 28
#define DPD_LOG_LABEL "\n\n[log_count]:%13u\n"
#define DPD_LOG_HEAD "count:%u\n\
head_s:%10u\n\
log%u_s:%u\n\
log%u_s:%u\n\
log%u_s:%u\n\
log%u_s:%u\n\
log%u_s:%u\n\
log%u_s:%u\n\
log%u_s:%u\n\
log%u_s:%u\n\
log%u_s:%u\n\
log%u_s:%u\n"


static int dpd_log_numlen(u32 num)
{
    int len = 0;
	if (num == 0)
		return 1;

	while (num) {
		num /= 10;
		len++;
	}

    return len;
}

static void bes2600_dpd_log_file_info_update(struct dpd_log_head_para *head, int size)
{
	int i;

	head->overlap = 0;
	head->count += 1;

	if (head->count <= DPD_LOG_SAVE_NUM_MAX) {
		head->offset[head->count] = size;
	} else {
		head->overlap = head->offset[1];
		for (i = 1; i < DPD_LOG_SAVE_NUM_MAX; i++)
			head->offset[i] = head->offset[i + 1];

		head->offset[DPD_LOG_SAVE_NUM_MAX] = size;
	}

}

static int bes2600_dpd_log_file_get_head(struct file *fp, struct dpd_log_head_para *head, u8 *head_buf)
{
	int ret, i;
	u32 beg_num[DPD_LOG_SAVE_NUM_MAX];

	if (fp->f_inode->i_size == 0)
		return 0;

	fp->f_pos = 0;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))
	ret = kernel_read(fp, head_buf, HEAD_BUF_MAX, &fp->f_pos);
#else
	ret = kernel_read(fp, fp->f_pos, head_buf, HEAD_BUF_MAX);
#endif
	if (ret < 0) {
		bes2600_err_with_cond(ret < 0, BES2600_DBG_CHARDEV, "dpd log head info get fail\n");
		return -1;
	}

	ret = sscanf(head_buf, DPD_LOG_HEAD, &head->count, &head->offset[0],
		&beg_num[0], &head->offset[1], &beg_num[1], &head->offset[2], &beg_num[2], &head->offset[3],
		&beg_num[3], &head->offset[4],&beg_num[4], &head->offset[5], &beg_num[5], &head->offset[6],
		&beg_num[6], &head->offset[7], &beg_num[7], &head->offset[8],
		&beg_num[8], &head->offset[9], &beg_num[9], &head->offset[10]);

	if (ret != 22) {
		bes2600_err_with_cond(ret < 0, BES2600_DBG_CHARDEV, "dpd log head info parse fail, rebuild\n");
		return -2;
	}

	head->pre_head_s = head->offset[0];

	for (i = 0; i < DPD_LOG_SAVE_NUM_MAX + 1; i++)
		head->file_size_pre += head->offset[i];

	return 0;
}

static int bes2600_dpd_log_file_head_handler(struct file *fp, struct dpd_log_head_para *head, int size, u8 *head_buf)
{
	int ret, i, offset = 0;
	u8 tmp[HEAD_BUF_MAX + 1];
	u32 beg_num[DPD_LOG_SAVE_NUM_MAX];
	u32 head_size = HEAD_BUF_CONST_CHAR_NUM;
	head->file_size = 0;

	/* update head info */
	bes2600_dpd_log_file_info_update(head, size);

	if (head->count > DPD_LOG_SAVE_NUM_MAX)
		offset = head->count - DPD_LOG_SAVE_NUM_MAX;

	for (i = 0; i < DPD_LOG_SAVE_NUM_MAX; i++) {
		beg_num[i] = i + 1 + offset;
		head_size += dpd_log_numlen(beg_num[i]);
	}

	for (i = 1; i <= DPD_LOG_SAVE_NUM_MAX; i++) {
		head->file_size += head->offset[i];
		head_size += dpd_log_numlen(head->offset[i]);
	}

	head_size += dpd_log_numlen(head->count);

	head->offset[0] = head_size;
	head->file_size += head_size;


	/* bulid head */
	ret = snprintf(tmp, HEAD_BUF_MAX + 1, DPD_LOG_HEAD, head->count, head->offset[0],
		beg_num[0], head->offset[1], beg_num[1], head->offset[2], beg_num[2], head->offset[3],
		beg_num[3], head->offset[4],beg_num[4], head->offset[5], beg_num[5], head->offset[6],
		beg_num[6], head->offset[7], beg_num[7], head->offset[8],
		beg_num[8], head->offset[9], beg_num[9], head->offset[10]);

	if (ret < 0)
		return -1;

	memcpy(head_buf, tmp, ret);
	return ret;
}

static int bes2600_genric_kernel_write(struct file *fp, const void *buf, size_t count,
			    loff_t pos)
{
	int ret;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))
	ret = kernel_write(fp, buf, count, &pos);
#else
	ret = kernel_write(fp, buf, count, pos);
#endif

	return ret;
}


static int bes2600_write_dpd_log_to_file(const char *path, void *buffer, int size)
{
	int ret = 0;
	struct file *fp;
	u8 head_buf[HEAD_BUF_MAX] = {0};
	u8 *dpd_buf_trans = NULL;
	struct dpd_log_head_para head = {0};
	u8 tmp[DPD_LOG_LABEL_NUM + 1];
	loff_t pos_tmp;

	if(buffer == NULL || size == 0)
		return 0;

	fp = filp_open(path, O_RDWR | O_CREAT, S_IRUSR);
	if (IS_ERR(fp)) {
		bes2600_err(BES2600_DBG_CHARDEV, "BES2600 : can't open %s\n", path);
		return -1;
	}

	/* get head info */
	ret = bes2600_dpd_log_file_get_head(fp, &head, head_buf);
	if (ret == -2 || head.file_size_pre != fp->f_inode->i_size || head.file_size_pre == 0) {
		/* clear head info, rebuild a new file from count 1 */
		memset(&head, 0, sizeof(struct dpd_log_head_para));
		goto rebuild;
	} else if (ret < 0) {
		ret = -1;
		goto out1;
	} else {
		dpd_buf_trans = kzalloc(head.file_size_pre, GFP_KERNEL);
		if (!dpd_buf_trans) {
			bes2600_err(BES2600_DBG_CHARDEV, "dpd log buffer alloc fail\n");
			ret = -1;
			goto out1;
		}
		/* read build info */
		pos_tmp = 0;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))
		ret = kernel_read(fp, dpd_buf_trans, head.file_size_pre, &pos_tmp);
#else
		ret = kernel_read(fp, pos_tmp, dpd_buf_trans, head.file_size_pre);
#endif
		if (ret < 0) {
			bes2600_err_with_cond(ret < 0, BES2600_DBG_CHARDEV, "read dpd log file failed\n");
			ret = -1;
			goto out;
		}
	}

rebuild:
	filp_close(fp, NULL);
	/* rebuild */
	fp = filp_open(path, O_TRUNC | O_CREAT | O_RDWR, S_IRUSR);
	if (IS_ERR(fp)) {
		bes2600_err(BES2600_DBG_CHARDEV, "BES2600 : can't open %s\n", path);
		ret = -1;
		goto out;
	}

	if (bes2600_dpd_log_file_head_handler(fp, &head, size, head_buf) <= 0) {
		bes2600_err(BES2600_DBG_CHARDEV, "dpd log head info handel fail\n");
		ret = -1;
		goto out;
	}

	/* upadte log file head */
	ret = bes2600_genric_kernel_write(fp, head_buf, head.offset[0], 0);
	if (ret < 0) {
		bes2600_err_with_cond(ret < 0, BES2600_DBG_CHARDEV, "write dpd log to file failed\n");
		ret = -1;
		goto out;
	}

	/* upadte log file */
	if (head.count > 1 && head.file_size_pre > 0) {
		ret = bes2600_genric_kernel_write(fp, dpd_buf_trans + head.pre_head_s + head.overlap,
				head.file_size_pre - head.pre_head_s - head.overlap, head.offset[0]);
		if (ret < 0) {
			bes2600_err_with_cond(ret < 0, BES2600_DBG_CHARDEV, "write dpd log to file failed\n");
			ret = -1;
			goto out;
		}
	}

	if (head.count > DPD_LOG_SAVE_NUM_MAX)
		pos_tmp = head.file_size - head.offset[DPD_LOG_SAVE_NUM_MAX];
	else
		pos_tmp = head.file_size - head.offset[head.count];

	snprintf(tmp, DPD_LOG_LABEL_NUM + 1, DPD_LOG_LABEL, head.count);
	memcpy(buffer, tmp, DPD_LOG_LABEL_NUM);
	ret = bes2600_genric_kernel_write(fp, buffer, size, pos_tmp);
	if (ret < 0) {
		bes2600_err_with_cond(ret < 0, BES2600_DBG_CHARDEV, "write dpd log to file failed\n");
		ret = -1;
		goto out;
	}

	bes2600_info(BES2600_DBG_CHARDEV, "write dpd log to %s\n", path);

out:
	kfree(dpd_buf_trans);
out1:
	filp_close(fp, NULL);
	return ret;
}

static int bes_read_dpd_log(struct platform_fw_t *fw_data)
{
	u16 dpd_log_size = 0;
	int ret = 0;
	u8 mcu_status = 0;
	u8 *dpd_log = NULL;
	unsigned long wait_timeout;
	//u8 *log_tmp = NULL;

	/* wait for device ready */
	wait_timeout = jiffies + 5 * HZ;
	do {
		msleep(10);
		ret = bes2600_reg_read(BES_SLAVE_STATUS_REG_ID, &mcu_status, 1);
	} while(((ret == 0) || (ret == -84)) &&
	        !(mcu_status & BES_SLAVE_STATUS_DPD_LOG_READY) &&
		time_before(jiffies, wait_timeout));
	
	if(ret < 0 || time_after(jiffies, wait_timeout)) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "wait dpd log ready failed:%d\n", ret);
		return -1;
	}

	/* wait dpd log dump data ready */
	ret = bes_slave_tx_ready(fw_data, &dpd_log_size, HZ);
	if (ret) {
		msleep(100);
		bes2600_err(BES2600_DBG_DOWNLOAD, "wait dpd log failed:%d\n", ret);
		return -1;
	}

	dpd_log = kmalloc(dpd_log_size + DPD_LOG_LABEL_NUM, GFP_KERNEL);
	if(!dpd_log) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "dpd log buffer alloc fail");
		return -1;
	}

	ret = bes2600_data_read(dpd_log + DPD_LOG_LABEL_NUM, dpd_log_size);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "read dpd log failed:%d\n", ret);
		kfree(dpd_log);
		return -1;
	}

	bes2600_info(BES2600_DBG_DOWNLOAD, "read dpd log size: %u\n", dpd_log_size);
	bes2600_write_dpd_log_to_file(BES2600_DPD_LOG_PATH, dpd_log, dpd_log_size + DPD_LOG_LABEL_NUM);

#if 0
	bes2600_info(BES2600_DBG_DOWNLOAD, "[dpd_log]:\n");
	log_tmp = dpd_log + DPD_LOG_LABEL_NUM;
	while ((token = strsep(&log_tmp, "\n")) != NULL) {
		bes2600_info(BES2600_DBG_DOWNLOAD, "%s\n", token);
	}
#endif
	kfree(dpd_log);

	return ret;
}
#endif /* BES2600_DUMP_FW_DPD_LOG */

static int bes2600_load_wifi_firmware(struct platform_fw_t *fw_data)
{
	int ret = 0;
	const char *fw_name_tbl[3];
	int fw_type = bes2600_chrdev_get_fw_type();

	fw_name_tbl[0] = BES2600_LOAD_FW_NAME;
	fw_name_tbl[1] = BES2600_LOAD_NOSIGNAL_FW_NAME;
	fw_name_tbl[2] = BES2600_LOAD_BTRF_FW_NAME;

	bes2600_info(BES2600_DBG_DOWNLOAD, "bes2600 download cali and wifi signal firmware.\n");
	ret = bes_firmware_download(fw_data, BES2600_LOAD_BOOT_NAME, true);
	bes2600_err_with_cond(ret, BES2600_DBG_DOWNLOAD, "download dpd cali firmware failed\n");

	if (!ret) {
		bes2600_info(BES2600_DBG_DOWNLOAD, "bes2600 read dpd cali data.\n");
		ret = bes_read_dpd_data(fw_data);
		bes2600_err_with_cond(ret, BES2600_DBG_DOWNLOAD, "read dpd data failed.\n");
	}

#ifdef BES2600_DUMP_FW_DPD_LOG
	if (!ret) {
		bes2600_info(BES2600_DBG_DOWNLOAD, "bes2600 read dpd log data.\n");
		ret = bes_read_dpd_log(fw_data);
		bes2600_err_with_cond(ret, BES2600_DBG_DOWNLOAD, "dump dpd log failed.\n");
	}
#endif

	/* for wifi non-signal mode, download second firmware directly */
	if (!ret && bes2600_chrdev_check_system_close()) {
		bes2600_info(BES2600_DBG_DOWNLOAD, "bes2600 device power down.\n");
		ret = bes2600_chrdev_do_system_close(fw_data->sbus_ops, fw_data->sbus_priv);
		bes2600_err_with_cond(ret, BES2600_DBG_DOWNLOAD, "device down fail.\n");
	} else if(!ret) {
		ret = bes_firmware_download(fw_data, fw_name_tbl[fw_type], true);
		bes2600_err_with_cond(ret, BES2600_DBG_DOWNLOAD, "download normal firmware failed.\n");
	}

	return ret;
}

static int bes2600_load_wifi_firmware_with_dpd(struct platform_fw_t *fw_data)
{
	int ret = 0;
	u32 dpd_data_len = 0;
	const u8 *dpd_data = NULL;
	const char *fw_name_tbl[3];
	int fw_type = bes2600_chrdev_get_fw_type();

	fw_name_tbl[0] = BES2600_LOAD_FW_NAME;
	fw_name_tbl[1] = BES2600_LOAD_NOSIGNAL_FW_NAME;
	fw_name_tbl[2] = BES2600_LOAD_BTRF_FW_NAME;

	dpd_data = bes2600_chrdev_get_dpd_data(&dpd_data_len);
	BUG_ON(!dpd_data);

	bes2600_info(BES2600_DBG_DOWNLOAD, "bes2600 download firmware with dpd.\n");
	ret = bes_firmware_download_write_mem(fw_data, BES2600_DPD_ADDR, dpd_data, dpd_data_len);
	bes2600_err_with_cond(ret, BES2600_DBG_DOWNLOAD, "download dpd data failed.\n");
	if (!ret) {
		ret = bes_firmware_download(fw_data, fw_name_tbl[fw_type], true);
		bes2600_err_with_cond(ret, BES2600_DBG_DOWNLOAD, "download firmware failed after dpd download.\n");
	}

	return ret;
}

static int bes2600_load_bt_firmware(struct platform_fw_t *fw_data)
{
	int ret = 0;

	/* for bt mode, don't need to download dpd cali firmware*/
	bes2600_info(BES2600_DBG_DOWNLOAD, "download bt test firmware.\n");
	ret = bes_firmware_download(fw_data, BES2600_LOAD_BTRF_FW_NAME, true);
	bes2600_err_with_cond(ret, BES2600_DBG_DOWNLOAD, "download normal firmware failed.\n");

	return ret;

}

int bes2600_load_firmware_sdio(struct sbus_ops *ops, struct sbus_priv *priv)
{
	int ret = 0;
	struct platform_fw_t *temp_fw_data;
	u32 dpd_data_len = 0;
	const u8 *dpd_data = NULL;
	int fw_type = bes2600_chrdev_get_fw_type();
#ifdef CONFIG_BES2600_CALIB_FROM_LINUX
	u8 *factory_data = NULL;
	u32 factory_data_len = 0;
#endif

	temp_fw_data = kzalloc(sizeof(struct platform_fw_t), GFP_KERNEL);
	if (!temp_fw_data)
		return -ENOMEM;

	init_completion(&temp_fw_data->completion_data);
	temp_fw_data->sbus_ops = ops;
	temp_fw_data->sbus_priv = priv;

	temp_fw_data->sbus_ops->irq_subscribe(temp_fw_data->sbus_priv,
			(sbus_irq_handler)bes_fw_irq_handler, temp_fw_data);

	bes_firmware_download_write_reg(temp_fw_data, 0x40100000, 0x802006);
	bes_firmware_download_write_reg(temp_fw_data, 0x4008602C, 0x3E00C000);

#ifdef CONFIG_BES2600_CALIB_FROM_LINUX
	factory_data = bes2600_get_factory_cali_data(&factory_data_len);
	if (!factory_data) {
		bes2600_warn(BES2600_DBG_DOWNLOAD, "factory cali data get failed.\n");
	} else {
		factory_little_endian_cvrt(factory_data);
		ret = bes_firmware_download_write_mem(temp_fw_data, BES2600_FACTORY_ADDR, factory_data, factory_data_len);
		factory_little_to_cpu_cvrt(factory_data);
		bes2600_err_with_cond(ret, BES2600_DBG_DOWNLOAD, "download factory data failed.\n");
	}
#endif

	bes2600_info(BES2600_DBG_DOWNLOAD, "%s fw_type:%d.\n", __func__, fw_type);
	if(fw_type == BES2600_FW_TYPE_BT) {
		ret = bes2600_load_bt_firmware(temp_fw_data);
	} else {
		dpd_data = bes2600_chrdev_get_dpd_data(&dpd_data_len);
		if(dpd_data) {
			ret = bes2600_load_wifi_firmware_with_dpd(temp_fw_data);
		} else {
			ret = bes2600_load_wifi_firmware(temp_fw_data);
		}
	}


	/* don't register net device when wifi is closed */
	if(!ret && !bes2600_chrdev_is_wifi_opened()) {
		ret = 1;
	}


	temp_fw_data->sbus_ops->irq_unsubscribe(temp_fw_data->sbus_priv);
	kfree(temp_fw_data);

	bes2600_info(BES2600_DBG_DOWNLOAD, "download finished ,wifi_state:%d result is %d\n", bes2600_chrdev_is_wifi_opened(), ret);

	return ret;
}
#endif

#if defined(BES2600_BOOT_UART_TO_SDIO)
static struct uart_dld_work_t {
	struct work_struct dld_work;
	struct completion completion_data;
	void *priv;
} uart_dld_data;

void bes2600_load_firmware_uart_work(struct work_struct *work)
{
	int ret;
#if defined(BES2600_LOAD_FW_TOOL_PATH) && defined(BES2600_LOAD_FW_TOOL_DEVICE) && defined(BES2600_LOAD_BOOT_PATCH_NAME)
	char cmd_path[] = BES2600_LOAD_FW_TOOL_PATH;
	char *cmd_argv[] = {cmd_path, BES2600_LOAD_FW_TOOL_DEVICE, BES2600_LOAD_BOOT_PATCH_NAME, NULL};
	char *cmd_envp[] = {"HOME=/", "PATH=/sbin:/bin:/user/bin:/system/bin:/usr/bin", NULL};
#else
	#error "BES uart download should specify fimrware load tool"
#endif
	complete(&uart_dld_data.completion_data);
	if ((ret = call_usermodehelper(cmd_path, cmd_argv, cmd_envp, UMH_WAIT_PROC))) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "call_usermodehelper failed:%d\n", ret);
	} else {
		msleep(200);
		complete(&uart_dld_data.completion_data);
	}
}

int bes2600_boot_uart_to_sdio(struct sbus_ops *ops)
{
	int ret, retry = 0;

uart_dld:
	memset(&uart_dld_data, 0, sizeof(uart_dld_data));
	init_completion(&uart_dld_data.completion_data);
	INIT_WORK(&uart_dld_data.dld_work, bes2600_load_firmware_uart_work);
	schedule_work(&uart_dld_data.dld_work);
	ret = wait_for_completion_interruptible_timeout(&uart_dld_data.completion_data, HZ);
	if (ret <= 0) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "%s uart dld boot patch start failed:%d\n",
				__func__, ret);
		return -110;
	}

	if (ops->reset)
		ops->reset(NULL);

	ret = wait_for_completion_interruptible_timeout(&uart_dld_data.completion_data, 10 * HZ);
	if (ret <= 0) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "%s uart dld boot patch end failed:%d(%d)\n",
				__func__, ret, retry);
		cancel_work_sync(&uart_dld_data.dld_work);
		retry++;
		if (retry < 10)
			goto uart_dld;
		else
			return -110;
	} else {
		return 0;
	}

}
#endif

#if defined(FW_DOWNLOAD_BY_UART)
static struct uart_dld_work_t {
	struct work_struct dld_work;
	struct completion completion_data;
	char *fw_name;
} uart_dld_data;

void bes2600_load_firmware_uart_work(struct work_struct *work)
{
	int ret;
#if defined(BES2600_LOAD_FW_TOOL_PATH) && defined(BES2600_LOAD_FW_TOOL_DEVICE)
	char cmd_path[] = BES2600_LOAD_FW_TOOL_PATH;
	char *cmd_argv[] = {cmd_path, BES2600_LOAD_FW_TOOL_DEVICE, uart_dld_data.fw_name, NULL};
	char *cmd_envp[] = {"HOME=/", "PATH=/sbin:/bin:/user/bin:/system/bin:/usr/bin", NULL};
#else
	#error "BES uart download should specify fimrware load tool"
#endif
	complete(&uart_dld_data.completion_data);
	if ((ret = call_usermodehelper(cmd_path, cmd_argv, cmd_envp, UMH_WAIT_PROC))) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "call_usermodehelper failed:%d\n", ret);
	} else {
		msleep(200);
		complete(&uart_dld_data.completion_data);
	}
}

#ifdef FW_DOWNLOAD_UART_DAEMON
extern int bes2600_load_uevent(char *evn[]);
#endif

static int bes2600_load_firmware_uart_wrapper(struct sbus_ops *ops, char *name)
{
	int ret = 0;
#ifdef FW_DOWNLOAD_UART_DAEMON
	char driver[] = "DRIVER=bes2600_wlan";
	char vendor[100] = "VENDOR_DESC=";
	char *env[] = {driver, vendor, NULL};
#endif
	memset(&uart_dld_data, 0, sizeof(uart_dld_data));
	init_completion(&uart_dld_data.completion_data);
#ifndef FW_DOWNLOAD_UART_DAEMON
	uart_dld_data.fw_name = name;
#else
	memcpy(vendor + strlen(vendor), name, strlen(name) + 1);
#endif
	INIT_WORK(&uart_dld_data.dld_work, bes2600_load_firmware_uart_work);

#ifndef FW_DOWNLOAD_UART_DAEMON
	schedule_work(&uart_dld_data.dld_work);
	ret = wait_for_completion_interruptible_timeout(&uart_dld_data.completion_data, HZ);
	if (ret <= 0) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "%s uart dld firmware start failed:%d\n",
				__func__, ret);
		return -110;
	}

	if (ops->reset) {
		ops->reset(NULL);
	}

	ret = wait_for_completion_interruptible_timeout(&uart_dld_data.completion_data, 10 * HZ);
	if (ret <= 0) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "%s uart dld firmware end failed:%d\n",
				__func__, ret);
		return -110;
	} else {
		return 0;
	}

#else

	if (ops->reset) {
		ops->reset(NULL);
	}

	if ((ret = bes2600_load_uevent(env))) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "%s uart dld firmware start failed:%d\n",
				__func__, ret);
	}
	return ret;
#endif
}

static int bes_read_dpd_data(struct sbus_ops *ops, struct sbus_priv *priv)
{
	int ret = 0, i;
	u32 dpd_data_len, dpd_ready = 0;
	u8 *dpd_data;
	u32 *temp;
	unsigned long dpd_started = jiffies;

	do {
		bes2600_reg_read(BES_SLAVE_STATUS_REG_ID, &dpd_ready, 4);
		if (dpd_ready & BES_SLAVE_STATUS_WIFI_CALI_READY)
			break;
		else
			msleep(1000);
	} while (time_before(jiffies, dpd_started + 10 * HZ));
	if (!(dpd_ready & BES_SLAVE_STATUS_WIFI_CALI_READY)) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "wait wifi cali timeout(%x)\n", dpd_ready);
		return -110;
	}

	if ( (ret = bes2600_reg_read(BES_TX_CTRL_REG_ID, &dpd_data_len, 4))) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "%s get dpd data len failed(%d)\n", __func__, dpd_data_len);
		goto exit;
	}

	dpd_data = bes2600_chrdev_get_dpd_buffer(dpd_data_len);
	if (!dpd_data) {
		ret = -ENOMEM;
		goto exit;
	}

	ops->lock(priv);
	ret = ops->sbus_memcpy_fromio(priv, BES_CALI_DATA_ADDR, dpd_data, dpd_data_len);
	ops->unlock(priv);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "%s get dpd data failed(%d)\n", __func__, ret);
		goto free_dpd;
	} else {
		temp = (u32 *)dpd_data;
		for (i = 0; i < (dpd_data_len >> 2); i++) {
			temp[i] = swab32(temp[i]);
		}
		ret = bes2600_chrdev_update_dpd_data();
	}
	return ret;
free_dpd:
	bes2600_chrdev_free_dpd_data();
exit:
	return ret;
}

static int bes_write_dpd_data(struct sbus_ops *ops, struct sbus_priv *priv)
{
	int ret;
	u32 dpd_data_len = 0, cfg = BES_DLD_DPD_DATA_DONE;
	const u8 *dpd_data = NULL;

	dpd_data = bes2600_chrdev_get_dpd_data(&dpd_data_len);
	BUG_ON(!dpd_data);

	ops->lock(priv);
	ret = ops->sbus_memcpy_toio(priv, BES_CALI_DATA_ADDR, dpd_data, dpd_data_len);
	ops->unlock(priv);
	if (ret) {
		bes2600_err(BES2600_DBG_SPI, "%s rewrite dpd data failed:%d\n", __func__, ret);
		return ret;
	} else {
		bes2600_err(BES2600_DBG_SPI, "%s rewrite dpd data success\n", __func__);
	}
	return bes2600_reg_write(BES_HOST_SUBINT_REG_ID, &cfg, 4);
}

#ifdef CONFIG_BES2600_CALIB_FROM_LINUX
static int bes_write_factory_data(struct sbus_ops *ops, struct sbus_priv *priv)
{
	int ret = 0;
	u32 factory_data_len = 0, cfg = BES_DLD_FACTORY_DATA_DONE;
	u8 *factory_data = NULL;

	factory_data = bes2600_get_factory_cali_data(&factory_data_len);
	if (!factory_data) {
		bes2600_warn(BES2600_DBG_DOWNLOAD, "factory cali data get failed.\n");
	} else {
		factory_little_endian_cvrt(factory_data);
		ops->lock(priv);
		ret = ops->sbus_memcpy_toio(priv, BES_FACTORY_DATA_ADDR, factory_data, factory_data_len);
		ops->unlock(priv);
		factory_little_to_cpu_cvrt(factory_data);
		if (ret) {
			bes2600_err(BES2600_DBG_DOWNLOAD, "download factory data failed(%d)\n", ret);
			return ret;
		} else {
			bes2600_err(BES2600_DBG_DOWNLOAD, "download factory data success:%x\n", *(u32 *)factory_data);
		}
	}

	return bes2600_reg_write(BES_HOST_SUBINT_REG_ID, &cfg, 4);
}
#endif /* CONFIG_BES2600_CALIB_FROM_LINUX */

static int bes_slave_sync(struct sbus_ops *ops, struct sbus_priv *priv)
{
	u32 sync_header;
	u32 cfg = SPI_CONTINUOUS_CFG_VAL;
	unsigned long sync_started = jiffies;

	do {
		bes2600_reg_read(BES_HOST_SYNC_REG_ID, &sync_header, 4);
		if (sync_header != BES_SLAVE_SYNC_HEADER)
			msleep(100);
		else
			break;
	} while (time_before(jiffies, sync_started + 5 * HZ));

	if (sync_header != BES_SLAVE_SYNC_HEADER) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "spi slave sync failed(%x)\n", sync_header);
		return -110;
	}

	return bes2600_reg_write(SPI_RD_CFG_REG_ID, &cfg, 4);
}

int bes2600_load_firmware_uart(struct sbus_ops *ops, struct sbus_priv *priv)
{
	int ret;
	u32 dpd_data_len = 0;
	const u8 *dpd_data = NULL;
	int fw_type = bes2600_chrdev_get_fw_type();
	char *fw_name;

	bes2600_info(BES2600_DBG_DOWNLOAD, "%s fw_type:%d.\n", __func__, fw_type);

	if (fw_type == BES2600_FW_TYPE_BT) {
		ret = bes2600_load_firmware_uart_wrapper(ops, BES2600_LOAD_BTRF_FW_NAME);
	} else {
reload:
		dpd_data = bes2600_chrdev_get_dpd_data(&dpd_data_len);
		if (!dpd_data) {
			bes2600_info(BES2600_DBG_DOWNLOAD, "%s boot bin\n", __func__);
			ret = bes2600_load_firmware_uart_wrapper(ops, BES2600_LOAD_BOOT_NAME);
			if (ret) {
				bes2600_err(BES2600_DBG_DOWNLOAD, "%s download boot failed:%d\n", __func__, ret);
				goto exit;
			}

			if (ops->init)
				ops->init(priv, NULL);

			if ((ret = bes_slave_sync(ops, priv)))
				goto exit;

			if ((ret = bes_read_dpd_data(ops, priv)))
				goto exit;

			/* wifi nosignal: load best2002_fw_spi_nosignal.bin */
			if (fw_type == BES2600_FW_TYPE_WIFI_NO_SIGNAL)
				goto reload;

			/* normal: judge whether load best2002_fw_spi.bin or not*/
			if (!bes2600_chrdev_is_wifi_opened())
				ret = 1;
			else
				goto reload;
		} else {
			fw_name = (fw_type == BES2600_FW_TYPE_WIFI_SIGNAL) ? BES2600_LOAD_FW_NAME : BES2600_LOAD_NOSIGNAL_FW_NAME;
			if ((ret = bes2600_load_firmware_uart_wrapper(ops, fw_name))) {
				bes2600_err(BES2600_DBG_SPI, "%s download normal fw failed:%d\n", __func__, ret);
				goto exit;
			}

			if ((ret = bes_slave_sync(ops, priv)))
				goto exit;

#ifdef CONFIG_BES2600_CALIB_FROM_LINUX
			if ((ret = bes_write_factory_data(ops, priv)))
				goto exit;
#endif
			if ((ret = bes_write_dpd_data(ops, priv)))
				goto exit;
		}
	}

exit:
	return ret;
}
#endif
