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

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/crc32.h>
#include <linux/version.h>
#include "bes2600_factory.h"
#include "bes2600_log.h"
#include "bes_chardev.h"

#define LE_CPU_TRANS(val, cvt)		(val = cvt(val))

#define TRANS_LE16(val) LE_CPU_TRANS(val, __cpu_to_le16)
#define TRANS_LE32(val) LE_CPU_TRANS(val, __cpu_to_le32)

#define TRANS_CPU16(val) LE_CPU_TRANS(val, __le16_to_cpu)
#define TRANS_CPU32(val) LE_CPU_TRANS(val, __le32_to_cpu)

static DEFINE_MUTEX(factory_lock);

static struct factory_t factory_cali_data;
static struct factory_t *factory_p = NULL;

static int bes2600_wifi_cali_table_save(struct factory_t *factory_save_p);

static inline uint32_t factory_crc32(const uint8_t *data, uint32_t len)
{
	u32 crc_le = 0;
	crc_le = crc32_le(0xffffffffL, (uint8_t *)data, len);
	crc_le ^= 0xffffffffL;
	return crc_le;
}
/**
 * factory_section_read_file - Read data of specified length from file
 * @path:	path of the file
 * @buffer:	storage of read data
 * @size:	length of data to be read
 *
 * Return: length on success, negative error code otherwise.
 */
static int factory_section_read_file(char *path, void *buffer, int size)
{
	int ret=0;
	struct file *fp;

	bes2600_info(BES2600_DBG_FACTORY, "reading %s \n", path);

	fp = filp_open(path, O_RDONLY, 0);//S_IRUSR


	if (IS_ERR(fp)) {
		bes2600_info(BES2600_DBG_FACTORY, "BES2600 : can't open %s\n",path);
		return -1;
	}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))
	ret = kernel_read(fp, buffer, size, &fp->f_pos);
#else
	ret = kernel_read(fp, fp->f_pos, buffer, size);
#endif

	filp_close(fp, NULL);

	return ret;
}

/**
 * factory_section_write_file - Write data of specified length to file
 * @path:	path of the file
 * @buffer:	storage of write data
 * @size:	length of data to write
 *
 * Return: length on success, negative error code otherwise.
 */
static int factory_section_write_file(char *path, void *buffer, int size)
{
	int ret = 0;
	struct file *fp;

	bes2600_info(BES2600_DBG_FACTORY, "writing %s \n", path);

	fp = filp_open(path, O_TRUNC | O_CREAT | O_RDWR, S_IRUSR);
	if (IS_ERR(fp)) {
		bes2600_info(BES2600_DBG_FACTORY, "BES2600 : can't open %s\n",path);
		return -1;
	}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))
	ret = kernel_write(fp, buffer, size, &fp->f_pos);
#else
	ret = kernel_write(fp, buffer, size, fp->f_pos);
#endif

	filp_close(fp,NULL);

	return ret;
}

static inline int factory_parse(uint8_t *source_buf, struct factory_t *factory)
{
	int ret;
	ret = sscanf(source_buf, STANDARD_FACTORY,\
		&factory->head.magic,\
		&factory->head.version,\
		&factory->head.crc,\
		&factory->data.iQ_offset,\
		&factory->data.freq_cal,\
		&factory->data.freq_cal_flags,\
		&factory->data.tx_power_ch[0],\
		&factory->data.tx_power_ch[1],\
		&factory->data.tx_power_ch[2],\
		&factory->data.tx_power_type,\
		&factory->data.temperature,\
		&factory->data.tx_power_ch_5G[0],\
		&factory->data.tx_power_ch_5G[1],\
		&factory->data.tx_power_ch_5G[2],\
		&factory->data.tx_power_ch_5G[3],\
		&factory->data.tx_power_ch_5G[4],\
		&factory->data.tx_power_ch_5G[5],\
		&factory->data.tx_power_ch_5G[6],\
		&factory->data.tx_power_ch_5G[7],\
		&factory->data.tx_power_ch_5G[8],\
		&factory->data.tx_power_ch_5G[9],\
		&factory->data.tx_power_ch_5G[10],\
		&factory->data.tx_power_ch_5G[11],\
		&factory->data.tx_power_ch_5G[12],\
		&factory->data.tx_power_flags_5G,\
		&factory->data.temperature_5G,\
		&factory->data.bt_tx_power[0],\
		&factory->data.bt_tx_power[1],\
		&factory->data.bt_tx_power[2],\
		&factory->data.bt_tx_power[3]);
	return ret;
}
static int factory_open(u8 *factory_buf)
{
	int ret = 0;

	ret = factory_section_read_file(FACTORY_PATH, factory_buf, FACTORY_SIZE);
	if(ret < 0) {
		bes2600_err(BES2600_DBG_FACTORY, "Read error: %d\n",ret);
		goto exit;
	}

	factory_parse(factory_buf, &factory_cali_data);

	if (factory_cali_data.head.magic != NVREC_DEV_MAGIC){
		ret = -EBADMSG;
		goto exit;
	}
	if ((factory_cali_data.head.version < NVREC_MINI_VERSION) ||
		(factory_cali_data.head.version > NVREC_CURRENT_VERSION))
	{
		bes2600_err(BES2600_DBG_FACTORY, "factory version error:%d", factory_cali_data.head.version);
		ret = -EBADMSG;
		goto exit;
	}

	factory_p = &factory_cali_data;

	bes2600_info(BES2600_DBG_FACTORY, "open wifi factory section success");
	ret = 0;
exit:
	return ret;
}

static void factory_section_wifi_tx_power_check(struct factory_t *factory_p)
{
	int i;
	bool inval_v = false;

	if (!factory_p)
		return ;

	/* only check cali channel, 11n ch1, ch7, ch13 */
	for (i = 0; i < ARRAY_SIZE(factory_p->data.tx_power_ch); ++i) {
		if (factory_p->data.tx_power_ch[i] == 0x0 ||
			factory_p->data.tx_power_ch[i] > 0x3fff) {
			inval_v = true;
		}
	}

	bes2600_warn_with_cond(inval_v, BES2600_DBG_FACTORY, "tx_power_ch_2g cali, inval calibration value\n");
	bes2600_info_dump(BES2600_DBG_FACTORY, "tx_power_ch_2g dump:", factory_p->data.tx_power_ch,
					sizeof(factory_p->data.tx_power_ch));

}


static void factory_section_wifi_tx_power_5G_check(struct factory_t *factory_p)
{
	int i;
	bool inval_v = false;

	if (!factory_p)
		return ;

	/* only check cali channel */
	for (i = 0; i < ARRAY_SIZE(factory_p->data.tx_power_ch_5G); ++i) {
		if (factory_p->data.tx_power_ch_5G[i] == 0x0 ||
			factory_p->data.tx_power_ch_5G[i] > 0x3fff) {
			inval_v = true;
		}
	}

	bes2600_warn_with_cond(inval_v, BES2600_DBG_FACTORY, "tx_power_ch_5g cali, inval calibration value\n");
	bes2600_info_dump(BES2600_DBG_FACTORY, "tx_power_ch_5g dump:", factory_p->data.tx_power_ch_5G,
					sizeof(factory_p->data.tx_power_ch_5G));

}

static void factory_section_wifi_freq_cali_check(struct factory_t *factory_p)
{
	if (!factory_p)
		return ;

	if (factory_p->data.freq_cal == 0x0 ||
		factory_p->data.freq_cal > 0x1ff) {
			bes2600_warn(BES2600_DBG_FACTORY, "freq cali, inval calibration value\n");
		}

	bes2600_info_dump(BES2600_DBG_FACTORY, "wifi freq cali dump:", &factory_p->data.freq_cal,
					sizeof(factory_p->data.freq_cal));

}

static void factory_section_bt_tx_power_check(struct factory_t *factory_p)
{
	int i;
	bool inval_v = false;

	if (!factory_p)
		return ;

	/* bt only check bdr & edr power, (bdr/edr: div, powerlevel) */
	for (i = 0; i < ARRAY_SIZE(factory_p->data.bt_tx_power) - 1; i += 2) {
		if (factory_p->data.bt_tx_power[i] != 0x05) {
			inval_v = true;
		}

		if (factory_p->data.bt_tx_power[i + 1] == 0x0 ||
			factory_p->data.bt_tx_power[i + 1] > 0x20) {
			inval_v = true;
		}
	}

	bes2600_warn_with_cond(inval_v, BES2600_DBG_FACTORY, "bt tx power cali, inval calibration value\n");
	bes2600_info_dump(BES2600_DBG_FACTORY, "bt tx power cali dump:", factory_p->data.bt_tx_power,
					sizeof(factory_p->data.bt_tx_power));

}

void factory_little_endian_cvrt(u8 *data)
{
	int i;
	struct factory_t *trans_data = NULL;
	if (!data)
		return ;

	trans_data = (struct factory_t *)data;

	TRANS_LE16(trans_data->head.magic);
	TRANS_LE16(trans_data->head.version);
	TRANS_LE32(trans_data->head.crc);

	TRANS_LE16(trans_data->data.freq_cal);
	TRANS_LE32(trans_data->data.iQ_offset);

	for (i = 0; i < ARRAY_SIZE(trans_data->data.tx_power_ch); i++)
		TRANS_LE16(trans_data->data.tx_power_ch[i]);

	TRANS_LE16(trans_data->data.temperature);

	for (i = 0; i < ARRAY_SIZE(trans_data->data.bt_tx_power); i++)
		TRANS_LE32(trans_data->data.bt_tx_power[i]);

	for (i = 0; i < ARRAY_SIZE(trans_data->data.tx_power_ch_5G); i++)
		TRANS_LE16(trans_data->data.tx_power_ch_5G[i]);

	TRANS_LE16(trans_data->data.tx_power_flags_5G);
	TRANS_LE16(trans_data->data.temperature_5G);

}

void factory_little_to_cpu_cvrt(u8 *data)
{
	int i;
	struct factory_t *trans_data = NULL;
	if (!data)
		return ;

	trans_data = (struct factory_t *)data;
	TRANS_CPU16(trans_data->head.magic);
	TRANS_CPU16(trans_data->head.version);
	TRANS_CPU32(trans_data->head.crc);

	TRANS_CPU16(trans_data->data.freq_cal);
	TRANS_CPU32(trans_data->data.iQ_offset);

	for (i = 0; i < ARRAY_SIZE(trans_data->data.tx_power_ch); i++)
		TRANS_CPU16(trans_data->data.tx_power_ch[i]);

	TRANS_CPU16(trans_data->data.temperature);

	for (i = 0; i < ARRAY_SIZE(trans_data->data.bt_tx_power); i++)
		TRANS_CPU32(trans_data->data.bt_tx_power[i]);

	for (i = 0; i < ARRAY_SIZE(trans_data->data.tx_power_ch_5G); i++)
		TRANS_CPU16(trans_data->data.tx_power_ch_5G[i]);

	TRANS_CPU16(trans_data->data.tx_power_flags_5G);
	TRANS_CPU16(trans_data->data.temperature_5G);

}


u8* bes2600_get_factory_cali_data(u32 *data_len)
{
	int ret = 0;
	uint8_t *factory_section_buf = NULL;
	u8 *ret_p = NULL;

	*data_len = sizeof(struct factory_t);
	if (factory_p)
		return (u8 *)factory_p;

	factory_section_buf = kzalloc(FACTORY_SIZE, GFP_KERNEL);
	if(!factory_section_buf) {
		*data_len = 0;
		return NULL;
	}

	ret = factory_open(factory_section_buf);
	if (ret) {
		*data_len = 0;
		ret_p = NULL;
		goto out;
	}

	if (!factory_p) {
		*data_len = 0;
		ret_p = NULL;
		goto out;
	}

	factory_section_wifi_tx_power_check(factory_p);
	factory_section_wifi_tx_power_5G_check(factory_p);
	factory_section_bt_tx_power_check(factory_p);
	factory_section_wifi_freq_cali_check(factory_p);

	/* In order to support manual value change, recalculate crc before sending */
	factory_p->head.crc =
		factory_crc32((uint8_t *)(&(factory_p->data)), sizeof(factory_data_t));

	ret_p = (u8 *)factory_p;

out:
	kfree(factory_section_buf);
	return ret_p;

}

/**
 * When the calibration file does not exist, a new file is automatically created when
 * the calibration value is written. After writing, update factory_p, if the update is successful,
 * it means the writing is successful, otherwise it fails. At the same time, subsequent calibration
 * values are saved on this basis to avoid duplicating file creation and flushing out previously saved values.
 */
static bool bes2600_factory_file_status_read(void)
{
	u8 *factory_temp = NULL;
	uint32_t len;
	bool ret = true;

	if (factory_p)
		return true;

	factory_temp = bes2600_get_factory_cali_data(&len);
	if (!factory_temp) {
		bes2600_warn(BES2600_DBG_FACTORY, "get factory cali fali, check file, check whether the file exists\n");
		ret = false;
	}

	return ret;
}

/* create a new factory.txt file */
static int bes2600_factory_cali_file_hdr_fill(struct factory_t **factory_head)
{
	u16 tx_power_type = 0xff;

	if (!factory_head)
		return -1;

	*factory_head = &factory_cali_data;
	memset(*factory_head, 0, sizeof(struct factory_t));
	(*factory_head)->data.tx_power_type = tx_power_type;
	(*factory_head)->head.magic = 0xba80;
	(*factory_head)->head.version = 2;

	return 0;
}


int16_t bes2600_wifi_power_cali_table_write(struct wifi_power_cali_save_t *data_cali)
{
	u16 mode, band, ch, power_cali, bandwidth;
	int power_index = 0;
	u16 power_origin;
	struct factory_t *factory_power_p = NULL;
	bool new_file = false;

	if (!data_cali) {
		bes2600_warn(BES2600_DBG_FACTORY, "%s: power cali save pointer is NULL\n", __func__);
		return -FACTORY_GET_INPUT_NULL_POINTER;
	}

	/**
	 * When it returns true, it means that the factory file has been read.
	 * When it returns false, it means that the factory file does not exist,
	 * or the operation of reading the text file fails. At this time, a new factory file will be created.
	 */
	if (bes2600_factory_file_status_read()) {
		factory_power_p = factory_p;
	} else {
		if (bes2600_factory_cali_file_hdr_fill(&factory_power_p)) {
			bes2600_warn(BES2600_DBG_FACTORY, "%s, create bes2600_factory.txt fail.", __func__);
			return -FACTORY_FACTORY_TXT_CREATE_FAIL;
		}
		new_file = true;
	}

	mode = data_cali->mode;
	bandwidth = data_cali->bandwidth;
	band = data_cali->band;
	ch = data_cali->ch;
	power_cali = data_cali->power_cali;

	bes2600_dbg(BES2600_DBG_FACTORY, "%s: mode = %u, bandwidth = %u,, band = %u, ch = %u, power_cali = 0x%04x\n",
				__func__, mode, bandwidth, band, ch, power_cali);

	/* only in 802.11n 20M msc7 mode, the power calibration value is saved */
	if (bandwidth != 0 || mode != WIFI_RF_11N_MODE)
		return -FACTORY_SAVE_MODE_ERR;

	/* powerlevel value range: 0 ~ 0x3fff */
	if (power_cali == 0 || power_cali > 0x3fff)
		return -FACTORY_SAVE_POWER_ERR;

	if (band == BAND_2G4) {
		switch (ch) {
		case 1:
			power_index = 0;
			break;
		case 7:
			power_index = 1;
			break;
		case 13:
			power_index = 2;
			break;
		default:
			return -FACTORY_SAVE_CH_ERR;
			break;
		}
		power_origin = factory_power_p->data.tx_power_ch[power_index];
		factory_power_p->data.tx_power_ch[power_index] = power_cali;
	} else if (band == BAND_5G) {
		switch (ch) {
		case 36:
		case 38:
		case 40:
			power_index = 0;
			break;
		case 44:
		case 46:
		case 48:
			power_index = 1;
			break;
		case 52:
		case 54:
		case 56:
			power_index = 2;
			break;
		case 60:
		case 62:
		case 64:
			power_index = 3;
			break;
		case 100:
		case 102:
		case 104:
			power_index = 4;
			break;
		case 108:
		case 110:
		case 112:
			power_index = 5;
			break;
		case 116:
		case 114:
		case 120:
			power_index = 6;
			break;
		case 124:
		case 126:
		case 128:
			power_index = 7;
			break;
		case 132:
		case 134:
		case 136:
			power_index = 8;
			break;
		case 140:
		case 142:
		case 144:
			power_index = 9;
			break;
		case 149:
		case 151:
		case 153:
			power_index = 10;
			break;
		case 157:
		case 159:
		case 161:
			power_index = 11;
			break;
		case 165:
		case 169:
			power_index = 12;
			break;
		default:
			return -FACTORY_SAVE_CH_ERR;
			break;
		}
		power_origin = factory_power_p->data.tx_power_ch_5G[power_index];
		factory_power_p->data.tx_power_ch_5G[power_index] = power_cali;
	}

	if (band == BAND_2G4) {
		power_origin = factory_power_p->data.tx_power_ch[power_index];
		factory_power_p->data.tx_power_ch[power_index] = power_cali;
	} else {
		power_origin = factory_power_p->data.tx_power_ch_5G[power_index];
		factory_power_p->data.tx_power_ch_5G[power_index] = power_cali;
	}

	/* save to file */
	if (bes2600_wifi_cali_table_save(factory_power_p)) {
		if (new_file) {
			memset(factory_power_p, 0, sizeof(struct factory_t));
			factory_p = NULL;
		} else {
			if (band == BAND_2G4)
				factory_power_p->data.tx_power_ch[power_index] = power_origin;
			else
				factory_power_p->data.tx_power_ch_5G[power_index] = power_origin;
		}
		return -FACTORY_SAVE_WRITE_ERR;
	} else {
		/* update factory_p */
		if (new_file)
			factory_p = factory_power_p;
	}

	return 0;

}

int16_t bes2600_wifi_cali_freq_write(struct wifi_freq_cali_t *data_cali)
{
	u16 freq_cali;
	struct factory_t *factory_freq_p = NULL;
	u16 freq_origin;
	u8 flag_origin;
	bool new_file = false;

	if (!data_cali) {
		bes2600_warn(BES2600_DBG_FACTORY, "%s: freq cali save pointer is NULL\n", __func__);
		return -FACTORY_GET_INPUT_NULL_POINTER;
	}

	/**
	 * When it returns true, it means that the factory file has been read.
	 * When it returns false, it means that the factory file does not exist,
	 * or the operation of reading the text file fails. At this time, a new factory file will be created.
	 */
	if (bes2600_factory_file_status_read()) {
		factory_freq_p = factory_p;
	} else {
		if (bes2600_factory_cali_file_hdr_fill(&factory_freq_p)) {
			bes2600_warn(BES2600_DBG_FACTORY, "%s, create bes2600_factory.txt fail.", __func__);
			return -FACTORY_FACTORY_TXT_CREATE_FAIL;
		}
		new_file = true;
	}

	freq_origin = factory_freq_p->data.freq_cal;
	flag_origin = factory_freq_p->data.freq_cal_flags;
	freq_cali = data_cali->freq_cali;
	data_cali->cali_flag = 1;

	/* freqOffset value range: 0 ~ 0x1ff */
	if (freq_cali == 0 || freq_cali > 0x1ff)
		return -FACTORY_SAVE_FREQ_ERR;

	factory_freq_p->data.freq_cal = freq_cali;
	factory_freq_p->data.freq_cal_flags = (u8)(data_cali->cali_flag);
	bes2600_dbg(BES2600_DBG_FACTORY, "%s: freq_cali = 0x%04x\n", __func__, data_cali->freq_cali);

	/* save to file */
	if (bes2600_wifi_cali_table_save(factory_freq_p)) {
		if (new_file) {
			memset(factory_freq_p, 0, sizeof(struct factory_t));
			factory_p = NULL;
		} else {
			/* recover factory value */
			factory_freq_p->data.freq_cal = freq_origin;
			factory_freq_p->data.freq_cal_flags = flag_origin;
		}
		return -FACTORY_SAVE_WRITE_ERR;
	} else {
		/* update factory_p */
		if (new_file)
			factory_p = factory_freq_p;
	}

	return 0;
}

int16_t vendor_set_power_cali_flag(struct wifi_power_cali_flag_t *cali_flag)
{
	struct factory_t *factory_power_flag_p = NULL;
	u16 flag_origin = 0;
	u16 calied_flag_5g = 1;
	u16 calied_flag_2g = 0;

	if (!cali_flag) {
		bes2600_warn(BES2600_DBG_FACTORY, "%s: power cali flag save pointer is NULL\n", __func__);
		return -FACTORY_GET_INPUT_NULL_POINTER;
	}

	if (cali_flag->band != BAND_2G4 && cali_flag->band != BAND_5G) {
		bes2600_warn(BES2600_DBG_FACTORY, "%s: power cali flag save band err\n", __func__);
		return -FACTORY_SET_POWER_CALI_FLAG_ERR;
	}

	if (bes2600_factory_file_status_read()) {
		factory_power_flag_p = factory_p;
	} else {
		bes2600_warn(BES2600_DBG_FACTORY, "%s: factory cali data is not exist\n", __func__);
		return -FACTORY_SAVE_FILE_NOT_EXIST;
	}

	if (cali_flag->band == BAND_2G4) {
		flag_origin = factory_power_flag_p->data.tx_power_type;
		factory_power_flag_p->data.tx_power_type = calied_flag_2g;
	} else {
		flag_origin = factory_power_flag_p->data.tx_power_flags_5G;
		factory_power_flag_p->data.tx_power_flags_5G = calied_flag_5g;
	}

	/* save to file */
	if (bes2600_wifi_cali_table_save(factory_power_flag_p)) {
		if (cali_flag->band == BAND_2G4) {
			factory_power_flag_p->data.tx_power_type = flag_origin;
		} else {
			factory_power_flag_p->data.tx_power_flags_5G = flag_origin;
		}

		return -FACTORY_SET_POWER_CALI_FLAG_ERR;
	}

	return 0;

}

static inline int factory_build(uint8_t *dest_buf, struct factory_t *factory)
{
	return snprintf(dest_buf, FACTORY_SIZE, STANDARD_FACTORY,\
		factory->head.magic,\
		factory->head.version,\
		factory->head.crc,\
		factory->data.iQ_offset,\
		factory->data.freq_cal,\
		factory->data.freq_cal_flags,\
		factory->data.tx_power_ch[0],\
		factory->data.tx_power_ch[1],\
		factory->data.tx_power_ch[2],\
		factory->data.tx_power_type,\
		factory->data.temperature,\
		factory->data.tx_power_ch_5G[0],\
		factory->data.tx_power_ch_5G[1],\
		factory->data.tx_power_ch_5G[2],\
		factory->data.tx_power_ch_5G[3],\
		factory->data.tx_power_ch_5G[4],\
		factory->data.tx_power_ch_5G[5],\
		factory->data.tx_power_ch_5G[6],\
		factory->data.tx_power_ch_5G[7],\
		factory->data.tx_power_ch_5G[8],\
		factory->data.tx_power_ch_5G[9],\
		factory->data.tx_power_ch_5G[10],\
		factory->data.tx_power_ch_5G[11],\
		factory->data.tx_power_ch_5G[12],\
		factory->data.tx_power_flags_5G,\
		factory->data.temperature_5G,\
		factory->data.bt_tx_power[0],\
		factory->data.bt_tx_power[1],\
		factory->data.bt_tx_power[2],\
		factory->data.bt_tx_power[3]);
}

static int bes2600_wifi_cali_table_save(struct factory_t *factory_save_p)
{
	int ret;
	int w_size;
	uint8_t *mempool = NULL;
	u32 crc_origin;

	bes2600_info(BES2600_DBG_FACTORY, "enter %s\n", __func__);

	if (!factory_save_p) {
		return -ENOENT;
	}

	mempool = kzalloc(FACTORY_SIZE, GFP_KERNEL);
	if(mempool == NULL) {
		bes2600_err(BES2600_DBG_FACTORY, "%s : mempool zalloc error!\n", __func__);
		return -ENOMEM;
	}

	crc_origin = factory_save_p->head.crc;

	factory_save_p->head.crc =
		factory_crc32((uint8_t *)(&(factory_save_p->data)), sizeof(factory_data_t));

	w_size = factory_build(mempool, factory_save_p);

	if (w_size < 0 || w_size >= FACTORY_SIZE) {
		bes2600_err(BES2600_DBG_FACTORY, "%s: build failed! ret = %d.", __func__, 0);
		kfree(mempool);
		return -ETXTBSY;
	}

	mutex_lock(&factory_lock);

	ret = factory_section_write_file(FACTORY_PATH, mempool, w_size);
	if(ret < 0) {
		factory_save_p->head.crc = crc_origin;
		bes2600_err(BES2600_DBG_FACTORY, "%s: write failed! ret = %d.", __func__, ret);
		mutex_unlock(&factory_lock);
		kfree(mempool);
		return ret;
	}
	mutex_unlock(&factory_lock);

	kfree(mempool);
	return 0;
}

int16_t vendor_get_power_cali(struct wifi_get_power_cali_t *power_cali)
{
	bool ret = bes2600_factory_file_status_read();

	if (!power_cali) 
		return -FACTORY_GET_INPUT_NULL_POINTER;

	if (!ret)
		return -FACTORY_SAVE_FILE_NOT_EXIST;

	memcpy(power_cali->tx_power_ch, factory_p->data.tx_power_ch, sizeof(power_cali->tx_power_ch));
	memcpy(power_cali->tx_power_ch_5G, factory_p->data.tx_power_ch_5G, sizeof(power_cali->tx_power_ch_5G));

	return 0;

}


int16_t vendor_get_freq_cali(struct wifi_freq_cali_t *vendor_freq)
{
	bool ret = bes2600_factory_file_status_read();

	if (!vendor_freq)
		return -FACTORY_GET_INPUT_NULL_POINTER;
	if (!ret)
		return -FACTORY_SAVE_FILE_NOT_EXIST;

	vendor_freq->status = 0;
	vendor_freq->freq_cali = factory_p->data.freq_cal;
	vendor_freq->cali_flag = factory_p->data.freq_cal_flags;

	return 0;
}

