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
#ifndef __FACTORY_H__
#define __FACTORY_H__

#include "bes2600.h"
#include "wsm.h"

#define NVREC_MINI_VERSION		1
#define NVREC_DEV_MAGIC			0xba80
#define NVREC_CURRENT_VERSION	2

#define FACTORY_SIZE 570
#define STANDARD_FACTORY "##head\n\
magic:0x%hx\n\
version:0x%hx\n\
crc:0x%x\n\
##iq&xtal\n\
iQ_offset:0x%x\n\
freq_cal:0x%hx\n\
freq_cal_flags:0x%hhx\n\
##2.4g_power_11n\n\
ch1:0x%hx\n\
ch7:0x%hx\n\
ch13:0x%hx\n\
tx_power_type:0x%hhx\n\
temperature:0x%hx\n\
##5g_power_11n\n\
ch36-40:0x%hx\n\
ch44-48:0x%hx\n\
ch52-56:0x%hx\n\
ch60-64:0x%hx\n\
ch100-104:0x%hx\n\
ch108-112:0x%hx\n\
ch116-120:0x%hx\n\
ch124-128:0x%hx\n\
ch132-136:0x%hx\n\
ch140-144:0x%hx\n\
ch149-153:0x%hx\n\
ch157-161:0x%hx\n\
ch165-169:0x%hx\n\
tx_power_flags_5G:0x%hx\n\
temperature_5G:0x%hx\n\
##bt\n\
bdr_div:0x%x\n\
bdr_power:0x%x\n\
edr_div:0x%x\n\
edr_power:0x%x\n\
%%%%\n"

typedef struct {
	uint16_t magic;
	uint16_t version;
	uint32_t crc;
} factory_head_t;

typedef struct {
	uint32_t iQ_offset;
	uint16_t freq_cal;
	/**
	 * index 0-2
	 * 11n ch1, 11n ch7, 11n ch13
	 */
	uint16_t tx_power_ch[3];

	/**
	 * freq_cal_flags 0 - chip not calibrated
	 * freq_cal_flags 1 - chip has been calibrated
	 */
	uint8_t freq_cal_flags;

	/**
	 * tx_power_type 0 - save bgn 1,7,13 power
	 * tx_power_type 1 - save bgn 1-13 power
	 * tx_power_type 0xff - not calibration
	 */
	uint8_t tx_power_type;
	uint16_t temperature;

	/**
	 * 11n
	 * 0   36~40:1    44~48:2    52~56:3    60~64;
	 * 4   100~104:5    108~112:6    116~120;
	 * 7   124~128:8    132~136:9    140~144
	 * 10    149~153; 11   157~161:12   165~169
	 */
	uint16_t tx_power_ch_5G[13];
	/**
	 * 0- it means that power not calib
	 * 1- it means that power have clibrated
	 */
	uint16_t tx_power_flags_5G;


	uint32_t bt_tx_power[4];
	/* The temperature after 5G clibrating. */
	uint16_t temperature_5G;
} factory_data_t;

struct factory_t {
	factory_head_t head;
	factory_data_t data;
};


enum band_type {
	BAND_2G4,
	BAND_5G,
};

struct wifi_get_power_cali_t {
	uint16_t save_type; /* enmu RF_FACTORY_CALI_DATA_SAVE_TYPE */
	uint16_t tx_power_ch[3];
	uint16_t tx_power_ch_5G[13];
	int16_t status; /* 0: success, != 0: fial */
};

struct wifi_power_cali_save_t {
	uint16_t save_type; /* enmu RF_FACTORY_CALI_DATA_SAVE_TYPE */
	uint16_t mode;
	uint16_t bandwidth;
	uint16_t band;
	uint16_t ch;
	uint16_t power_cali;
	int16_t status; /* 0: success, != 0: fial */
};

struct wifi_freq_cali_t {
	uint16_t save_type; /* enmu RF_FACTORY_CALI_DATA_SAVE_TYPE */
	uint16_t freq_cali;
	int16_t status; /* 0: success, != 0: fial */
	uint16_t cali_flag;
};

struct wifi_power_cali_flag_t {
	uint16_t save_type; /* enmu RF_FACTORY_CALI_DATA_SAVE_TYPE */
	uint16_t band;
	int16_t status; /* 0: success, != 0: fial */
};


/**
 * fatory cali data save type
 * @RF_CALIB_DATA_IN_LINUX - save to linux file
 * @RF_CALIB_DATA_IN_EFUSE - save to efuse
 * @RF_CALIB_DATA_IN_FLASH - save to flash
 * @RF_CALIB_DATA_TYPE_MAX - save type num
 */
enum RF_FACTORY_CALI_DATA_SAVE_TYPE {
	RF_CALIB_DATA_IN_LINUX = 0,
	RF_CALIB_DATA_IN_EFUSE,
	RF_CALIB_DATA_IN_FLASH,
	RF_CALIB_DATA_TYPE_MAX,
};

/* fatory power & freq cali save status code */
enum factory_cali_status {
	FACTORY_SAVE_SUCCESS				= 0,
	FACTORY_SAVE_FILE_NOT_EXIST			= 1,
	FACTORY_SAVE_MODE_ERR				= 2,
	FACTORY_SAVE_CH_ERR					= 3,
	FACTORY_SAVE_POWER_ERR				= 4,
	FACTORY_SAVE_FREQ_ERR				= 5,
	FACTORY_SAVE_EFUSE_CALIED			= 6,
	FACTORY_SAVE_WRITE_ERR				= 7,
	FACTORY_GET_CALIB_FROM_EFUSE_ERR	= 8,
	FACTORY_GET_FREQ_FROM_EFUSE_ERR		= 9,
	FACTORY_GET_POWER_FROM_EFUSE_ERR	= 10,
	FACTORY_GET_POWER_FROM_FLASH_ERR	= 11,
	FACTORY_GET_FREQ_FROM_FLASH_ERR		= 12,
	FACTORY_SET_POWER_CALI_FLAG_ERR		= 13,
	FACTORY_SET_FREQ_CALI_FLAG_ERR		= 14,
	FACTORY_SAVE_READ_ERR				= 15,
	FACTORY_GET_INPUT_NULL_POINTER		= 16,
	FACTORY_FACTORY_TXT_CREATE_FAIL		= 17,
	/* add new here, and numbered sequentially */
};



/* just calibrate 11n, other protocols are automatically mapped */
#define WIFI_RF_11N_MODE 0x15

/* read wifi & bt factory cali value*/
u8* bes2600_get_factory_cali_data(u32 *data_len);
void factory_little_endian_cvrt(u8 *data);
void factory_little_to_cpu_cvrt(u8 *data);

/* read & write wifi cali value */
int16_t bes2600_wifi_power_cali_table_write(struct wifi_power_cali_save_t *data_cali);
int16_t bes2600_wifi_cali_freq_write(struct wifi_freq_cali_t *data_cali);
int16_t vendor_get_freq_cali(struct wifi_freq_cali_t *vendor_freq);
int16_t vendor_get_power_cali(struct wifi_get_power_cali_t *power_cali);
int16_t vendor_set_power_cali_flag(struct wifi_power_cali_flag_t *cali_flag);

#endif
