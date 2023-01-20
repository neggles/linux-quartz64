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
#ifndef __BES_FW_COMMON_H__
#define __BES_FW_COMMON_H__

#include <linux/types.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/crc32.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <linux/wait.h>
#include <linux/completion.h>
#include <linux/firmware.h>
#include <linux/fs.h>
#include <linux/version.h>
#include "bes2600.h"

/***** firmware macro *****/
#define BUF_SIZE        49152
#define RETRY_CNT_MAX   3
#define TIMEOUT_TIME    20
#define FRAME_HEADER_SIZE           0x04
#define CODE_DATA_USELESS_SIZE      0x04
/****frame header code****/
#define FRAME_HEADER_REPLY          0xB0
#define FRAME_HEADER_DOWNLOAD_INFO  0xB1
#define FRAME_HEADER_DOWNLOAD_DATA  0xB2
#define FRAME_HEADER_DOWNLOAD_END   0xB3
#define FRAME_HEADER_RUN_CODE       0xB4

/****frame length get****/
#define BES_FW_MSG_TOTAL_LEN(msg)  (sizeof(struct fw_msg_hdr_t) + ((struct fw_msg_hdr_t )(msg)).len)

/****frame length get****/
#define BES2600_DPD_ADDR	0x2008C000
#define BES2600_FACTORY_ADDR	0x2008B000

/***** bes fw error code *****/
enum ERR_CODE {
	ERR_NONE = 0x00,
	ERR_LEN = 0x01,
};

/***** data struct *****/
struct frame_struct_t {
    u8 type;
    u8 frame_num;
    u16 len;
    u32 payload;
};

struct fw_msg_hdr_t {
    u8 type;
    u8 seq;
    u16 len;
};

struct fw_msg_replay_t {
    u32 replay;
};

struct fw_info_t {
    u32 len;
    u32 addr;
};

struct download_fw_t {
    u32 addr;
    u8 data[0];
};

struct fw_crc_t {
    u32 crc32;
};

struct run_fw_t {
    u32 addr;
};

struct exec_struct_t {
	u32 entry;
	u32 param;
	u32 sp;
	u32 exec_addr;
};

#if defined(FW_DOWNLOAD_BY_SDIO) || defined(FW_DOWNLOAD_BY_USB)
void bes_parse_fw_info(const u8 *data, u32 data_len, u32 *load_addr, u32 *crc32);
int bes_frame_rsp_check(void *rsp, u8 frame_num);
const u8* bes2600_get_firmware_version_info(const u8 *data, u32 count);
#endif

#endif