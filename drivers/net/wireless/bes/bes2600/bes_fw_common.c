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

//#define BES_CRC32_DOUBLE_CHECK
#ifdef BES_CRC32_DOUBLE_CHECK
extern u32 bes_crc32_c(u32 crc, const u8 *data, u32 data_len);
#endif

#if defined(FW_DOWNLOAD_BY_SDIO) || defined(FW_DOWNLOAD_BY_USB)
void bes_parse_fw_info(const u8 *data, u32 data_len, u32 *load_addr, u32 *crc32)
{
	u8 buffer[16];
	struct exec_struct_t exec_struct;
	u32 exec_addr_last4byte;
	u32 crc_le = 0;
#ifdef BES_CRC32_DOUBLE_CHECK
	u32 crc_bes = 0;
	u32 crc_be = 0;
#endif
	crc_le = crc32_le(0xffffffffL, (u8 *)data, data_len - CODE_DATA_USELESS_SIZE);
	crc_le ^= 0xffffffffL;

#ifdef BES_CRC32_DOUBLE_CHECK
	crc_be = crc32_be(0xffffffffL, (u8 *)data, data_len - CODE_DATA_USELESS_SIZE);
	crc_be ^= 0xffffffffL;
	crc_bes = bes_crc32_c(crc_bes, (u8 *)data, data_len - CODE_DATA_USELESS_SIZE);
#endif

	//read entry,param,sp,exec_addr
	memcpy((u8 *)buffer, (u8 *)data, sizeof(exec_struct));
	exec_struct.entry       = ((struct exec_struct_t *)buffer)->entry;//PC
	exec_struct.param       = ((struct exec_struct_t *)buffer)->param;
	exec_struct.sp          = ((struct exec_struct_t *)buffer)->sp;
	exec_struct.exec_addr   = ((struct exec_struct_t *)buffer)->exec_addr;//load addr


#ifdef BES_CRC32_DOUBLE_CHECK
	bes2600_dbg(BES2600_DBG_DOWNLOAD, "crc32 %x(le) %x(be) %x(bes)\n", crc_le, crc_be, crc_bes);
#else
	bes2600_dbg(BES2600_DBG_DOWNLOAD, "crc32                :0x%08X\n", crc_le);
#endif
	bes2600_dbg(BES2600_DBG_DOWNLOAD, "exec_struct.entry    :0x%08X\n", exec_struct.entry);
	bes2600_dbg(BES2600_DBG_DOWNLOAD, "exec_struct.param    :0x%08X\n", exec_struct.param);
	bes2600_dbg(BES2600_DBG_DOWNLOAD, "exec_struct.sp       :0x%08X\n", exec_struct.sp);
	bes2600_dbg(BES2600_DBG_DOWNLOAD, "exec_struct.exec_addr:0x%08X\n", exec_struct.exec_addr);

	exec_addr_last4byte = (*((u32 *)(data + data_len - 4)));
	bes2600_dbg(BES2600_DBG_DOWNLOAD, "exec_addr_last4byte  :0x%08X\n", exec_addr_last4byte);
	if ((!exec_struct.exec_addr) || (exec_struct.exec_addr != exec_addr_last4byte && exec_addr_last4byte)) {
		exec_struct.exec_addr = exec_addr_last4byte;
		bes2600_dbg(BES2600_DBG_DOWNLOAD, "exec_addr_last4byte covered exec_struct.exec_addr\n");
	}
	bes2600_dbg(BES2600_DBG_DOWNLOAD, "final exec_struct.exec_addr:0x%08X\n", exec_struct.exec_addr);

	*load_addr = exec_struct.exec_addr;

#ifndef BES_CRC32_DOUBLE_CHECK
	*crc32 = crc_le;
#else
	*crc32 = crc_bes;
#endif
}

int bes_frame_rsp_check(void *rsp, u8 frame_num)
{
	int ret = 0;
	struct frame_struct_t *pframe = (struct frame_struct_t *)rsp;
	if (pframe->type == FRAME_HEADER_REPLY) {
		if (pframe->frame_num == frame_num) {
			if (pframe->len == 4) {
				if (pframe->payload == ERR_NONE) {
					bes2600_dbg(BES2600_DBG_DOWNLOAD, "bes slave  download firmware is ready\n");
				} else {
					bes2600_err(BES2600_DBG_DOWNLOAD, "frame payload=0x%x\n", pframe->payload);
					ret = -200;
				}
			} else {
				bes2600_err(BES2600_DBG_DOWNLOAD, "payload len error:%u\n", pframe->len);
				ret = -201;
			}
		} else {
			bes2600_err(BES2600_DBG_DOWNLOAD, "frame num err. 0x%x != 0x%x. len:%u\n",
				pframe->frame_num, frame_num, pframe->len);
			ret = -202;
		}
	} else {
		bes2600_err(BES2600_DBG_DOWNLOAD, "frame type err. type 0x%x num=0x%x(0x%x), len:%u\n",
			pframe->type, pframe->frame_num, frame_num, pframe->len);
		ret = -203;
	}
	return ret;
}

const u8* bes2600_get_firmware_version_info(const u8 *data, u32 count)
{
        int i = 0;
        const u8 *tmp_ptr = NULL;
        const char month[12][4] = {
                "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
        };

        if(!data || count < 4)
                return NULL;

        for(tmp_ptr = data + count; tmp_ptr > data; tmp_ptr -= 4) {
                for(i = 0; i < 12; i++) {
                        if(memcmp(tmp_ptr, month[i], 3) == 0) {
                                return tmp_ptr;
                        }
                }
        }

        return NULL;
}
#endif