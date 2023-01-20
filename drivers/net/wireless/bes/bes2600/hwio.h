/*
 * Low-level API for mac80211 BES2600 drivers
 *
 * Copyright (c) 2010, Bestechnic
 * Author:
 *
 * Based on:
 * UMAC BES2600 driver which is
 * Copyright (c) 2010, Bestechnic
 * Author:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef BES2600_HWIO_H_INCLUDED
#define BES2600_HWIO_H_INCLUDED

/* extern */ struct sbus_ops;
/* extern */ struct sbus_priv;

/* DPLL initial values */
#define DPLL_INIT_VAL_9000		(0x00000191)
#define DPLL_INIT_VAL_BES2600		(0x0EC4F121)

/* Hardware Type Definitions */
#define HIF_8601_VERSATILE		(0)
#define HIF_8601_SILICON		(1)
#define HIF_9000_SILICON_VERSTAILE	(2)

#define BES2600_CUT_11_ID_STR		(0x302E3830)
#define BES2600_CUT_22_ID_STR1		(0x302e3132)
#define BES2600_CUT_22_ID_STR2		(0x32302e30)
#define BES2600_CUT_22_ID_STR3		(0x3335)
#define CW1250_CUT_11_ID_STR1		(0x302e3033)
#define CW1250_CUT_11_ID_STR2		(0x33302e32)
#define CW1250_CUT_11_ID_STR3		(0x3535)
#define BES2600_CUT_ID_ADDR		(0xFFF17F90)
#define BES2600_CUT2_ID_ADDR		(0xFFF1FF90)

/* Download control area */
/* boot loader start address in SRAM */
#define DOWNLOAD_BOOT_LOADER_OFFSET	(0x00000000)
/* 32K, 0x4000 to 0xDFFF */
#define DOWNLOAD_FIFO_OFFSET		(0x00004000)
/* 32K */
#define DOWNLOAD_FIFO_SIZE		(0x00008000)
/* 128 bytes, 0xFF80 to 0xFFFF */
#define DOWNLOAD_CTRL_OFFSET		(0x0000FF80)
#define DOWNLOAD_CTRL_DATA_DWORDS	(32-6)

struct download_cntl_t {
	/* size of whole firmware file (including Cheksum), host init */
	u32 ImageSize;
	/* downloading flags */
	u32 Flags;
	/* No. of bytes put into the download, init & updated by host */
	u32 Put;
	/* last traced program counter, last ARM reg_pc */
	u32 TracePc;
	/* No. of bytes read from the download, host init, device updates */
	u32 Get;
	/* r0, boot losader status, host init to pending, device updates */
	u32 Status;
	/* Extra debug info, r1 to r14 if status=r0=DOWNLOAD_EXCEPTION */
	u32 DebugData[DOWNLOAD_CTRL_DATA_DWORDS];
};

#define	DOWNLOAD_IMAGE_SIZE_REG		\
	(DOWNLOAD_CTRL_OFFSET + offsetof(struct download_cntl_t, ImageSize))
#define	DOWNLOAD_FLAGS_REG		\
	(DOWNLOAD_CTRL_OFFSET + offsetof(struct download_cntl_t, Flags))
#define DOWNLOAD_PUT_REG		\
	(DOWNLOAD_CTRL_OFFSET + offsetof(struct download_cntl_t, Put))
#define DOWNLOAD_TRACE_PC_REG		\
	(DOWNLOAD_CTRL_OFFSET + offsetof(struct download_cntl_t, TracePc))
#define	DOWNLOAD_GET_REG		\
	(DOWNLOAD_CTRL_OFFSET + offsetof(struct download_cntl_t, Get))
#define	DOWNLOAD_STATUS_REG		\
	(DOWNLOAD_CTRL_OFFSET + offsetof(struct download_cntl_t, Status))
#define DOWNLOAD_DEBUG_DATA_REG		\
	(DOWNLOAD_CTRL_OFFSET + offsetof(struct download_cntl_t, DebugData))
#define DOWNLOAD_DEBUG_DATA_LEN		(108)

#define DOWNLOAD_BLOCK_SIZE		(1024)

/* For boot loader detection */
#define DOWNLOAD_ARE_YOU_HERE		(0x87654321)
#define DOWNLOAD_I_AM_HERE		(0x12345678)

/* Download error code */
#define DOWNLOAD_PENDING		(0xFFFFFFFF)
#define DOWNLOAD_SUCCESS		(0)
#define DOWNLOAD_EXCEPTION		(1)
#define DOWNLOAD_ERR_MEM_1		(2)
#define DOWNLOAD_ERR_MEM_2		(3)
#define DOWNLOAD_ERR_SOFTWARE		(4)
#define DOWNLOAD_ERR_FILE_SIZE		(5)
#define DOWNLOAD_ERR_CHECKSUM		(6)
#define DOWNLOAD_ERR_OVERFLOW		(7)
#define DOWNLOAD_ERR_IMAGE		(8)
#define DOWNLOAD_ERR_HOST		(9)
#define DOWNLOAD_ERR_ABORT		(10)


#define SYS_BASE_ADDR_SILICON		(0)
#define PAC_BASE_ADDRESS_SILICON	(SYS_BASE_ADDR_SILICON + 0x09000000)
#define PAC_SHARED_MEMORY_SILICON	(PAC_BASE_ADDRESS_SILICON)

#define BES26000_APB(addr)		(PAC_SHARED_MEMORY_SILICON + (addr))

/* ***************************************************************
*Device register definitions
*************************************************************** */
/* WBF - SPI Register Addresses */
#define ST90TDS_ADDR_ID_BASE		(0x0000)
/* 16/32 bits */
#define ST90TDS_CONFIG_REG_ID		(0x0000)
/* 16/32 bits */
#define ST90TDS_CONTROL_REG_ID		(0x0001)
/* 16 bits, Q mode W/R */
#define ST90TDS_IN_OUT_QUEUE_REG_ID	(0x0002)
/* 32 bits, AHB bus R/W */
#define ST90TDS_AHB_DPORT_REG_ID	(0x0003)
/* 16/32 bits */
#define ST90TDS_SRAM_BASE_ADDR_REG_ID   (0x0004)
/* 32 bits, APB bus R/W */
#define ST90TDS_SRAM_DPORT_REG_ID	(0x0005)
/* 32 bits, t_settle/general */
#define ST90TDS_TSET_GEN_R_W_REG_ID	(0x0006)
/* 16 bits, Q mode read, no length */
#define ST90TDS_FRAME_OUT_REG_ID	(0x0007)
#define ST90TDS_ADDR_ID_MAX		(ST90TDS_FRAME_OUT_REG_ID)

/* WBF - Control register bit set */
/* next o/p length, bit 11 to 0 */
#define ST90TDS_CONT_NEXT_LEN_MASK	(0x0FFF)
#define ST90TDS_CONT_WUP_BIT		(BIT(12))
#define ST90TDS_CONT_RDY_BIT		(BIT(13))
#define ST90TDS_CONT_IRQ_ENABLE		(BIT(14))
#define ST90TDS_CONT_RDY_ENABLE		(BIT(15))
#define ST90TDS_CONT_IRQ_RDY_ENABLE	(BIT(14)|BIT(15))

/* SPI Config register bit set */
#define ST90TDS_CONFIG_FRAME_BIT	(BIT(2))
#define ST90TDS_CONFIG_WORD_MODE_BITS	(BIT(3)|BIT(4))
#define ST90TDS_CONFIG_WORD_MODE_1	(BIT(3))
#define ST90TDS_CONFIG_WORD_MODE_2	(BIT(4))
#define ST90TDS_CONFIG_ERROR_0_BIT	(BIT(5))
#define ST90TDS_CONFIG_ERROR_1_BIT	(BIT(6))
#define ST90TDS_CONFIG_ERROR_2_BIT	(BIT(7))
/* TBD: Sure??? */
#define ST90TDS_CONFIG_CSN_FRAME_BIT	(BIT(7))
#define ST90TDS_CONFIG_ERROR_3_BIT	(BIT(8))
#define ST90TDS_CONFIG_ERROR_4_BIT	(BIT(9))
/* QueueM */
#define ST90TDS_CONFIG_ACCESS_MODE_BIT	(BIT(10))
/* AHB bus */
#define ST90TDS_CONFIG_AHB_PFETCH_BIT	(BIT(11))
#define ST90TDS_CONFIG_CPU_CLK_DIS_BIT	(BIT(12))
/* APB bus */
#define ST90TDS_CONFIG_PFETCH_BIT	(BIT(13))
/* cpu reset */
#define ST90TDS_CONFIG_CPU_RESET_BIT	(BIT(14))
#define ST90TDS_CONFIG_CLEAR_INT_BIT	(BIT(15))

/* For BES2600 the IRQ Enable and Ready Bits are in CONFIG register */
#define ST90TDS_CONF_IRQ_RDY_ENABLE	(BIT(16)|BIT(17))

void bes2600_reg_set_object(struct sbus_ops *ops, struct sbus_priv *priv);
int bes2600_data_read(void *buf, size_t buf_len);
int bes2600_data_write(const void *buf, size_t buf_len);

int bes2600_reg_read(u32 addr, void *buf, size_t buf_len);
int bes2600_reg_write(u32 addr, const void *buf, size_t buf_len);

static inline int bes2600_reg_read_16(u16 addr, u16 *val)
{
	return bes2600_reg_read(addr, val, sizeof(*val));
}

static inline int bes2600_reg_write_16(u16 addr, u16 val)
{
	return bes2600_reg_write(addr, &val, sizeof(val));
}

static inline int bes2600_reg_read_32(u16 addr, u32 *val)
{
	return bes2600_reg_read(addr, val, sizeof(val));
}

static inline int bes2600_reg_write_32(u16 addr, u32 val)
{
	return bes2600_reg_write(addr, &val, sizeof(val));
}

int bes2600_indirect_read(u32 addr, void *buf, size_t buf_len, u32 prefetch, u16 port_addr);
int bes2600_apb_write(u32 addr, const void *buf, size_t buf_len);
int bes2600_ahb_write(u32 addr, const void *buf, size_t buf_len);

static inline int bes2600_apb_read(u32 addr, void *buf, size_t buf_len)
{
	return bes2600_indirect_read(addr, buf, buf_len,
		ST90TDS_CONFIG_PFETCH_BIT, ST90TDS_SRAM_DPORT_REG_ID);
}

static inline int bes2600_ahb_read(u32 addr, void *buf, size_t buf_len)
{
	return bes2600_indirect_read(addr, buf, buf_len,
		ST90TDS_CONFIG_AHB_PFETCH_BIT, ST90TDS_AHB_DPORT_REG_ID);
}

static inline int bes2600_apb_read_32(u32 addr, u32 *val)
{
	return bes2600_apb_read(addr, val, sizeof(val));
}

static inline int bes2600_apb_write_32(u32 addr, u32 val)
{
	return bes2600_apb_write(addr, &val, sizeof(val));
}

static inline int bes2600_ahb_read_32(u32 addr, u32 *val)
{
	return bes2600_ahb_read(addr, val, sizeof(val));
}

#if defined(BES2600_DETECTION_LOGIC)
static inline int bes2600_ahb_write_32(u32 addr, u32 val)
{
	return bes2600_ahb_write(addr, &val, sizeof(val));
}
#endif /*BES2600_DETECTION_LOGIC*/

#ifdef CONFIG_BES2600_WLAN_SDIO
#define SDIO_DEVICE_SEND_INT_LEN_SEPARATE

#define BES_TX_CTRL_REG_ID	(0x0)

#ifdef SDIO_DEVICE_SEND_INT_LEN_SEPARATE
#define BES_TX_NEXT_LEN_REG_ID	(0x104)
#else
#define BES_TX_NEXT_LEN_REG_ID	BES_TX_CTRL_REG_ID
#endif

#define BES_TX_NEXT_LEN_MASK	(0xffff)
#define BES_TX_DATA_ADDR	(0x0)

#define BES_HOST_INT_REG_ID		(0x120)
#define BES_HOST_INT			(1 << 0)
#define BES_AP_WAKEUP_CFG		(1 << 1)
#define BES_SUBSYSTEM_MCU_DEACTIVE	(1 << 2)
#define BES_SUBSYSTEM_MCU_ACTIVE	(1 << 3)
#define BES_SUBSYSTEM_WIFI_DEACTIVE	(1 << 4)
#define BES_SUBSYSTEM_WIFI_ACTIVE	(1 << 5)
#define BES_SUBSYSTEM_WIFI_DEBUG	(1 << 6)
#define BES_SUBSYSTEM_BT_DEACTIVE	(1 << 7)
#define BES_SUBSYSTEM_BT_ACTIVE		(1 << 8)
#define BES_SUBSYSTEM_SYSTEM_CLOSE	(1 << 9)
#define BES_SUBSYSTEM_BT_WAKEUP		(1 << 10)
#define BES_SUBSYSTEM_BT_SLEEP		(1 << 11)

#define BES_AP_WAKEUP_TYPE_MASK		0xC
#define BES_AP_WAKEUP_TYPE_SHIFT	2
#define BES_AP_WAKEUP_TYPE_GPIO		0
#define BES_AP_WAKEUP_TYPE_IF		1

#define BES_AP_WAKEUP_REG_ID		(0x124)
#define BES_AP_WAKEUP_CFG_VALID		(0x80)

#define BES_AP_WAKEUP_GPIO_MASK		(0x3)
#define BES_AP_WAKEUP_GPIO_HIGH		(0x0)
#define BES_AP_WAKEUP_GPIO_LOW		(0x1)
#define BES_AP_WAKEUP_GPIO_RISE		(0x2)
#define BES_AP_WAKEUP_GPIO_FALL		(0x3)

#define BES_SLAVE_STATUS_REG_ID			(0x10c)
#define BES_SLAVE_STATUS_MCU_READY		(1 << 0)
#define BES_SLAVE_STATUS_DPD_READY		(1 << 1)
#define BES_SLAVE_STATUS_WIFI_READY		(1 << 2)
#define BES_SLAVE_STATUS_BT_READY		(1 << 3)
#define BES_SLAVE_STATUS_MCU_WAKEUP_READY	(1 << 4)
#define BES_SLAVE_STATUS_BT_WAKE_READY		(1 << 5)
#define BES_SLAVE_STATUS_DPD_LOG_READY		(1 << 6)

#define PACKET_TOTAL_LEN(len) 		((len) & 0xffff)
#define PACKET_COUNT(len) 		(((len) >> 16) & 0xff)
#define PAKCET_CRC8(len) 		(((len) >> 24) & 0xff)

#define BES_SDIO_RX_MULTIPLE_NUM (16)
#define BES_SDIO_TX_MULTIPLE_NUM (16)
#define BES_SDIO_TX_MULTIPLE_NUM_NOSIGNAL (1)
#endif

#ifdef CONFIG_BES2600_WLAN_SPI

#define SPI_RD_CFG_REG_ID	(0xfffc0004)
#define SPI_NCONTINUOUS_CFG_VAL	(0x0)
#define SPI_CONTINUOUS_CFG_VAL	(0x1)
#define SPI_RD_ADDR(X)	((X >> 2) | (1 << 30))
#define SPI_WR_ADDR(X)	((X >> 2) | (0 << 30))

#define SPI_MASTER_SECTION_BASE (0x20083000)

#define BES_HOST_SYNC_REG_ID    (SPI_MASTER_SECTION_BASE)
#define BES_SLAVE_SYNC_HEADER   (0xbe572002)

#define BES_HOST_SUBINT_REG_ID  (SPI_MASTER_SECTION_BASE + 0x4)
#define BES_SLAVE_STATUS_REG_ID (SPI_MASTER_SECTION_BASE + 0X8)

#define BES_LMAC_BUF_NUMS	    (64)
#define BES_LMAC_BUF_TOTAL      (SPI_MASTER_SECTION_BASE + 0xC)

#define BES_TX_CTRL_REG_ID      (SPI_MASTER_SECTION_BASE + 0x10)
#define BES_TX_NEXT_LEN_MASK    (0xffffffff)

#define BES_LMAC_BUF_DESC       (SPI_MASTER_SECTION_BASE + 0x14)

#define BES_TX_DATA_ADDR        (SPI_MASTER_SECTION_BASE + 0x114)

#define MAX_SEND_PACKETS_NUM    (8)
#define BES_MISC_DATA_ADDR      (BES_TX_DATA_ADDR + (1632 + 4 + 4) * MAX_SEND_PACKETS_NUM)

#define BES_CALI_DATA_ADDR      (0x2008c000)
#define BES_FACTORY_DATA_ADDR   (0x2008b000)


#define BES_HOST_INT_REG_ID                     (0x40000098)
#define BES_HOST_INT_RD_DONE                    (1 << 0)
#define BES_HOST_INT_WR_DONE                    (1 << 1)
#define BES_HOST_INT_SUBINT                     (1 << 2)

#define BES_AP_WAKEUP_CFG                       (1 << 1)
#define BES_SUBSYSTEM_MCU_DEACTIVE              (1 << 2)
#define BES_SUBSYSTEM_MCU_ACTIVE                (1 << 3)
#define BES_SUBSYSTEM_WIFI_DEACTIVE             (1 << 4)
#define BES_SUBSYSTEM_WIFI_ACTIVE               (1 << 5)
#define BES_SUBSYSTEM_WIFI_DEBUG                (1 << 6)
#define BES_SUBSYSTEM_BT_DEACTIVE               (1 << 7)
#define BES_SUBSYSTEM_BT_ACTIVE                 (1 << 8)
#define BES_SUBSYSTEM_SYSTEM_CLOSE              (1 << 9)
#define BES_DLD_FACTORY_DATA_DONE               (1 << 12)
#define BES_DLD_DPD_DATA_DONE                   (1 << 13)
#define BES_MISC_DATA_DONE                      (1 << 14)

#define BES_SLAVE_STATUS_MCU_READY              (1 << 0)
#define BES_SLAVE_STATUS_WIFI_CALI_READY        (1 << 1)
#define BES_SLAVE_STATUS_WIFI_OPEN_READY        (1 << 2)
#define BES_SLAVE_STATUS_BT_OPEN_READY          (1 << 3)
#define BES_SLAVE_STATUS_MCU_WAKEUP_READY       (1 << 4)

#define PACKET_TOTAL_LEN_V2(len) ((len) & 0xfffffff)
#define PACKET_COUNT_V2(len) (((len) >> 28) & 0xf)

#endif

#endif /* BES2600_HWIO_H_INCLUDED */
