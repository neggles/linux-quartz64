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
#ifndef _BES2600_DRIVER_MODE_CMD_
#define _BES2600_DRIVER_MODE_CMD_

#ifdef FW_DOWNLOAD_BY_UART
#if defined(PLAT_ALLWINNER_T507)
#if defined(CONFIG_BES2600_WLAN_SDIO)
#define BES2600_LOAD_BOOT_NAME          "/vendor/firmware/best2002_fw_boot_sdio.bin"
#define BES2600_LOAD_FW_NAME            "/vendor/firmware/best2002_fw_sdio.bin"
#define BES2600_LOAD_NOSIGNAL_FW_NAME       "/vendor/firmware/best2002_fw_sdio_nosignal_uart.bin"
#define BES2600_LOAD_BTRF_FW_NAME       "/vendor/firmware/best2002_fw_sdio_btrf.bin"

#elif defined(CONFIG_BES2600_WLAN_SPI)
#define BES2600_LOAD_BOOT_NAME     "/vendor/firmware/best2002_fw_boot_spi.bin"
#define BES2600_LOAD_FW_NAME        "/vendor/firmware/best2002_fw_spi.bin"
#define BES2600_LOAD_NOSIGNAL_FW_NAME   "/vendor/firmware/best2002_fw_spi_nosignal.bin"
#define BES2600_LOAD_BTRF_FW_NAME   "/vendor/firmware/best2002_fw_spi_btrf.bin"
#endif
#endif

#if defined(PLAT_QCOM_QM215)
#define BES2600_LOAD_BOOT_NAME           "/data/wifi/best2002_fw_boot_spi.bin"
#define BES2600_LOAD_FW_NAME             "/data/wifi/best2002_fw_spi.bin"
#define BES2600_LOAD_NOSIGNAL_FW_NAME    "/data/wifi/best2002_fw_spi_nosignal.bin"
#define BES2600_LOAD_BTRF_FW_NAME        "/data/wifi/best2002_fw_spi_btrf.bin"
#endif
#endif

#ifdef FW_DOWNLOAD_BY_SDIO
#ifndef PLAT_GENERIC
#define BES2600_LOAD_BOOT_NAME      "best2002_fw_boot_sdio.bin"
#define BES2600_LOAD_FW_NAME        "best2002_fw_sdio.bin"
#define BES2600_LOAD_NOSIGNAL_FW_NAME   "best2002_fw_sdio_nosignal.bin"
#define BES2600_LOAD_BTRF_FW_NAME   "best2002_fw_sdio_btrf.bin"
#else
#define BES2600_LOAD_BOOT_NAME      "bes2600/best2002_fw_boot_sdio.bin"
#define BES2600_LOAD_FW_NAME        "bes2600/best2002_fw_sdio.bin"
#define BES2600_LOAD_NOSIGNAL_FW_NAME   "bes2600/best2002_fw_sdio_nosignal.bin"
#define BES2600_LOAD_BTRF_FW_NAME   "bes2600/best2002_fw_sdio_btrf.bin"
#endif
#ifdef BES2600_BOOT_UART_TO_SDIO
#define BES2600_LOAD_FW_TOOL_PATH   "/usr/bin/bes_fw_download"
#define BES2600_LOAD_FW_TOOL_DEVICE "/dev/ttyS3"
#define BES2600_LOAD_BOOT_PATCH_NAME  "/lib/firmware/bes2600_boot_patch.bin"
#endif
#endif

#ifdef FW_DOWNLOAD_BY_USB
#define BES2600_LOAD_BOOT_NAME      "best2002_fw_boot_usb.bin"
#define BES2600_LOAD_FW_NAME        "best2002_fw_usb.bin"
#define BES2600_LOAD_NOSIGNAL_FW_NAME   "best2002_fw_usb_nosignal.bin"
#define BES2600_LOAD_BTRF_FW_NAME   "best2002_fw_usb_btrf.bin"
#endif


#endif /* _BES2600_DRIVER_MODE_CMD_ */
