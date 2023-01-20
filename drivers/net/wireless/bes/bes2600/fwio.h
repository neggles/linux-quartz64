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
#ifndef FWIO_H_INCLUDED
#define FWIO_H_INCLUDED

#define FIRMWARE_1250_CUT11	("wsm_5011.bin")
#define FIRMWARE_CUT22		("wsm_22.bin")
#define FIRMWARE_CUT20		("wsm_20.bin")
#define FIRMWARE_CUT11		("wsm_11.bin")
#define FIRMWARE_CUT10		("wsm_10.bin")
#if defined(BES2600_DETECTION_LOGIC)
#define FIRMWARE_1260_CUT10	("wsm_6010.bin")
#endif
#define SDD_FILE_1250_11	("sdd_5011.bin")
#define SDD_FILE_22		("sdd_22.bin")
#define SDD_FILE_20		("sdd_20.bin")
#define SDD_FILE_11		("sdd_11.bin")
#define SDD_FILE_10		("sdd_10.bin")
#if defined(BES2600_DETECTION_LOGIC)
#define SDD_FILE_1260_10	("sdd_6010.bin")
#endif
#if defined(BES2600_DETECTION_LOGIC)
#define BOOTLOADER_FILE_1260 	("bootloader_1260.bin")
#endif

#define BES2600_HW_REV_CUT10	(10)
#define BES2600_HW_REV_CUT11	(11)
#define BES2600_HW_REV_CUT20	(20)
#define BES2600_HW_REV_CUT22	(22)
#define CW1250_HW_REV_CUT10	(110)
#define CW1250_HW_REV_CUT11	(5011)
#if defined(BES2600_DETECTION_LOGIC)
#define BES2600_HW_REV_CUT10	(6010)
#endif
struct sbus_ops;
struct sbus_priv;

int bes2600_load_firmware(struct sbus_ops *ops, struct sbus_priv *priv);

#endif
