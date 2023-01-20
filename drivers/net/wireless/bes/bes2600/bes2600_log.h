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
#ifndef __BES2600_LOG_H__
#define __BES2600_LOG_H__

/* Log Level Control */
#define BES2600_LOG_NONE		0
#define BES2600_LOG_ERROR		1
#define BES2600_LOG_WARN		2
#define BES2600_LOG_INFO		3
#define BES2600_LOG_DBG			4


/* Module Log Level Control */
#define BES2600_DBG_DOWNLOAD_LVL	BES2600_LOG_INFO
#define BES2600_DBG_NIY_LVL         	BES2600_LOG_INFO
#define BES2600_DBG_SBUS_LVL        	BES2600_LOG_INFO
#define BES2600_DBG_INIT_LVL        	BES2600_LOG_INFO
#define BES2600_DBG_TXRX_LVL	       	BES2600_LOG_INFO
#define BES2600_DBG_TXRX_OPT_LVL       	BES2600_LOG_INFO
#define BES2600_DBG_QUEUE_LVL       	BES2600_LOG_INFO
#define BES2600_DBG_SPI_LVL		BES2600_LOG_INFO
#define BES2600_DBG_SDIO_LVL		BES2600_LOG_INFO
#define BES2600_DBG_USB_LVL		BES2600_LOG_INFO
#define BES2600_DBG_PM_LVL   		BES2600_LOG_INFO
#define BES2600_DBG_SYS_LVL		BES2600_LOG_INFO
#define BES2600_DBG_BT_LVL		BES2600_LOG_INFO
#define BES2600_DBG_ANDROID_LVL		BES2600_LOG_INFO
#define BES2600_DBG_BH_LVL		BES2600_LOG_INFO
#define BES2600_DBG_AP_LVL		BES2600_LOG_INFO
#define BES2600_DBG_STA_LVL		BES2600_LOG_INFO
#define BES2600_DBG_SCAN_LVL		BES2600_LOG_INFO
#define BES2600_DBG_ITP_LVL		BES2600_LOG_INFO
#define BES2600_DBG_TEST_MODE_LVL	BES2600_LOG_INFO
#define BES2600_DBG_TX_POLICY_LVL	BES2600_LOG_INFO
#define BES2600_DBG_WSM_LVL		BES2600_LOG_INFO
#define BES2600_DBG_ROC_LVL		BES2600_LOG_NONE
#define BES2600_DBG_CHARDEV_LVL		BES2600_LOG_INFO
#define BES2600_DBG_FACTORY_LVL		BES2600_LOG_INFO
#define BES2600_DBG_EPTA_LVL		BES2600_LOG_INFO
#define BES2600_DBG_PWR_LVL		BES2600_LOG_INFO
#define BES2600_DBG_TXLOOP_LVL		BES2600_LOG_INFO

#define GET_LOG_LVL(module)		(module##_LVL)

#define bes2600_dbg(module, ...)				\
	do {							\
		if (GET_LOG_LVL(module) >= BES2600_LOG_DBG)	\
			printk(KERN_INFO __VA_ARGS__);		\
	} while (0)
#define bes2600_dbg_with_cond(cond, module, ...)		\
	do {							\
		if ((0 != (cond)) && 				\
		    GET_LOG_LVL(module) >= BES2600_LOG_DBG)	\
			printk(KERN_DEBUG __VA_ARGS__);		\
	} while (0)
#define bes2600_dbg_dump(module, desc, array, len)		\
	do {							\
		if (GET_LOG_LVL(module) >= BES2600_LOG_DBG)	\
			print_hex_dump(KERN_DEBUG, 		\
				desc, DUMP_PREFIX_NONE,		\
				16, 1, array, 			\
				len, false);			\
	} while(0)



#define bes2600_info(module, ...)				\
	do {							\
		if (GET_LOG_LVL(module) >= BES2600_LOG_INFO)	\
			printk(KERN_INFO __VA_ARGS__);		\
	} while (0)
#define bes2600_info_with_cond(cond, module, ...)		\
	do {							\
		if ((0 != (cond)) && 				\
		    GET_LOG_LVL(module) >= BES2600_LOG_INFO)	\
			printk(KERN_INFO __VA_ARGS__);		\
	} while (0)
#define bes2600_info_dump(module, desc, array, len)		\
	do {							\
		if (GET_LOG_LVL(module) >= BES2600_LOG_INFO)	\
			print_hex_dump(KERN_INFO, 		\
				desc, DUMP_PREFIX_NONE,		\
				16, 1, array, 			\
				len, false);			\
	} while(0)


#define bes2600_warn(module, ...)				\
	do {							\
		if (GET_LOG_LVL(module) >= BES2600_LOG_WARN)	\
			printk(KERN_WARNING __VA_ARGS__);	\
	} while (0)
#define bes2600_warn_with_cond(cond, module, ...)		\
	do {							\
		if ((0 != (cond)) && 				\
		    GET_LOG_LVL(module) >= BES2600_LOG_WARN)	\
			printk(KERN_WARNING __VA_ARGS__);	\
	} while (0)
#define bes2600_warn_dump(module, desc, array, len)		\
	do {							\
		if (GET_LOG_LVL(module) >= BES2600_LOG_WARN)	\
			print_hex_dump(KERN_WARNING, 		\
				desc, DUMP_PREFIX_NONE,		\
				16, 1, array, 			\
				len, false);			\
	} while(0)



#define bes2600_err(module, ...)				\
	do {							\
		if (GET_LOG_LVL(module) >= BES2600_LOG_ERROR)	\
			printk(KERN_ERR __VA_ARGS__);		\
	} while (0)
#define bes2600_err_with_cond(cond, module, ...)		\
	do {							\
		if ((0 != (cond)) && 				\
		    GET_LOG_LVL(module) >= BES2600_LOG_ERROR)	\
			printk(KERN_ERR __VA_ARGS__);		\
	} while (0)
#define bes2600_err_dump(module, desc, array, len)		\
	do {							\
		if (GET_LOG_LVL(module) >= BES2600_LOG_ERROR)	\
			print_hex_dump(KERN_ERR, 		\
				desc, DUMP_PREFIX_NONE,		\
				16, 1, array, 			\
				len, false);			\
	} while(0)


#define STUB()							\
	do {							\
		bes2600_dbg(BES2600_DBG_NIY,			\
			   "%s: STUB at line %d.\n",		\
			   __func__, __LINE__);			\
	} while (0)

#endif
