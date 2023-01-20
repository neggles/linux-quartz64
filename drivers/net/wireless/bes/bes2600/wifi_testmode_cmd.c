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
#ifdef CONFIG_BES2600_TESTMODE
#include <net/netlink.h>
#include <linux/module.h>
#include <linux/firmware.h>
#include <linux/etherdevice.h>
#include <linux/vmalloc.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <net/mac80211.h>
#include <linux/time.h>
#include <linux/string.h>

#include "wsm.h"
#include "bes2600.h"
#include "bes_nl80211_testmode_msg.h"
#include "bes2600_driver_mode.h"
#include "bes_chardev.h"
#include "bes2600_factory.h"


/* store the reply message of the rf cmd */
static struct vendor_rf_cmd_msg_reply vendor_rf_cmd_reply;

extern int bes2600_testmode_reply(struct wiphy *wiphy, const void *data, int len);

void bes2600_rf_cmd_msg_assembly(u32 cmd_type, void *data, u32 msg_len)
{
	vendor_rf_cmd_reply.id = cmd_type;
	vendor_rf_cmd_reply.msg_len = msg_len + 2 * sizeof(u32);

	if (msg_len)
		memcpy(vendor_rf_cmd_reply.ret_msg, (u8 *)data, msg_len);
	else
		vendor_rf_cmd_reply.ret_msg[0] = '\0';

}

/**
 * bes2600_vendor_rf_cmd, signaling cmd & rf nosignaling cmd
 * reaches bes2600
 *
 * @hw: the hardware
 * @vif: vif
 * @data: incoming data
 * @len: incoming data length
 *
 * Returns: 0 on success or non zero value on failure
 */
int bes2600_vendor_rf_cmd(struct ieee80211_hw *hw, struct ieee80211_vif *vif, u8 *data, int len)
{
	struct bes2600_common *hw_priv = hw->priv;
	int ret = 0;
	int recv_timeout = 1000; /* delay waiting for reply message for 4 seconds */
	struct vendor_rf_cmd_t *vendor_rf_cmd = (struct vendor_rf_cmd_t *)data;
	//struct timeval tstart, tend;
	int if_id = 0;
	u32 count, cmd_len, cmd_type;

	count = vendor_rf_cmd->cmd_argc;
	cmd_len = vendor_rf_cmd->cmd_len;
	cmd_type = vendor_rf_cmd->cmd_type;

	if (count == 0 || cmd_len == 0 ||
		strlen(vendor_rf_cmd->cmd) + 1 != cmd_len) {
		bes2600_err(BES2600_DBG_TEST_MODE, "%s line: %d, "
			"vendor rf cmd parsing failed\n", __func__, __LINE__);
		return -EINVAL;
	}

	bes2600_info(BES2600_DBG_TEST_MODE, "vendor cmd = %s\n", vendor_rf_cmd->cmd);


	/**
	 * signaling mode does not support the saving of calibration files,
	 * but the saved calibration values can be read.
	 *
	 */
	if (bes2600_chrdev_is_signal_mode()) {
		if (cmd_type == VENDOR_RF_SAVE_FREQOFFSET_CMD ||
			cmd_type == VENDOR_RF_SAVE_POWERLEVEL_CMD ||
			cmd_type == VENDOR_RF_POWER_CALIB_FINISH)
			return -EOPNOTSUPP;
	}

	if (cmd_type == VENDOR_RF_SIG_NOSIG_MIX) {
		if (bes2600_chrdev_is_signal_mode()) {
			vendor_rf_cmd->cmd_type = VENDOR_RF_SIGNALING_CMD;
			cmd_type = VENDOR_RF_SIGNALING_CMD;
		} else {
			vendor_rf_cmd->cmd_type = VENDOR_RF_NOSIGNALING_CMD;
			cmd_type = VENDOR_RF_NOSIGNALING_CMD;
		}
	}

	switch (cmd_type) {
	case VENDOR_RF_POWER_CALIB_FINISH:
	case VENDOR_RF_GET_SAVE_FREQOFFSET_CMD:
	case VENDOR_RF_GET_SAVE_POWERLEVEL_CMD:
	case VENDOR_RF_SIGNALING_CMD:
	case VENDOR_RF_NOSIGNALING_CMD:
	case VENDOR_RF_SAVE_FREQOFFSET_CMD:
	case VENDOR_RF_SAVE_POWERLEVEL_CMD:
		sema_init(&hw_priv->vendor_rf_cmd_replay_sema, 0);
		ret = wsm_vendor_rf_cmd(hw_priv, if_id, vendor_rf_cmd);

		if (ret) {
			bes2600_err(BES2600_DBG_TEST_MODE, "vendor rf cmd send error code = %d\n", ret);
			return ret;
		}

		//do_gettimeofday(&tstart);
		if (down_timeout(&hw_priv->vendor_rf_cmd_replay_sema, recv_timeout)) {
			bes2600_err(BES2600_DBG_TEST_MODE, "vendor rf cmd failed to receive reply message\n");
			return -ENOMSG;
		}
		//do_gettimeofday(&tend);
		//bes2600_dbg(BES2600_DBG_TEST_MODE,"recv time: %ldms\n",
		//1000 * (tend.tv_sec - tstart.tv_sec) + (tend.tv_usec - tstart.tv_usec) / 1000);

		ret = bes2600_testmode_reply(hw->wiphy, &vendor_rf_cmd_reply, vendor_rf_cmd_reply.msg_len);
		vendor_rf_cmd_reply.ret_msg[0] = '\0';
		break;
	case VENDOR_RF_SIG_NOSIG_MIX:
		ret = 0;
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	return ret;
}
#endif /* CONFIG_BES2600_TESTMODE */
