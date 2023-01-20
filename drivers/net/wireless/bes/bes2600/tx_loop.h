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
#ifndef __TX_LOOP_H__
#define __TX_LOOP_H__

#include "bes2600.h"

struct bes2600_tx_loop
{
        bool enabled;
        spinlock_t tx_loop_lock;
        u8 start_lmac_seq;
        u8 start_mcu_seq;
        struct sk_buff_head rx_queue;
        u8 *wsm_cmd_ptr;
};

void bes2600_tx_loop_init(struct bes2600_common *hw_priv);
void bes2600_tx_loop_record_wsm_cmd(struct bes2600_common *hw_priv, u8 *wsm_cmd);
void bes2600_tx_loop_clear_wsm_cmd(struct bes2600_common *hw_priv);
struct sk_buff *bes2600_tx_loop_read(struct bes2600_common *hw_priv);
void bes2600_tx_loop_set_enable(struct bes2600_common *hw_priv);
void bes2600_tx_loop_pipe_send(struct bes2600_common *hw_priv, u8 *buf, u32 len);

#endif