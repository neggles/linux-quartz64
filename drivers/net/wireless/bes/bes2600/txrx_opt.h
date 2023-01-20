
/***************************************************************************
 *
 * Copyright 2015-2022 BES.
 * All rights reserved. All unpublished rights reserved.
 *
 * No part of this work may be used or reproduced in any form or by any
 * means, or stored in a database or retrieval system, without prior written
 * permission of BES.
 *
 * Use of this work is governed by a license granted by BES.
 * This work contains confidential and proprietary information of
 * BES. which is protected by copyright, trade secret,
 * trademark and other intellectual property rights.
 *
 ****************************************************************************/
#ifndef bes2600_TXRX_OPT_H
#define bes2600_TXRX_OPT_H
#include <linux/list.h>
/* open it for enhance wifi throughput */
#define BES2600_TX_RX_OPT   1
void bes2600_add_tx_ac_delta_time(int ac, uint32_t del_time);
void bes2600_add_tx_delta_time(uint32_t tx_time);
void bes2600_rx_status(struct bes2600_vif *priv, struct sk_buff *skb);
void bes2600_tx_status(struct bes2600_vif *priv, struct sk_buff *skb);
void bes2600_dynamic_opt_rxtx(struct bes2600_common *hw_priv,struct bes2600_vif *priv, int rssi);
int txrx_opt_timer_init(struct bes2600_common *hw_priv);
int txrx_opt_timer_exit(struct bes2600_common *hw_priv);

#endif

