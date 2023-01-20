/*
 * Device handling thread interface for mac80211 BES2600 drivers
 *
 * Copyright (c) 2010, Bestechnic
 * Author:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef BES2600_BH_H
#define BES2600_BH_H

/* extern */ struct bes2600_common;

#define SDIO_BLOCK_SIZE (528)

#define KEY_FRAME_SW_RETRY
#ifdef  KEY_FRAME_SW_RETRY
#define CW1200_MAX_SW_RETRY_CNT		(2)
#endif


int bes2600_register_bh(struct bes2600_common *hw_priv);
void bes2600_unregister_bh(struct bes2600_common *hw_priv);
void bes2600_irq_handler(struct bes2600_common *hw_priv);
void bes2600_bh_wakeup(struct bes2600_common *hw_priv);
int bes2600_bh_suspend(struct bes2600_common *hw_priv);
int bes2600_bh_resume(struct bes2600_common *hw_priv);
/* Must be called from BH thread. */
void bes2600_enable_powersave(struct bes2600_vif *priv,
			     bool enable);
int wsm_release_tx_buffer(struct bes2600_common *hw_priv, int count);
int wsm_release_vif_tx_buffer(struct bes2600_common *hw_priv, int if_id,
				int count);
int bes2600_bh_sw_process(struct bes2600_common *hw_priv,
			 struct wsm_tx_confirm *tx_confirm);


#endif /* BES2600_BH_H */
