/*
 * DebugFS code for BES2600 mac80211 driver
 *
 * Copyright (c) 2011, Bestechnic
 * Author:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef BES2600_DEBUG_H_INCLUDED
#define BES2600_DEBUG_H_INCLUDED

#include "itp.h"

struct cw200_common;

struct bes2600_debug_common {
	struct dentry *debugfs_phy;
	int tx_cache_miss;
	int tx_burst;
	int rx_burst;
	int ba_cnt;
	int ba_acc;
	int ba_cnt_rx;
	int ba_acc_rx;
#ifdef CONFIG_BES2600_ITP
	struct bes2600_itp itp;
#endif /* CONFIG_BES2600_ITP */
};

struct bes2600_debug_priv {
	struct dentry *debugfs_phy;
	int tx;
	int tx_agg;
	int rx;
	int rx_agg;
	int tx_multi;
	int tx_multi_frames;
	int tx_align;
	int tx_ttl;
};

#ifdef CONFIG_BES2600_DEBUGFS
int bes2600_debug_init_common(struct bes2600_common *hw_priv);
int bes2600_debug_init_priv(struct bes2600_common *hw_priv,
			   struct bes2600_vif *priv);
void bes2600_debug_release_common(struct bes2600_common *hw_priv);
void bes2600_debug_release_priv(struct bes2600_vif *priv);

static inline void bes2600_debug_txed(struct bes2600_vif *priv)
{
	++priv->debug->tx;
}

static inline void bes2600_debug_txed_agg(struct bes2600_vif *priv)
{
	++priv->debug->tx_agg;
}

static inline void bes2600_debug_txed_multi(struct bes2600_vif *priv,
					   int count)
{
	++priv->debug->tx_multi;
	priv->debug->tx_multi_frames += count;
}

static inline void bes2600_debug_rxed(struct bes2600_vif *priv)
{
	++priv->debug->rx;
}

static inline void bes2600_debug_rxed_agg(struct bes2600_vif *priv)
{
	++priv->debug->rx_agg;
}

static inline void bes2600_debug_tx_cache_miss(struct bes2600_common *common)
{
	++common->debug->tx_cache_miss;
}

static inline void bes2600_debug_tx_align(struct bes2600_vif *priv)
{
	++priv->debug->tx_align;
}

static inline void bes2600_debug_tx_ttl(struct bes2600_vif *priv)
{
	++priv->debug->tx_ttl;
}

static inline void bes2600_debug_tx_burst(struct bes2600_common *hw_priv)
{
	++hw_priv->debug->tx_burst;
}

static inline void bes2600_debug_rx_burst(struct bes2600_common *hw_priv)
{
	++hw_priv->debug->rx_burst;
}

static inline void bes2600_debug_ba(struct bes2600_common *hw_priv,
				   int ba_cnt, int ba_acc, int ba_cnt_rx,
				   int ba_acc_rx)
{
	hw_priv->debug->ba_cnt = ba_cnt;
	hw_priv->debug->ba_acc = ba_acc;
	hw_priv->debug->ba_cnt_rx = ba_cnt_rx;
	hw_priv->debug->ba_acc_rx = ba_acc_rx;
}

int bes2600_print_fw_version(struct bes2600_common *hw_priv, u8* buf, size_t len);

#else /* CONFIG_BES2600_DEBUGFS */

static inline int bes2600_debug_init_common(struct bes2600_common *hw_priv)
{
	return 0;
}

static inline int bes2600_debug_init_priv(struct bes2600_common *hw_priv,
			   struct bes2600_vif *priv)
{
	return 0;
}

static inline void bes2600_debug_release_common(struct bes2600_common *hw_priv)
{
}

static inline void bes2600_debug_release_priv(struct bes2600_vif *priv)
{
}

static inline void bes2600_debug_txed(struct bes2600_vif *priv)
{
}

static inline void bes2600_debug_txed_agg(struct bes2600_vif *priv)
{
}

static inline void bes2600_debug_txed_multi(struct bes2600_vif *priv,
					   int count)
{
}

static inline void bes2600_debug_rxed(struct bes2600_vif *priv)
{
}

static inline void bes2600_debug_rxed_agg(struct bes2600_vif *priv)
{
}

static inline void bes2600_debug_tx_cache_miss(struct bes2600_vif *priv)
{
}

static inline void bes2600_debug_tx_align(struct bes2600_vif *priv)
{
}

static inline void bes2600_debug_tx_ttl(struct bes2600_vif *priv)
{
}

static inline void bes2600_debug_tx_burst(struct bes2600_common *hw_priv)
{
}

static inline void bes2600_debug_rx_burst(struct bes2600_common *hw_priv)
{
}

static inline void bes2600_debug_ba(struct bes2600_common *hw_priv,
				   int ba_cnt, int ba_acc, int ba_cnt_rx,
				   int ba_acc_rx)
{
}

static inline int bes2600_print_fw_version(struct bes2600_common *hw_priv, u8* buf, size_t len)
{
	return 0;
}

#endif /* CONFIG_BES2600_DEBUGFS */

#endif /* BES2600_DEBUG_H_INCLUDED */
