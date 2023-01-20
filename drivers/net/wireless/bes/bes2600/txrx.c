/*
 * Datapath implementation for BES2600 mac80211 drivers
 *
 * Copyright (c) 2022, Bestechnic
 * Author:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <net/mac80211.h>
#include <net/sock.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>

#include "bes2600.h"
#include "wsm.h"
#include "bh.h"
#include "ap.h"
#include "debug.h"
#include "sta.h"
#include "sbus.h"
#include "txrx_opt.h"

#define BES2600_INVALID_RATE_ID (0xFF)

#ifdef CONFIG_BES2600_TESTMODE
#include "bes_nl80211_testmode_msg.h"
#endif /* CONFIG_BES2600_TESTMODE */
static const struct ieee80211_rate *
bes2600_get_tx_rate(const struct bes2600_common *hw_priv,
		   const struct ieee80211_tx_rate *rate);

/* ******************************************************************** */
/* TX policy cache implementation					*/

static void tx_policy_dump(struct tx_policy *policy)
{
	bes2600_dbg(BES2600_DBG_TX_POLICY, "[TX policy] "
		"%.1X%.1X%.1X%.1X%.1X%.1X%.1X%.1X"
		"%.1X%.1X%.1X%.1X%.1X%.1X%.1X%.1X"
		"%.1X%.1X%.1X%.1X%.1X%.1X%.1X%.1X: %d\n",
		policy->raw[0] & 0x0F,  policy->raw[0] >> 4,
		policy->raw[1] & 0x0F,  policy->raw[1] >> 4,
		policy->raw[2] & 0x0F,  policy->raw[2] >> 4,
		policy->raw[3] & 0x0F,  policy->raw[3] >> 4,
		policy->raw[4] & 0x0F,  policy->raw[4] >> 4,
		policy->raw[5] & 0x0F,  policy->raw[5] >> 4,
		policy->raw[6] & 0x0F,  policy->raw[6] >> 4,
		policy->raw[7] & 0x0F,  policy->raw[7] >> 4,
		policy->raw[8] & 0x0F,  policy->raw[8] >> 4,
		policy->raw[9] & 0x0F,  policy->raw[9] >> 4,
		policy->raw[10] & 0x0F,  policy->raw[10] >> 4,
		policy->raw[11] & 0x0F,  policy->raw[11] >> 4,
		policy->defined);
}

static void bes2600_check_go_neg_conf_success(struct bes2600_common *hw_priv,
						u8 *action)
{
	if (action[2] == 0x50 && action[3] == 0x6F && action[4] == 0x9A &&
		action[5] == 0x09 && action[6] == 0x02) {
		if(action[17] == 0) {
			hw_priv->is_go_thru_go_neg = true;
		}
		else {
			hw_priv->is_go_thru_go_neg = false;
		}
	}
}

static void bes2600_check_prov_desc_req(struct bes2600_common *hw_priv,
                                                u8 *action)
{
	if (action[2] == 0x50 && action[3] == 0x6F && action[4] == 0x9A &&
                action[5] == 0x09 && action[6] == 0x07) {
                        hw_priv->is_go_thru_go_neg = false;
        }
}

static void tx_policy_build(const struct bes2600_common *hw_priv,
	/* [out] */ struct tx_policy *policy,
	struct ieee80211_tx_rate *rates, size_t count)
{
	int i, j;
	unsigned limit = hw_priv->short_frame_max_tx_count;
	unsigned total = 0;
	static int tx_rate_idx;

	BUG_ON(rates[0].idx < 0);
	memset(policy, 0, sizeof(*policy));

	/* minstrel is buggy a little bit, so distille
	 * incoming rates first. */
	/* Sort rates in descending order. */
	for (i = 0; i < count; i++) {
		if (rates[i].idx < 0) {
			count = i;
			break;
		}
		for (j= 0; j < count; j++) {
			if (rates[j].idx < 0) {
				continue;
			}

			if (rates[j].idx < rates[j + 1].idx) {
				struct ieee80211_tx_rate tmp = rates[j];
				rates[j] = rates[j + 1];
				rates[j + 1] = tmp;
			}
		}
	}
	/* enhance throughput, more tx retry rate */
#ifdef BES2600_TX_RX_OPT
	if (rates[0].flags & IEEE80211_TX_RC_MCS) {
		static int min_rate_index = 1; //min rate index  is mcs1
		static u8 last_rate_tx_cnt = 7;

		count = IEEE80211_TX_MAX_RATES;
		/* if idx < min rate index, set min rate index */
		rates[0].count = 6;
		if (rates[0].idx <= min_rate_index) {
			rates[0].idx = min_rate_index;
		}

		for (i = 1; i < count; ++i) {
			/* only one rate try 2 times*/
			if (rates[i].count > 6)
				rates[i].count = 6;
			if (rates[i - 1].idx > min_rate_index) {
				rates[i].idx = (rates[i - 1].idx - 1);
				rates[i].count = 6;
				rates[i].flags = rates[i - 1].flags;
			} else if (rates[i - 1].idx <= min_rate_index) {
				rates[i].idx = -1;
				rates[i].count = 0;
				rates[i].flags = 0;
				break;
			}
		}
		/* update the last  rate index  tx cnt */
		rates[i - 1].count = last_rate_tx_cnt;
		count = i;
	}
#endif
	/* Eliminate duplicates. */
	total = rates[0].count;
	for (i = 0, j = 1; j < count; ++j) {
		if (rates[j].idx == rates[i].idx) {
			rates[i].count += rates[j].count;
		} else if (rates[j].idx > rates[i].idx) {
			break;
		} else {
			++i;
			if (i != j)
				rates[i] = rates[j];
		}
		total += rates[j].count;
	}
	count = i + 1;

	/* Re-fill policy trying to keep every requested rate and with
	 * respect to the global max tx retransmission count. */
	if (limit < count)
		limit = count;
	if (total > limit) {
		for (i = 0; i < count; ++i) {
			int left = count - i - 1;
			if (rates[i].count > limit - left)
				rates[i].count = limit - left;
			limit -= rates[i].count;
		}
	}

	/* HACK!!! Device has problems (at least) switching from
	 * 54Mbps CTS to 1Mbps. This switch takes enormous amount
	 * of time (100-200 ms), leading to valuable throughput drop.
	 * As a workaround, additional g-rates are injected to the
	 * policy.
	 */
	if (count == 2 && !(rates[0].flags & IEEE80211_TX_RC_MCS) &&
			rates[0].idx > 4 && rates[0].count > 2 &&
			rates[1].idx < 2) {
		/* ">> 1" is an equivalent of "/ 2", but faster */
		int mid_rate = (rates[0].idx + 4) >> 1;

		/* Decrease number of retries for the initial rate */
		rates[0].count -= 2;

		if (mid_rate != 4) {
			/* Keep fallback rate at 1Mbps. */
			rates[3] = rates[1];

			/* Inject 1 transmission on lowest g-rate */
			rates[2].idx = 4;
			rates[2].count = 1;
			rates[2].flags = rates[1].flags;

			/* Inject 1 transmission on mid-rate */
			rates[1].idx = mid_rate;
			rates[1].count = 1;

			/* Fallback to 1 Mbps is a really bad thing,
			 * so let's try to increase probability of
			 * successful transmission on the lowest g rate
			 * even more */
			if (rates[0].count >= 3) {
				--rates[0].count;
				++rates[2].count;
			}

			/* Adjust amount of rates defined */
			count += 2;
		} else {
			/* Keep fallback rate at 1Mbps. */
			rates[2] = rates[1];

			/* Inject 2 transmissions on lowest g-rate */
			rates[1].idx = 4;
			rates[1].count = 2;

			/* Adjust amount of rates defined */
			count += 1;
		}
	}

	policy->defined = bes2600_get_tx_rate(hw_priv, &rates[0])->hw_value + 1;
#if 1 //add min basic rate in the tx path, driver should set wifi_Hook_cfg->new_run_flag |= RETRY_1M_RATE;
	if (rates[0].flags & IEEE80211_TX_RC_MCS) {
		int low_rate_idx = 0;  /* set default 11b 1M */
		int low_rate_count = 1;
		register unsigned rateid, off, shift, retries;
		/* if the mcs < mcs3, more retry 2 times with low rate. */
		if (rates[0].idx < 3) {
			low_rate_count += 2;
		}
		/* if the tx rate is mcs0, more retry 2 times with low rate.
		 * sample tx rate count is 1 in the minstrel_ht_set_rate.*/
		if (rates[0].idx == 0 || (rates[1].idx == 0 && rates[0].count == 1)) {
			low_rate_count += 2;
			/* smaple and mcs0 tx rate count set 2. */
			for (i = 0; i < count; i++) {
				rates[0].count = (i + 1);
			}
		}
		if (hw_priv->channel != NULL && hw_priv->channel->hw_value > 14)
			low_rate_idx = 6;  /* set default 11a 6M */

		rateid = low_rate_idx;
		off = rateid >> 3;      /* eq. rateid / 8 */
		shift = (rateid & 0x07) << 2;   /* eq. (rateid % 8) * 4 */
		retries = low_rate_count;
		policy->tbl[off] |= __cpu_to_le32(retries << shift);
		policy->retry_count += retries;
	}
#endif

	for (i = 0; i < count; ++i) {
		register unsigned rateid, off, shift, retries;

		rateid = bes2600_get_tx_rate(hw_priv, &rates[i])->hw_value;
		off = rateid >> 3;		/* eq. rateid / 8 */
		shift = (rateid & 0x07) << 2;	/* eq. (rateid % 8) * 4 */

		retries = rates[i].count;
		if (unlikely(retries > 0x0F))
			rates[i].count = retries = 0x0F;
		policy->tbl[off] |= __cpu_to_le32(retries << shift);
		policy->retry_count += retries;
	}


	if (rates[0].idx !=  tx_rate_idx) {
		tx_rate_idx = rates[0].idx;
		bes2600_dbg(BES2600_DBG_TXRX_OPT, "[TX policy] Policy (%lu): " \
			    "%d:%d, %d:%d, %d:%d, %d:%d, %d:%d\n",
			    count,
			    rates[0].idx, rates[0].count,
			    rates[1].idx, rates[1].count,
			    rates[2].idx, rates[2].count,
			    rates[3].idx, rates[3].count,
			    rates[4].idx, rates[4].count);
	}
}

static inline bool tx_policy_is_equal(const struct tx_policy *wanted,
					const struct tx_policy *cached)
{
	size_t count = wanted->defined >> 1;
	if (wanted->defined > cached->defined)
		return false;
	if (count) {
		if (memcmp(wanted->raw, cached->raw, count))
			return false;
	}
	if (wanted->defined & 1) {
		if ((wanted->raw[count] & 0x0F) != (cached->raw[count] & 0x0F))
			return false;
	}
	return true;
}

static int tx_policy_find(struct tx_policy_cache *cache,
				const struct tx_policy *wanted)
{
	/* O(n) complexity. Not so good, but there's only 8 entries in
	 * the cache.
	 * Also lru helps to reduce search time. */
	struct tx_policy_cache_entry *it;
	/* Search for policy in "used" list */
	list_for_each_entry(it, &cache->used, link) {
		if (tx_policy_is_equal(wanted, &it->policy))
			return it - cache->cache;
	}
	/* Then - in "free list" */
	list_for_each_entry(it, &cache->free, link) {
		if (tx_policy_is_equal(wanted, &it->policy))
			return it - cache->cache;
	}
	return -1;
}

static inline void tx_policy_use(struct tx_policy_cache *cache,
				 struct tx_policy_cache_entry *entry)
{
	++entry->policy.usage_count;
	list_move(&entry->link, &cache->used);
}

static inline int tx_policy_release(struct tx_policy_cache *cache,
				    struct tx_policy_cache_entry *entry)
{
	int ret = --entry->policy.usage_count;
	if (!ret)
		list_move(&entry->link, &cache->free);
	return ret;
}

/* ******************************************************************** */
/* External TX policy cache API						*/

void tx_policy_init(struct bes2600_common *hw_priv)
{
	struct tx_policy_cache *cache = &hw_priv->tx_policy_cache;
	int i;

	bes2600_dbg(BES2600_DBG_TXRX_OPT, "tx_policy_init\n\r");

	memset(cache, 0, sizeof(*cache));

	spin_lock_init(&cache->lock);
	INIT_LIST_HEAD(&cache->used);
	INIT_LIST_HEAD(&cache->free);

	for (i = 0; i < TX_POLICY_CACHE_SIZE; ++i)
		list_add(&cache->cache[i].link, &cache->free);
}

void tx_policy_deinit(struct bes2600_common *hw_priv)
{
	bes2600_dbg(BES2600_DBG_TXRX_OPT, "tx_policy_deinit\n\r");
}

static int tx_policy_get(struct bes2600_common *hw_priv,
		  struct ieee80211_tx_rate *rates,
		  size_t count, bool *renew)
{
	int idx;
	struct tx_policy_cache *cache = &hw_priv->tx_policy_cache;
	struct tx_policy wanted;

	tx_policy_build(hw_priv, &wanted, rates, count);

	spin_lock_bh(&cache->lock);
	if (WARN_ON_ONCE(list_empty(&cache->free))) {
		spin_unlock_bh(&cache->lock);
		return BES2600_INVALID_RATE_ID;
	}
	idx = tx_policy_find(cache, &wanted);
	if (idx >= 0) {
		bes2600_dbg(BES2600_DBG_TX_POLICY, "[TX policy] Used TX policy: %d\n",
					idx);
		*renew = false;
	} else {
		struct tx_policy_cache_entry *entry;
		*renew = true;
		/* If policy is not found create a new one
		 * using the oldest entry in "free" list */
		entry = list_entry(cache->free.prev,
			struct tx_policy_cache_entry, link);
		entry->policy = wanted;
		idx = entry - cache->cache;
		bes2600_dbg(BES2600_DBG_TX_POLICY, "[TX policy] New TX policy: %d\n",
					idx);
		tx_policy_dump(&entry->policy);
	}
	tx_policy_use(cache, &cache->cache[idx]);
	if (unlikely(list_empty(&cache->free))) {
		/* Lock TX queues. */
		bes2600_tx_queues_lock(hw_priv);
	}
	spin_unlock_bh(&cache->lock);
	return idx;
}

static void tx_policy_put(struct bes2600_common *hw_priv, int idx)
{
	int usage, locked;
	struct tx_policy_cache *cache = &hw_priv->tx_policy_cache;

	spin_lock_bh(&cache->lock);
	locked = list_empty(&cache->free);
	usage = tx_policy_release(cache, &cache->cache[idx]);
	if (unlikely(locked) && !usage) {
		/* Unlock TX queues. */
		bes2600_tx_queues_unlock(hw_priv);
	}
	spin_unlock_bh(&cache->lock);
}

/*
bool tx_policy_cache_full(struct bes2600_common *hw_priv)
{
	bool ret;
	struct tx_policy_cache *cache = &hw_priv->tx_policy_cache;
	spin_lock_bh(&cache->lock);
	ret = list_empty(&cache->free);
	spin_unlock_bh(&cache->lock);
	return ret;
}
*/

static int tx_policy_upload(struct bes2600_common *hw_priv)
{
	struct tx_policy_cache *cache = &hw_priv->tx_policy_cache;
	int i;
	struct wsm_set_tx_rate_retry_policy arg = {
		.hdr = {
			.numTxRatePolicies = 0,
		}
	};
	int if_id = 0;
	spin_lock_bh(&cache->lock);

	/* Upload only modified entries. */
	for (i = 0; i < TX_POLICY_CACHE_SIZE; ++i) {
		struct tx_policy *src = &cache->cache[i].policy;
		if (src->retry_count && !src->uploaded) {
			struct wsm_set_tx_rate_retry_policy_policy *dst =
				&arg.tbl[arg.hdr.numTxRatePolicies];
			dst->policyIndex = i;
			dst->shortRetryCount =
				hw_priv->short_frame_max_tx_count;
			dst->longRetryCount = hw_priv->long_frame_max_tx_count;

			/* BIT(2) - Terminate retries when Tx rate retry policy
			 *          finishes.
			 * BIT(3) - Count initial frame transmission as part of
			 *          rate retry counting but not as a retry
			 *          attempt */
			dst->policyFlags = BIT(2) | BIT(3);

			memcpy(dst->rateCountIndices, src->tbl,
					sizeof(dst->rateCountIndices));
			src->uploaded = 1;
			++arg.hdr.numTxRatePolicies;
		}
	}
	spin_unlock_bh(&cache->lock);
	//bes2600_debug_tx_cache_miss(hw_priv);
	bes2600_dbg(BES2600_DBG_TX_POLICY, "[TX policy] Upload %d policies\n",
				arg.hdr.numTxRatePolicies);
	/*TODO: COMBO*/
	return wsm_set_tx_rate_retry_policy(hw_priv, &arg, if_id);
}

void tx_policy_upload_work(struct work_struct *work)
{
	struct bes2600_common *hw_priv =
		container_of(work, struct bes2600_common, tx_policy_upload_work);

	bes2600_dbg(BES2600_DBG_TX_POLICY, "[TX] TX policy upload.\n");
	WARN_ON(tx_policy_upload(hw_priv));

	wsm_unlock_tx(hw_priv);
	bes2600_tx_queues_unlock(hw_priv);
}

/* ******************************************************************** */
/* bes2600 TX implementation						*/

struct bes2600_txinfo {
	struct sk_buff *skb;
	unsigned queue;
	struct ieee80211_tx_info *tx_info;
	const struct ieee80211_rate *rate;
	struct ieee80211_hdr *hdr;
	size_t hdrlen;
	const u8 *da;
	struct bes2600_sta_priv *sta_priv;
	struct ieee80211_sta *sta;
	struct bes2600_txpriv txpriv;
};

u32 bes2600_rate_mask_to_wsm(struct bes2600_common *hw_priv, u32 rates)
{
	u32 ret = 0;
	int i;
	struct ieee80211_rate * bitrates =
		hw_priv->hw->wiphy->bands[hw_priv->channel->band]->bitrates;
	for (i = 0; i < 32; ++i) {
		if (rates & BIT(i))
			ret |= BIT(bitrates[i].hw_value);
	}
	return ret;
}

static const struct ieee80211_rate *
bes2600_get_tx_rate(const struct bes2600_common *hw_priv,
		   const struct ieee80211_tx_rate *rate)
{
	if (rate->idx < 0)
		return NULL;
	if (rate->flags & IEEE80211_TX_RC_MCS)
		return &hw_priv->mcs_rates[rate->idx];
	return &hw_priv->hw->wiphy->bands[hw_priv->channel->band]->
		bitrates[rate->idx];
}

static int
bes2600_tx_h_calc_link_ids(struct bes2600_vif *priv,
			  struct bes2600_txinfo *t)
{
#ifndef P2P_MULTIVIF
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
	if ((t->tx_info->flags & IEEE80211_TX_CTL_TX_OFFCHAN) ||
			(hw_priv->roc_if_id == priv->if_id))
		t->txpriv.offchannel_if_id = 2;
	else
		t->txpriv.offchannel_if_id = 0;
#endif

	if (likely(t->sta && t->sta_priv->link_id))
		t->txpriv.raw_link_id =
				t->txpriv.link_id =
				t->sta_priv->link_id;
	else if (priv->mode != NL80211_IFTYPE_AP)
		t->txpriv.raw_link_id =
				t->txpriv.link_id = 0;
	else if (is_multicast_ether_addr(t->da)) {
		if (priv->enable_beacon) {
			t->txpriv.raw_link_id = 0;
			t->txpriv.link_id = priv->link_id_after_dtim;
		} else {
			t->txpriv.raw_link_id = 0;
			t->txpriv.link_id = 0;
		}
	} else {
		t->txpriv.link_id =
			bes2600_find_link_id(priv, t->da);
		/* Do not assign valid link id for deauth/disassoc frame being
		transmitted to an unassociated STA */
		if (!(t->txpriv.link_id) &&
			(ieee80211_is_deauth(t->hdr->frame_control) ||
			ieee80211_is_disassoc(t->hdr->frame_control))) {
					t->txpriv.link_id = 0;
		} else {
			if (!t->txpriv.link_id)
				t->txpriv.link_id = bes2600_alloc_link_id(priv, t->da);
			if (!t->txpriv.link_id) {
				wiphy_err(priv->hw->wiphy,
					"%s: No more link IDs available.\n",
					__func__);
				return -ENOENT;
			}
		}
		t->txpriv.raw_link_id = t->txpriv.link_id;
	}
	if (t->txpriv.raw_link_id)
		priv->link_id_db[t->txpriv.raw_link_id - 1].timestamp =
				jiffies;

#if defined(CONFIG_BES2600_USE_STE_EXTENSIONS)
	if (t->tx_info->sta &&
			(t->tx_info->sta->uapsd_queues & BIT(t->queue)))
		t->txpriv.link_id = priv->link_id_uapsd;
#endif /* CONFIG_BES2600_USE_STE_EXTENSIONS */
	return 0;
}

static void
bes2600_tx_h_pm(struct bes2600_vif *priv,
	       struct bes2600_txinfo *t)
{
	if (unlikely(ieee80211_is_auth(t->hdr->frame_control))) {
		u32 mask = ~BIT(t->txpriv.raw_link_id);
		spin_lock_bh(&priv->ps_state_lock);
		priv->sta_asleep_mask &= mask;
		priv->pspoll_mask &= mask;
		spin_unlock_bh(&priv->ps_state_lock);
	}
}

static void
bes2600_tx_h_calc_tid(struct bes2600_vif *priv,
		     struct bes2600_txinfo *t)
{
	if (ieee80211_is_data_qos(t->hdr->frame_control)) {
		u8 *qos = ieee80211_get_qos_ctl(t->hdr);
		t->txpriv.tid = qos[0] & IEEE80211_QOS_CTL_TID_MASK;
	} else if (ieee80211_is_data(t->hdr->frame_control)) {
		t->txpriv.tid = 0;
	}
}

#ifdef CONFIG_BES2600_WAPI_SUPPORT
static void bes2600_tx_wapi_shrink_iv_space(struct bes2600_vif *priv,
		     struct bes2600_txinfo *t)
{
	int hdrlen;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) t->skb->data;
	u8 *pos, iv_len = t->tx_info->control.hw_key->iv_len;

	if (!t->tx_info->control.hw_key ||
		!ieee80211_has_protected(t->hdr->frame_control))
		return;

	hdrlen = ieee80211_hdrlen(t->hdr->frame_control);

	if(ieee80211_is_mgmt(t->hdr->frame_control) &&
		t->tx_info->control.hw_key->cipher == WLAN_CIPHER_SUITE_SMS4 &&
		(t->tx_info->control.hw_key->flags & IEEE80211_KEY_FLAG_PUT_IV_SPACE)) {
		pos = t->skb->data;
		memmove(pos + iv_len, pos, hdrlen);
		skb_pull(t->skb, iv_len);
		hdr->frame_control &= ~cpu_to_le16(IEEE80211_FCTL_PROTECTED);
		t->tx_info->control.hw_key = NULL;
		t->hdr = (struct ieee80211_hdr *)t->skb->data;
	}
}
#endif

#if 0
/* IV/ICV injection. */
/* TODO: Quite unoptimal. It's better co modify mac80211
 * to reserve space for IV */
static int
bes2600_tx_h_crypt(struct bes2600_vif *priv,
		  struct bes2600_txinfo *t)
{
	size_t iv_len;
	size_t icv_len;
	u8 *icv;
	u8 *newhdr;

	if (!t->tx_info->control.hw_key ||
	    !(t->hdr->frame_control &
	     __cpu_to_le32(IEEE80211_FCTL_PROTECTED)))
		return 0;

	iv_len = t->tx_info->control.hw_key->iv_len;
	icv_len = t->tx_info->control.hw_key->icv_len;

	if (t->tx_info->control.hw_key->cipher == WLAN_CIPHER_SUITE_TKIP)
		icv_len += 8; /* MIC */

	if ((skb_headroom(t->skb) + skb_tailroom(t->skb) <
			 iv_len + icv_len + WSM_TX_EXTRA_HEADROOM) ||
			(skb_headroom(t->skb) <
			 iv_len + WSM_TX_EXTRA_HEADROOM)) {
		wiphy_err(priv->hw->wiphy,
			"Bug: no space allocated for crypto headers.\n"
			"headroom: %d, tailroom: %d, "
			"req_headroom: %d, req_tailroom: %d\n"
			"Please fix it in bes2600_get_skb().\n",
			skb_headroom(t->skb), skb_tailroom(t->skb),
			iv_len + WSM_TX_EXTRA_HEADROOM, icv_len);
		return -ENOMEM;
	} else if (skb_tailroom(t->skb) < icv_len) {
		size_t offset = icv_len - skb_tailroom(t->skb);
		u8 *p;
		wiphy_warn(priv->hw->wiphy,
			"Slowpath: tailroom is not big enough. "
			"Req: %d, got: %d.\n",
			icv_len, skb_tailroom(t->skb));

		p = skb_push(t->skb, offset);
		memmove(p, &p[offset], t->skb->len - offset);
		skb_trim(t->skb, t->skb->len - offset);
	}

	newhdr = skb_push(t->skb, iv_len);
	memmove(newhdr, newhdr + iv_len, t->hdrlen);
	t->hdr = (struct ieee80211_hdr *) newhdr;
	t->hdrlen += iv_len;
	icv = skb_put(t->skb, icv_len);

	return 0;
}
#else
static int
bes2600_tx_h_crypt(struct bes2600_vif *priv,
		  struct bes2600_txinfo *t)
{
	if (!t->tx_info->control.hw_key ||
		!ieee80211_has_protected(t->hdr->frame_control) ||
		(ieee80211_is_mgmt(t->hdr->frame_control) &&
		t->tx_info->control.hw_key->cipher == WLAN_CIPHER_SUITE_SMS4))
		return 0;

	t->hdrlen += t->tx_info->control.hw_key->iv_len;
	skb_put(t->skb, t->tx_info->control.hw_key->icv_len);

	if (t->tx_info->control.hw_key->cipher == WLAN_CIPHER_SUITE_TKIP)
		skb_put(t->skb, 8); /* MIC space */

	return 0;
}
#endif

static int
bes2600_tx_h_align(struct bes2600_vif *priv,
		  struct bes2600_txinfo *t,
		  u8 *flags)
{
	size_t offset = (size_t)t->skb->data & 3;

	if (!offset)
		return 0;

	if (offset & 1) {
		wiphy_err(priv->hw->wiphy,
			"Bug: attempt to transmit a frame "
			"with wrong alignment: %ld\n",
			offset);
		return -EINVAL;
	}

	if (skb_headroom(t->skb) < offset) {
		wiphy_err(priv->hw->wiphy,
			"Bug: no space allocated "
			"for DMA alignment.\n"
			"headroom: %d\n",
			skb_headroom(t->skb));
		return -ENOMEM;
	}
	skb_push(t->skb, offset);
	t->hdrlen += offset;
	t->txpriv.offset += offset;
	*flags |= WSM_TX_2BYTES_SHIFT;
	bes2600_debug_tx_align(priv);
	return 0;
}

static int
bes2600_tx_h_action(struct bes2600_vif *priv,
		   struct bes2600_txinfo *t)
{
	struct ieee80211_mgmt *mgmt =
		(struct ieee80211_mgmt *)t->hdr;

	if (ieee80211_is_action(t->hdr->frame_control) &&
			mgmt->u.action.category == WLAN_CATEGORY_BACK)
		return 1;
	else
		return 0;
}

/* Add WSM header */
static struct wsm_tx *
bes2600_tx_h_wsm(struct bes2600_vif *priv,
		struct bes2600_txinfo *t)
{
	struct wsm_tx *wsm;

	if (skb_headroom(t->skb) < sizeof(struct wsm_tx)) {
		wiphy_err(priv->hw->wiphy,
			"Bug: no space allocated "
			"for WSM header.\n"
			"headroom: %d\n",
			skb_headroom(t->skb));
		return NULL;
	}

	wsm = (struct wsm_tx *)skb_push(t->skb, sizeof(struct wsm_tx));
	t->txpriv.offset += sizeof(struct wsm_tx);
	memset(wsm, 0, sizeof(*wsm));
	wsm->hdr.len = __cpu_to_le16(t->skb->len);
	wsm->hdr.id = __cpu_to_le16(0x0004);
	wsm->queueId =
		(t->txpriv.raw_link_id << 2) | wsm_queue_id_to_wsm(t->queue);
	return wsm;
}

/* BT Coex specific handling */
static void
bes2600_tx_h_bt(struct bes2600_vif *priv,
	       struct bes2600_txinfo *t,
	       struct wsm_tx *wsm)
{
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);

	u8 priority = 0;

	if (!hw_priv->is_BT_Present)
		return;

	if (unlikely(ieee80211_is_nullfunc(t->hdr->frame_control)))
		priority = WSM_EPTA_PRIORITY_MGT;
	else if (ieee80211_is_data(t->hdr->frame_control)) {
		/* Skip LLC SNAP header (+6) */
		u8 *payload = &t->skb->data[t->hdrlen];
		u16 *ethertype = (u16 *) &payload[6];
		if (unlikely(*ethertype == __be16_to_cpu(ETH_P_PAE)))
			priority = WSM_EPTA_PRIORITY_EAPOL;
	} else if (unlikely(ieee80211_is_assoc_req(t->hdr->frame_control) ||
		ieee80211_is_reassoc_req(t->hdr->frame_control))) {
		struct ieee80211_mgmt *mgt_frame =
				(struct ieee80211_mgmt *)t->hdr;

		if (mgt_frame->u.assoc_req.listen_interval <
						priv->listen_interval) {
			bes2600_dbg(BES2600_DBG_TX_POLICY,
				"Modified Listen Interval to %d from %d\n",
				priv->listen_interval,
				mgt_frame->u.assoc_req.listen_interval);
			/* Replace listen interval derieved from
			 * the one read from SDD */
			mgt_frame->u.assoc_req.listen_interval =
				priv->listen_interval;
		}
	}

	if (likely(!priority)) {
		if (ieee80211_is_action(t->hdr->frame_control))
			priority = WSM_EPTA_PRIORITY_ACTION;
		else if (ieee80211_is_mgmt(t->hdr->frame_control))
			priority = WSM_EPTA_PRIORITY_MGT;
		else if (wsm->queueId == WSM_QUEUE_VOICE)
			priority = WSM_EPTA_PRIORITY_VOICE;
		else if (wsm->queueId == WSM_QUEUE_VIDEO)
			priority = WSM_EPTA_PRIORITY_VIDEO;
		else
			priority = WSM_EPTA_PRIORITY_DATA;
	}

	bes2600_dbg(BES2600_DBG_TXRX, "[TX] EPTA priority %d.\n",
		priority);

	wsm->flags |= priority << 1;
}

static int
bes2600_tx_h_rate_policy(struct bes2600_common *hw_priv,
			struct bes2600_txinfo *t,
			struct wsm_tx *wsm)
{
	bool tx_policy_renew = false;
	struct bes2600_vif *priv =
				cw12xx_get_vif_from_ieee80211(t->tx_info->control.vif);

	t->txpriv.rate_id = tx_policy_get(hw_priv,
		t->tx_info->control.rates, IEEE80211_TX_MAX_RATES,
		&tx_policy_renew);
	if (t->txpriv.rate_id == BES2600_INVALID_RATE_ID)
		return -EFAULT;

	wsm->flags |= t->txpriv.rate_id << 4;

	t->rate = bes2600_get_tx_rate(hw_priv,
		&t->tx_info->control.rates[0]),
	wsm->maxTxRate = t->rate->hw_value;
	priv->hw_value = wsm->maxTxRate;
	if (t->rate->flags & IEEE80211_TX_RC_MCS) {
		if (priv->association_mode.greenfieldMode)
			wsm->htTxParameters |=
				__cpu_to_le32(WSM_HT_TX_GREENFIELD);
		else
			wsm->htTxParameters |=
				__cpu_to_le32(WSM_HT_TX_MIXED);
	}

	if (tx_policy_renew) {
		bes2600_dbg(BES2600_DBG_TX_POLICY, "[TX] TX policy renew.\n");
		/* It's not so optimal to stop TX queues every now and then.
		 * Maybe it's better to reimplement task scheduling with
		 * a counter. */
		/* bes2600_tx_queues_lock(priv); */
		/* Definetly better. TODO. */
		wsm_lock_tx_async(hw_priv);
		bes2600_tx_queues_lock(hw_priv);
		if (queue_work(hw_priv->workqueue,
				&hw_priv->tx_policy_upload_work) <= 0) {
			bes2600_tx_queues_unlock(hw_priv);
			wsm_unlock_tx(hw_priv);
		}
	}
	return 0;
}

static bool
bes2600_tx_h_pm_state(struct bes2600_vif *priv,
		     struct bes2600_txinfo *t)
{
	int was_buffered = 1;

	if (t->txpriv.link_id == priv->link_id_after_dtim &&
			!priv->buffered_multicasts) {
		priv->buffered_multicasts = true;
		if (priv->sta_asleep_mask)
			queue_work(priv->hw_priv->workqueue,
				&priv->multicast_start_work);
	}

	if (t->txpriv.raw_link_id && t->txpriv.tid < BES2600_MAX_TID)
		was_buffered = priv->link_id_db[t->txpriv.raw_link_id - 1]
				.buffered[t->txpriv.tid]++;

	return !was_buffered;
}

static void
bes2600_tx_h_ba_stat(struct bes2600_vif *priv,
		    struct bes2600_txinfo *t)
{
	struct bes2600_common *hw_priv = priv->hw_priv;

	if (priv->join_status != BES2600_JOIN_STATUS_STA)
		return;
	if (!bes2600_is_ht(&hw_priv->ht_info))
		return;
	if (!priv->setbssparams_done)
		return;
	if (!ieee80211_is_data(t->hdr->frame_control))
		return;

	spin_lock_bh(&hw_priv->ba_lock);
	hw_priv->ba_acc += t->skb->len - t->hdrlen;
	if (!(hw_priv->ba_cnt_rx || hw_priv->ba_cnt)) {
		mod_timer(&hw_priv->ba_timer,
			jiffies + BES2600_BLOCK_ACK_INTERVAL);
	}
	hw_priv->ba_cnt++;
	spin_unlock_bh(&hw_priv->ba_lock);
}

static int
bes2600_tx_h_skb_pad(struct bes2600_common *priv,
		    struct wsm_tx *wsm,
		    struct sk_buff *skb)
{
	size_t len = __le16_to_cpu(wsm->hdr.len);
	size_t padded_len = priv->sbus_ops->align_size(priv->sbus_priv, len);

	if (WARN_ON(skb_padto(skb, padded_len) != 0)) {
		return -EINVAL;
	}
	return 0;
}

#ifdef CONFIG_BES2600_KEEP_ALIVE
extern struct ip_alive_cfg iac[];

static uint16_t find_idx_by_matched_paras(uint8_t proto, uint16_t src_port, uint16_t dst_port,
                                         uint32_t src_ip, uint32_t dst_ip)
{
	uint16_t idx;

	for (idx = 0; idx < NUM_IP_FRAMES; idx++) {
		if (iac[idx].bd.idx_used &&
		    (proto == iac[idx].bd.proto) &&
		    (src_port == iac[idx].bd.src_port) &&
		    (dst_port == iac[idx].bd.dest_port)&&
		    (src_ip == iac[idx].bd.src_ip) &&
		    (dst_ip == iac[idx].bd.dest_ip)) {
			break;
		}
	}

	return idx;
}

static int extract_ip_headers_info(struct bes2600_common *hw_priv, struct bes2600_vif *priv, uint8_t *iphdr)
{
	uint16_t _v_hl, _proto, src_port, dst_port, idx, tcp_bd_len;
	uint8_t offset;
	uint32_t src_ip, dst_ip;

	bes2600_dbg_dump(BES2600_DBG_TEST_MODE, "iphdr:", iphdr, 64);

	/* Frame Control Flags, bit6: 1 for protected frame and 0 for non-protected frame; */
	((iphdr[1] >> 6) & 0x1) ? (offset = 40) : (offset = 32);

	_v_hl = iphdr[offset + 2];
	_proto = iphdr[offset + 11];

	/*
	 * _v_hl == 0x45 for ip packet;
	 * _proto == 6 for tcp protocol and 17 for udp protocol;
	 */
	if (_v_hl == 0x45) {
		if (_proto == TCP_PROTO) {
			/* obtain destination's listening port. */
			src_port = (iphdr[offset+22]<<8) + iphdr[offset+23];
			dst_port = (iphdr[offset+24]<<8) + iphdr[offset+25];
			src_ip = (iphdr[offset+14]<<24) + (iphdr[offset+15]<<16) + (iphdr[offset+16]<<8) + iphdr[offset+17];
			dst_ip = (iphdr[offset+18]<<24) + (iphdr[offset+19]<<16) + (iphdr[offset+20]<<8) + iphdr[offset+21];
			idx = find_idx_by_matched_paras(1, src_port, dst_port, src_ip, dst_ip);
			/* if port matches */
			if (idx < NUM_IP_FRAMES) {
				iac[idx].iphd._len = (iphdr[offset+4]<<8) + iphdr[offset+5];
				iac[idx].iphd._proto = _proto;
				iac[idx].tcphd._hdrlen_rsvd_flags = (iphdr[offset+34]<<8) + iphdr[offset+35];
				iac[idx].tcphd.seqno = (iphdr[offset+26]<<24) + (iphdr[offset+27]<<16) + (iphdr[offset+28]<<8) + iphdr[offset+29];
				iac[idx].tcphd.ackno = (iphdr[offset+30]<<24) + (iphdr[offset+31]<<16) + (iphdr[offset+32]<<8) + iphdr[offset+33];
				tcp_bd_len = iac[idx].iphd._len - sizeof(struct ip_header) - sizeof(struct tcp_header);
				iac[idx].bd.next_seqno = iac[idx].tcphd.seqno + tcp_bd_len;
				memcpy(iac[idx].bd.dest_mac, ((struct ieee80211_hdr *)iphdr)->addr3, 6);

				bes2600_dbg(BES2600_DBG_TEST_MODE, "src-ip:%x dest-ip:%x src-port:%d dest-port:%d\n",
				                   iac[idx].iphd.src,
				                   iac[idx].iphd.dest,
				                   iac[idx].tcphd.src,
				                   iac[idx].tcphd.dest);
				bes2600_dbg(BES2600_DBG_TEST_MODE, "seqno:%u ackno:%u\n", iac[idx].tcphd.seqno, iac[idx].tcphd.ackno);
			}
		}
		else if (_proto == UDP_PROTO) {
			/* obtain destination's listening port. */
			src_port = (iphdr[offset+22]<<8) + iphdr[offset+23];
			dst_port = (iphdr[offset+24]<<8) + iphdr[offset+25];
			src_ip = (iphdr[offset+14]<<24) + (iphdr[offset+15]<<16) + (iphdr[offset+16]<<8) + iphdr[offset+17];
			dst_ip = (iphdr[offset+18]<<24) + (iphdr[offset+19]<<16) + (iphdr[offset+20]<<8) + iphdr[offset+21];
			idx = find_idx_by_matched_paras(0, src_port, dst_port, src_ip, dst_ip);
			/* if port matches */
			if (idx < NUM_IP_FRAMES) {
				iac[idx].iphd._len = (iphdr[offset+4]<<8) + iphdr[offset+5];
				iac[idx].iphd._proto = _proto;
				memcpy(iac[idx].bd.dest_mac, ((struct ieee80211_hdr *)iphdr)->addr3, 6);
			}
		}
	}

	return 0;
}
#endif /* CONFIG_BES2600_KEEP_ALIVE */

/* ******************************************************************** */

void bes2600_tx(struct ieee80211_hw *dev,
			struct ieee80211_tx_control *control,
			struct sk_buff *skb)
{
	struct bes2600_common *hw_priv = dev->priv;
	struct bes2600_txinfo t = {
		.skb = skb,
		.queue = skb_get_queue_mapping(skb),
		.tx_info = IEEE80211_SKB_CB(skb),
		.hdr = (struct ieee80211_hdr *)skb->data,
		.txpriv.tid = BES2600_MAX_TID,
		.txpriv.rate_id = BES2600_INVALID_RATE_ID,
#ifdef P2P_MULTIVIF
		.txpriv.raw_if_id = 0,
#endif
	};
	struct ieee80211_sta *sta;
	struct wsm_tx *wsm;
	bool tid_update = 0;
	u8 flags = 0;
	int ret;
	struct bes2600_vif *priv;
	struct ieee80211_hdr *frame = (struct ieee80211_hdr *)skb->data;
        struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)skb->data;

	if (!skb->data)
		BUG_ON(1);

	if (!(t.tx_info->control.vif)) {
	        goto drop;
	}
	priv = cw12xx_get_vif_from_ieee80211(t.tx_info->control.vif);
	if (!priv)
		goto drop;

	if (atomic_read(&priv->enabled) == 0)
		goto drop;

	/* wake up device if device is in low power mode */
	bes2600_pwr_set_busy_event_with_timeout_async(
		hw_priv, BES_PWR_LOCK_ON_TX, BES_PWR_EVENT_TX_TIMEOUT);

#ifdef CONFIG_BES2600_KEEP_ALIVE
	/* extract ip & tcp header's information; */
	extract_ip_headers_info(hw_priv, priv, skb->data);
#endif

#ifdef CONFIG_BES2600_TESTMODE
	spin_lock_bh(&hw_priv->tsm_lock);
	if (hw_priv->start_stop_tsm.start) {
		if (hw_priv->tsm_info.ac == t.queue)
			hw_priv->tsm_stats.txed_msdu_count++;
	}
	spin_unlock_bh(&hw_priv->tsm_lock);
#endif /*CONFIG_BES2600_TESTMODE*/

	if ((ieee80211_is_action(frame->frame_control))
			&& (mgmt->u.action.category == WLAN_CATEGORY_PUBLIC)) {
		u8 *action = (u8*)&mgmt->u.action.category;
		bes2600_check_go_neg_conf_success(hw_priv, action);
		bes2600_check_prov_desc_req(hw_priv, action);
	}

	t.txpriv.if_id = priv->if_id;
	t.hdrlen = ieee80211_hdrlen(t.hdr->frame_control);
	t.da = ieee80211_get_DA(t.hdr);
	if (control) {
		t.sta = control->sta;
		t.sta_priv = (struct bes2600_sta_priv *)&t.sta->drv_priv;
	}

	if (WARN_ON(t.queue >= 4))
		goto drop;

	/*
		should not drop packets here, it may cause tx rate decreasing
		tx flow control will be handled in bes2600_queue_put
	*/
#if 0
	spin_lock_bh(&hw_priv->tx_queue[t.queue].lock);

	if ((priv->if_id == 0) &&
		(hw_priv->tx_queue[t.queue].num_queued_vif[0] >=
			hw_priv->vif0_throttle)) {
		spin_unlock_bh(&hw_priv->tx_queue[t.queue].lock);
		goto drop;
	} else if ((priv->if_id == 1) &&
		(hw_priv->tx_queue[t.queue].num_queued_vif[1] >=
			hw_priv->vif1_throttle)) {
		spin_unlock_bh(&hw_priv->tx_queue[t.queue].lock);
		goto drop;
	}

	spin_unlock_bh(&hw_priv->tx_queue[t.queue].lock);
#endif

	ret = bes2600_tx_h_calc_link_ids(priv, &t);
	if (ret)
		goto drop;

	bes2600_dbg(BES2600_DBG_TXRX, "[TX] TX %d bytes (if_id: %d,"
			" queue: %d, link_id: %d (%d)).\n",
			skb->len, priv->if_id, t.queue, t.txpriv.link_id,
			t.txpriv.raw_link_id);

	bes2600_tx_h_pm(priv, &t);
	bes2600_tx_h_calc_tid(priv, &t);
#ifdef CONFIG_BES2600_WAPI_SUPPORT
	bes2600_tx_wapi_shrink_iv_space(priv, &t);
#endif
	ret = bes2600_tx_h_crypt(priv, &t);
	if (ret)
		goto drop;
	ret = bes2600_tx_h_align(priv, &t, &flags);
	if (ret)
		goto drop;
	ret = bes2600_tx_h_action(priv, &t);
	if (ret)
		goto drop;
	wsm = bes2600_tx_h_wsm(priv, &t);
	if (!wsm) {
		ret = -ENOMEM;
		goto drop;
	}
#ifdef CONFIG_BES2600_TESTMODE
	flags |= WSM_TX_FLAG_EXPIRY_TIME;
#endif /*CONFIG_BES2600_TESTMODE*/
	wsm->flags |= flags;
	bes2600_tx_h_bt(priv, &t, wsm);
	ret = bes2600_tx_h_rate_policy(hw_priv, &t, wsm);
	if (ret)
		goto drop;

	ret = bes2600_tx_h_skb_pad(hw_priv, wsm, skb);
	if (ret)
		goto drop;
	rcu_read_lock();
	sta = rcu_dereference(t.sta);

	bes2600_tx_h_ba_stat(priv, &t);

	spin_lock_bh(&priv->ps_state_lock);
	{
		tid_update = bes2600_tx_h_pm_state(priv, &t);
		BUG_ON(bes2600_queue_put(&hw_priv->tx_queue[t.queue],
				t.skb, &t.txpriv));

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0))
		if (skb->sk)
			sk_pacing_shift_update(skb->sk, 7);
#endif

		bes2600_dbg(BES2600_DBG_ROC, "QPUT %x, %pM, if_id - %d\n",
			t.hdr->frame_control, t.da, priv->if_id);
	}
	spin_unlock_bh(&priv->ps_state_lock);

#if defined(CONFIG_BES2600_USE_STE_EXTENSIONS)
	if (tid_update && sta)
		ieee80211_sta_set_buffered(sta,
				t.txpriv.tid, true);
#endif /* CONFIG_BES2600_USE_STE_EXTENSIONS */

	rcu_read_unlock();

	bes2600_bh_wakeup(hw_priv);

	return;

drop:
	bes2600_skb_dtor(hw_priv, skb, &t.txpriv);
	return;
}

/* ******************************************************************** */

static int bes2600_handle_pspoll(struct bes2600_vif *priv,
				struct sk_buff *skb)
{
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
	struct ieee80211_sta *sta;
	struct ieee80211_pspoll *pspoll =
		(struct ieee80211_pspoll *) skb->data;
	int link_id = 0;
	u32 pspoll_mask = 0;
	int drop = 1;
	int i;

	if (priv->join_status != BES2600_JOIN_STATUS_AP)
		goto done;
	if (memcmp(priv->vif->addr, pspoll->bssid, ETH_ALEN))
		goto done;

	rcu_read_lock();
	sta = ieee80211_find_sta(priv->vif, pspoll->ta);
	if (sta) {
		struct bes2600_sta_priv *sta_priv;
		sta_priv = (struct bes2600_sta_priv *)&sta->drv_priv;
		link_id = sta_priv->link_id;
		pspoll_mask = BIT(sta_priv->link_id);
	}
	rcu_read_unlock();
	if (!link_id)
		goto done;

	priv->pspoll_mask |= pspoll_mask;
	drop = 0;

	/* Do not report pspols if data for given link id is
	 * queued already. */
	for (i = 0; i < 4; ++i) {
		if (bes2600_queue_get_num_queued(priv,
				&hw_priv->tx_queue[i],
				pspoll_mask)) {
			bes2600_bh_wakeup(hw_priv);
			drop = 1;
			break;
		}
	}
	bes2600_info(BES2600_DBG_TXRX, "[RX] PSPOLL: %s\n", drop ? "local" : "fwd");
done:
	return drop;
}

/* ******************************************************************** */

void bes2600_tx_confirm_cb(struct bes2600_common *hw_priv,
			  struct wsm_tx_confirm *arg)
{
	u8 queue_id = bes2600_queue_get_queue_id(arg->packetID);
	struct bes2600_queue *queue = &hw_priv->tx_queue[queue_id];
	struct sk_buff *skb;
	const struct bes2600_txpriv *txpriv;
	struct bes2600_vif *priv;
#ifdef CONFIG_BES2600_TESTMODE
	u16 pkt_delay;
#endif

	bes2600_dbg(BES2600_DBG_TXRX, "[TX] TX confirm: %d, %d.\n",
		arg->status, arg->ackFailures);

	if (unlikely(bes2600_itp_tx_running(hw_priv)))
		return;

	priv = cw12xx_hwpriv_to_vifpriv(hw_priv, arg->if_id);
	if (unlikely(!priv))
		return;
	if (unlikely(priv->mode == NL80211_IFTYPE_UNSPECIFIED)) {
		/* STA is stopped. */
		spin_unlock(&priv->vif_lock);
		return;
	}

	if (WARN_ON(queue_id >= 4)) {
		spin_unlock(&priv->vif_lock);
		return;
	}

	if (arg->status)
		bes2600_dbg(BES2600_DBG_TXRX, "TX failed: %d.\n",
				arg->status);

#ifdef CONFIG_BES2600_TESTMODE
	spin_lock_bh(&hw_priv->tsm_lock);
	if ((arg->status == WSM_STATUS_RETRY_EXCEEDED) ||
	    (arg->status == WSM_STATUS_TX_LIFETIME_EXCEEDED)) {
		hw_priv->tsm_stats.msdu_discarded_count++;
	} else if ((hw_priv->start_stop_tsm.start) &&
		(arg->status == WSM_STATUS_SUCCESS)) {
		if (queue_id == hw_priv->tsm_info.ac) {
			struct timeval tmval;
			do_gettimeofday(&tmval);
			pkt_delay = hw_priv->start_stop_tsm.packetization_delay;
			if (hw_priv->tsm_info.sta_roamed &&
			    !hw_priv->tsm_info.use_rx_roaming) {
				hw_priv->tsm_info.roam_delay = tmval.tv_usec -
				hw_priv->tsm_info.txconf_timestamp_vo;
				if (hw_priv->tsm_info.roam_delay > pkt_delay)
					hw_priv->tsm_info.roam_delay -= pkt_delay;
				bes2600_info(BES2600_DBG_TEST_MODE, "[TX] txConf"
				"Roaming: roam_delay = %u\n",
				hw_priv->tsm_info.roam_delay);
				hw_priv->tsm_info.sta_roamed = 0;
			}
			hw_priv->tsm_info.txconf_timestamp_vo = tmval.tv_usec;
		}
	}
	spin_unlock_bh(&hw_priv->tsm_lock);
#endif /*CONFIG_BES2600_TESTMODE*/
	if ((arg->status == WSM_REQUEUE) &&
	    (arg->flags & WSM_TX_STATUS_REQUEUE)) {
		/* "Requeue" means "implicit suspend" */
		struct wsm_suspend_resume suspend = {
			.link_id = arg->link_id,
			.stop = 1,
			.multicast = !arg->link_id,
			.if_id = arg->if_id,
		};
		bes2600_suspend_resume(priv, &suspend);
		wiphy_warn(priv->hw->wiphy, "Requeue for link_id %d (try %d)."
			" STAs asleep: 0x%.8X\n",
			arg->link_id,
			bes2600_queue_get_generation(arg->packetID) + 1,
			priv->sta_asleep_mask);
#ifdef CONFIG_BES2600_TESTMODE
		WARN_ON(bes2600_queue_requeue(hw_priv, queue,
				arg->packetID, true));
#else
		WARN_ON(bes2600_queue_requeue(queue,
				arg->packetID, true));
#endif
		spin_lock_bh(&priv->ps_state_lock);
		if (!arg->link_id) {
			priv->buffered_multicasts = true;
			if (priv->sta_asleep_mask) {
				queue_work(hw_priv->workqueue,
					&priv->multicast_start_work);
			}
		}
		spin_unlock_bh(&priv->ps_state_lock);
		spin_unlock(&priv->vif_lock);
	} else if (!(bes2600_queue_get_skb(
			queue, arg->packetID, &skb, &txpriv))) {
		struct ieee80211_tx_info *tx = IEEE80211_SKB_CB(skb);
		int tx_count = arg->ackFailures;
		u8 ht_flags = 0;
		int i;

#ifndef P2P_MULTIVIF
		if (txpriv->offchannel_if_id)
			bes2600_dbg(BES2600_DBG_ROC, "TX CONFIRM %x - %d - %d\n",
				skb->data[txpriv->offset],
				txpriv->offchannel_if_id, arg->status);
#endif
		if (priv->association_mode.greenfieldMode)
			ht_flags |= IEEE80211_TX_RC_GREEN_FIELD;

		if (likely(!arg->status)) {
			tx->flags |= IEEE80211_TX_STAT_ACK;
			priv->cqm_tx_failure_count = 0;
			++tx_count;
			bes2600_debug_txed(priv);
			if (arg->flags & WSM_TX_STATUS_AGGREGATION) {
				/* Do not report aggregation to mac80211:
				 * it confuses minstrel a lot. */
				/* tx->flags |= IEEE80211_TX_STAT_AMPDU; */
				bes2600_debug_txed_agg(priv);
			}
		} else {
			spin_lock(&priv->bss_loss_lock);
			if (priv->bss_loss_status == BES2600_BSS_LOSS_CONFIRMING &&
					priv->bss_loss_confirm_id == arg->packetID) {
				priv->bss_loss_status = BES2600_BSS_LOSS_CONFIRMED;
				spin_unlock(&priv->bss_loss_lock);
				cancel_delayed_work(&priv->bss_loss_work);
				queue_delayed_work(hw_priv->workqueue,
						&priv->bss_loss_work, BSS_LOSS_CFM_INV * HZ / 1000);
			} else {
				spin_unlock(&priv->bss_loss_lock);
			}

			/* TODO: Update TX failure counters */
			if (unlikely(priv->cqm_tx_failure_thold &&
			     (++priv->cqm_tx_failure_count >
			      priv->cqm_tx_failure_thold))) {
				priv->cqm_tx_failure_thold = 0;
				queue_work(hw_priv->workqueue,
						&priv->tx_failure_work);
			}
			if (tx_count)
				++tx_count;
		}
		spin_unlock(&priv->vif_lock);

		for (i = 0; i < IEEE80211_TX_MAX_RATES; ++i) {
			if (tx->status.rates[i].count >= tx_count) {
				tx->status.rates[i].count = tx_count;
				break;
			}
			tx_count -= tx->status.rates[i].count;
			if (tx->status.rates[i].flags & IEEE80211_TX_RC_MCS)
				tx->status.rates[i].flags |= ht_flags;
		}

		for (++i; i < IEEE80211_TX_MAX_RATES; ++i) {
			tx->status.rates[i].count = 0;
			tx->status.rates[i].idx = -1;
		}
#ifdef KEY_FRAME_SW_RETRY
		if (bes2600_bh_sw_process(hw_priv, arg) == 0) {
			return;
		}
#endif

#ifdef CONFIG_BES2600_TESTMODE
		bes2600_queue_remove(hw_priv, queue, arg->packetID);
#else
		bes2600_queue_remove(queue, arg->packetID);
#endif /*CONFIG_BES2600_TESTMODE*/
	}else {
		spin_unlock(&priv->vif_lock);
		return;
	}
}

static void bes2600_notify_buffered_tx(struct bes2600_vif *priv,
			       struct sk_buff *skb, int link_id, int tid)
{
#if defined(CONFIG_BES2600_USE_STE_EXTENSIONS)
	struct ieee80211_sta *sta;
	struct ieee80211_hdr *hdr;
	u8 *buffered;
	u8 still_buffered = 0;

	if (link_id && tid < BES2600_MAX_TID) {
		buffered = priv->link_id_db
				[link_id - 1].buffered;

		spin_lock_bh(&priv->ps_state_lock);
		if (!WARN_ON(!buffered[tid]))
			still_buffered = --buffered[tid];
		spin_unlock_bh(&priv->ps_state_lock);

		if (!still_buffered && tid < BES2600_MAX_TID) {
			hdr = (struct ieee80211_hdr *) skb->data;
			rcu_read_lock();
			sta = ieee80211_find_sta(priv->vif, hdr->addr1);
			if (sta)
				ieee80211_sta_set_buffered(sta, tid, false);
			rcu_read_unlock();
		}
	}
#endif /* CONFIG_BES2600_USE_STE_EXTENSIONS */
}

void bes2600_skb_dtor(struct bes2600_common *hw_priv,
		     struct sk_buff *skb,
		     const struct bes2600_txpriv *txpriv)
{
	struct bes2600_vif *priv =
		__cw12xx_hwpriv_to_vifpriv(hw_priv, txpriv->if_id);

	skb_pull(skb, txpriv->offset);
	if (priv && txpriv->rate_id != BES2600_INVALID_RATE_ID) {
		bes2600_notify_buffered_tx(priv, skb,
				txpriv->raw_link_id, txpriv->tid);
		tx_policy_put(hw_priv, txpriv->rate_id);
	}
	if (likely(!bes2600_is_itp(hw_priv))) {
		ieee80211_tx_status(hw_priv->hw, skb);
		bes2600_tx_status(priv, skb);
	}

}
#ifdef CONFIG_BES2600_TESTMODE
/* TODO It should be removed before official delivery */
static void frame_hexdump(char *prefix, u8 *data, int len)
{
	bes2600_dbg_dump(BES2600_DBG_TXRX, prefix, data, len);
}
/**
 * bes2600_tunnel_send_testmode_data - Send test frame to the driver
 *
 * @priv: pointer to bes2600 private structure
 * @skb: skb with frame
 *
 * Returns: 0 on success or non zero value on failure
 */
static int bes2600_tunnel_send_testmode_data(struct bes2600_common *hw_priv,
					    struct sk_buff *skb)
{
	if (bes2600_testmode_event(hw_priv->hw->wiphy, BES_MSG_EVENT_FRAME_DATA,
				 skb->data, skb->len, GFP_ATOMIC))
		return -EINVAL;

	return 0;
}

/**
 * bes2600_frame_test_detection - Detection frame_test
 *
 * @priv: pointer to bes2600 vif structure
 * @frame: ieee80211 header
 * @skb: skb with frame
 *
 * Returns: 1 - frame test detected, 0 - not detected
 */
static int bes2600_frame_test_detection(struct bes2600_vif *priv,
				       struct ieee80211_hdr *frame,
				       struct sk_buff *skb)
{
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
	int hdrlen = ieee80211_hdrlen(frame->frame_control);
	int detected = 0;
	int ret;

	if (hdrlen + hw_priv->test_frame.len <= skb->len &&
	    memcmp(skb->data + hdrlen, hw_priv->test_frame.data,
		   hw_priv->test_frame.len) == 0) {
		detected = 1;
		bes2600_dbg(BES2600_DBG_TEST_MODE, "TEST FRAME detected");
		frame_hexdump("TEST FRAME original:", skb->data, skb->len);
		ret = ieee80211_data_to_8023(skb, hw_priv->mac_addr,
				priv->mode);
		if (!ret) {
			frame_hexdump("FRAME 802.3:", skb->data, skb->len);
			ret = bes2600_tunnel_send_testmode_data(hw_priv, skb);
		}
		if (ret)
			bes2600_err(BES2600_DBG_TEST_MODE, "Send TESTFRAME failed(%d)", ret);
	}
	return detected;
}
#endif /* CONFIG_BES2600_TESTMODE */


static void
bes2600_rx_h_ba_stat(struct bes2600_vif *priv,
		    size_t hdrlen, size_t skb_len )
{
	struct bes2600_common *hw_priv = priv->hw_priv;
	if (priv->join_status != BES2600_JOIN_STATUS_STA)
		return;
	if (!bes2600_is_ht(&hw_priv->ht_info))
		return;
	if (!priv->setbssparams_done)
		return;

	spin_lock_bh(&hw_priv->ba_lock);
	hw_priv->ba_acc_rx += skb_len - hdrlen;
	if (!(hw_priv->ba_cnt_rx || hw_priv->ba_cnt)) {
		mod_timer(&hw_priv->ba_timer,
			jiffies + BES2600_BLOCK_ACK_INTERVAL);
	}
	hw_priv->ba_cnt_rx++;
	spin_unlock_bh(&hw_priv->ba_lock);
}

void bes2600_rx_cb(struct bes2600_vif *priv,
		  struct wsm_rx *arg,
		  struct sk_buff **skb_p)
{
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
	struct sk_buff *skb = *skb_p;
	struct ieee80211_rx_status *hdr = IEEE80211_SKB_RXCB(skb);
	struct ieee80211_hdr *frame = (struct ieee80211_hdr *)skb->data;
	struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)skb->data;
	struct bes2600_link_entry *entry = NULL;
	bool early_data = false;
	size_t hdrlen = 0;

	hdr->flag = 0;
	hdr->boottime_ns = jiffies64_to_nsecs(jiffies_64 - INITIAL_JIFFIES);
	if (unlikely(priv->mode == NL80211_IFTYPE_UNSPECIFIED)) {
		/* STA is stopped. */
		goto drop;
	}

	/* wakeup device based on frame type */
	if (!is_multicast_ether_addr(ieee80211_get_DA(frame))) {
		/* for unicast, wakeup device directly */
		bes2600_pwr_set_busy_event_with_timeout_async(
	 			hw_priv, BES_PWR_LOCK_ON_RX, BES_PWR_EVENT_RX_TIMEOUT);
	}

	if ((ieee80211_is_action(frame->frame_control))
                        && (mgmt->u.action.category == WLAN_CATEGORY_PUBLIC)) {
		u8 *action = (u8*)&mgmt->u.action.category;
		bes2600_check_go_neg_conf_success(hw_priv, action);
	}

#ifdef CONFIG_BES2600_TESTMODE
	spin_lock_bh(&hw_priv->tsm_lock);
	if (hw_priv->start_stop_tsm.start) {
		unsigned queue_id = skb_get_queue_mapping(skb);
		if (queue_id == 0) {
			struct timeval tmval;
			do_gettimeofday(&tmval);
			if (hw_priv->tsm_info.sta_roamed &&
			    hw_priv->tsm_info.use_rx_roaming) {
				hw_priv->tsm_info.roam_delay = tmval.tv_usec -
					hw_priv->tsm_info.rx_timestamp_vo;
				bes2600_dbg(BES2600_DBG_TEST_MODE, "[RX] RxInd Roaming:"
				"roam_delay = %u\n", hw_priv->tsm_info.roam_delay);
				hw_priv->tsm_info.sta_roamed = 0;
			}
			hw_priv->tsm_info.rx_timestamp_vo = tmval.tv_usec;
		}
	}
	spin_unlock_bh(&hw_priv->tsm_lock);
#endif /*CONFIG_BES2600_TESTMODE*/
	if (arg->link_id && (arg->link_id != BES2600_LINK_ID_UNMAPPED)
			&& (arg->link_id <= BES2600_MAX_STA_IN_AP_MODE)) {
		entry =	&priv->link_id_db[arg->link_id - 1];
		if (entry->status == BES2600_LINK_SOFT &&
				ieee80211_is_data(frame->frame_control))
			early_data = true;
		entry->timestamp = jiffies;
	}
#if defined(CONFIG_BES2600_USE_STE_EXTENSIONS)
	else if ((arg->link_id == BES2600_LINK_ID_UNMAPPED)
			&& (priv->vif->p2p == WSM_START_MODE_P2P_GO)
			&& ieee80211_is_action(frame->frame_control)
			&& (mgmt->u.action.category == WLAN_CATEGORY_PUBLIC)) {
		bes2600_dbg(BES2600_DBG_TXRX, "[RX] Going to MAP&RESET link ID\n");

		if (work_pending(&priv->linkid_reset_work))
			WARN_ON(1);

		memcpy(&priv->action_frame_sa[0],
				ieee80211_get_SA(frame), ETH_ALEN);
		priv->action_linkid = 0;
		schedule_work(&priv->linkid_reset_work);
	}

	if (arg->link_id && (arg->link_id != BES2600_LINK_ID_UNMAPPED)
			&& (priv->vif->p2p == WSM_START_MODE_P2P_GO)
			&& ieee80211_is_action(frame->frame_control)
			&& (mgmt->u.action.category == WLAN_CATEGORY_PUBLIC)) {
		/* Link ID already exists for the ACTION frame.
		 * Reset and Remap */
		if (work_pending(&priv->linkid_reset_work))
			WARN_ON(1);
		memcpy(&priv->action_frame_sa[0],
				ieee80211_get_SA(frame), ETH_ALEN);
		priv->action_linkid = arg->link_id;
		schedule_work(&priv->linkid_reset_work);
	}
#endif
	if (unlikely(arg->status)) {
		if (arg->status == WSM_STATUS_MICFAILURE) {
			bes2600_warn(BES2600_DBG_TXRX, "[RX] MIC failure.\n");
			hdr->flag |= RX_FLAG_MMIC_ERROR;
		} else if (arg->status == WSM_STATUS_NO_KEY_FOUND) {
			bes2600_dbg(BES2600_DBG_TXRX, "[RX] No key found.\n");
			goto drop;
		} else {
			bes2600_warn(BES2600_DBG_TXRX, "[RX] Receive failure: %d.\n",
				arg->status);
			goto drop;
		}
	}

	if (skb->len < sizeof(struct ieee80211_pspoll)) {
		wiphy_warn(priv->hw->wiphy, "Mailformed SDU rx'ed. "
				"Size is lesser than IEEE header.\n");
		goto drop;
	}

	if (unlikely(ieee80211_is_pspoll(frame->frame_control)))
		if (bes2600_handle_pspoll(priv, skb))
			goto drop;

	hdr->mactime = 0; /* Not supported by WSM */
	hdr->band = (arg->channelNumber > 14) ?
			NL80211_BAND_5GHZ : NL80211_BAND_2GHZ;
	hdr->freq = ieee80211_channel_to_frequency(
			arg->channelNumber,
			hdr->band);

	if (arg->rxedRate >= 14) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))
		hdr->encoding |= RX_ENC_HT;
#else
		hdr->flag |= RX_FLAG_HT;
#endif
		hdr->rate_idx = arg->rxedRate - 14;
	} else if (arg->rxedRate >= 4) {
		if (hdr->band == NL80211_BAND_5GHZ)
			hdr->rate_idx = arg->rxedRate - 6;
		else
			hdr->rate_idx = arg->rxedRate - 2;
	} else {
		hdr->rate_idx = arg->rxedRate;
	}

	hdr->signal = (s8)arg->rcpiRssi;
	hdr->antenna = 0;

	hdrlen = ieee80211_hdrlen(frame->frame_control);
	if (WSM_RX_STATUS_ENCRYPTION(arg->flags) == WSM_RX_STATUS_DECRYPTED) {
		/* decrypted frame with iv/icv stripped */
		hdr->flag |= RX_FLAG_DECRYPTED;
		hdr->flag |= RX_FLAG_IV_STRIPPED;
	}
	else if (WSM_RX_STATUS_ENCRYPTION(arg->flags)) {
		size_t iv_len = 0, icv_len = 0;

		hdr->flag |= RX_FLAG_DECRYPTED;

		/* Oops... There is no fast way to ask mac80211 about
		 * IV/ICV lengths. Even defineas are not exposed.*/
		switch (WSM_RX_STATUS_ENCRYPTION(arg->flags)) {
		case WSM_RX_STATUS_WEP:
			iv_len = 4 /* WEP_IV_LEN */;
			icv_len = 4 /* WEP_ICV_LEN */;
			break;
		case WSM_RX_STATUS_TKIP:
			iv_len = 8 /* TKIP_IV_LEN */;
			icv_len = 4 /* TKIP_ICV_LEN */
				+ 8 /*MICHAEL_MIC_LEN*/;
			hdr->flag |= RX_FLAG_MMIC_STRIPPED;
			break;
		case WSM_RX_STATUS_AES:
			iv_len = 8 /* CCMP_HDR_LEN */;
			icv_len = 8 /* CCMP_MIC_LEN */;
			break;
		case WSM_RX_STATUS_WAPI:
			iv_len = 18 /* WAPI_HDR_LEN */;
			icv_len = 16 /* WAPI_MIC_LEN */;
			hdr->flag |= RX_FLAG_IV_STRIPPED;
			break;
		default:
			WARN_ON("Unknown encryption type");
			goto drop;
		}

		/* Firmware strips ICV in case of MIC failure. */
		if (arg->status == WSM_STATUS_MICFAILURE) {
			icv_len = 0;
			hdr->flag |= RX_FLAG_IV_STRIPPED;
		}

		if (skb->len < hdrlen + iv_len + icv_len) {
			wiphy_warn(priv->hw->wiphy, "Mailformed SDU rx'ed. "
				"Size is lesser than crypto headers.\n");
			goto drop;
		}

		/* Protocols not defined in mac80211 should be
		stripped/crypted in driver/firmware */
		if (WSM_RX_STATUS_ENCRYPTION(arg->flags) ==
						WSM_RX_STATUS_WAPI) {
			/* Remove IV, ICV and MIC */
			skb_trim(skb, skb->len - icv_len);
			memmove(skb->data + iv_len, skb->data, hdrlen);
			skb_pull(skb, iv_len);
		}

	}

	bes2600_debug_rxed(priv);
	if (arg->flags & WSM_RX_STATUS_AGGREGATE)
		bes2600_debug_rxed_agg(priv);

	if (ieee80211_is_beacon(frame->frame_control) &&
			!arg->status &&
			!memcmp(ieee80211_get_SA(frame), priv->join_bssid,
				ETH_ALEN)) {
		const u8 *tim_ie;
		u8 *ies;
		size_t ies_len;
		priv->disable_beacon_filter = false;
		queue_work(hw_priv->workqueue, &priv->update_filtering_work);
		ies = ((struct ieee80211_mgmt *)
			  (skb->data))->u.beacon.variable;
		ies_len = skb->len - (ies - (u8 *)(skb->data));

		tim_ie = bes2600_get_ie(ies, ies_len, WLAN_EID_TIM);
		if (tim_ie) {
			struct ieee80211_tim_ie *tim =
				(struct ieee80211_tim_ie *)&tim_ie[2];

			if (priv->join_dtim_period != tim->dtim_period) {
				priv->join_dtim_period = tim->dtim_period;
				queue_work(hw_priv->workqueue,
					&priv->set_beacon_wakeup_period_work);
			}
		}
		if (unlikely(priv->disable_beacon_filter)) {
			priv->disable_beacon_filter = false;
			queue_work(hw_priv->workqueue,
				&priv->update_filtering_work);
		}
	}
#ifdef AP_HT_CAP_UPDATE
        if (priv->mode == NL80211_IFTYPE_AP &&
                        ieee80211_is_beacon(frame->frame_control) &&
                        !arg->status){

                u8 *ies;
                size_t ies_len;
                const u8 *ht_cap;
                ies = ((struct ieee80211_mgmt *)
                          (skb->data))->u.beacon.variable;
                ies_len = skb->len - (ies - (u8 *)(skb->data));
                ht_cap = bes2600_get_ie(ies, ies_len, WLAN_EID_HT_CAPABILITY);
                if(!ht_cap){
                        priv->ht_info |= 0x0011;
                }
                queue_work(hw_priv->workqueue,
                                &priv->ht_info_update_work);

        }
#endif

#ifdef ROAM_OFFLOAD
	if ((ieee80211_is_beacon(frame->frame_control)||ieee80211_is_probe_resp(frame->frame_control)) &&
			!arg->status ) {
		if (hw_priv->auto_scanning && !atomic_read(&hw_priv->scan.in_progress))
			hw_priv->frame_rcvd = 1;

		if (!memcmp(ieee80211_get_SA(frame), priv->join_bssid, ETH_ALEN)) {
			if (hw_priv->beacon)
				dev_kfree_skb(hw_priv->beacon);
			hw_priv->beacon = skb_copy(skb, GFP_ATOMIC);
			if (!hw_priv->beacon)
				bes2600_err(BES2600_DBG_TXRX, "bes2600: sched_scan: own beacon storing failed\n");
		}
	}
#endif /*ROAM_OFFLOAD*/

	if (ieee80211_is_deauth(frame->frame_control) ||
	    ieee80211_is_disassoc(frame->frame_control))
	    bes2600_pwr_set_busy_event_with_timeout_async(hw_priv,
	    		BES_PWR_LOCK_ON_DISCON, 1500);


	if (ieee80211_is_data(frame->frame_control)) {
		bes2600_rx_h_ba_stat(priv, hdrlen, skb->len);
		bes2600_rx_status(priv, skb);
	}

#ifdef CONFIG_BES2600_TESTMODE
	if (hw_priv->test_frame.len > 0 &&
		priv->mode == NL80211_IFTYPE_STATION) {
		if (bes2600_frame_test_detection(priv, frame, skb) == 1) {
			consume_skb(skb);
			*skb_p = NULL;
			return;
		}
	}
#endif /* CONFIG_BES2600_TESTMODE */

	if (unlikely(bes2600_itp_rxed(hw_priv, skb)))
		consume_skb(skb);
	else if (unlikely(early_data)) {
		spin_lock_bh(&priv->ps_state_lock);
		/* Double-check status with lock held */
		if (entry->status == BES2600_LINK_SOFT)
			skb_queue_tail(&entry->rx_queue, skb);
		else
			ieee80211_rx_irqsafe(priv->hw, skb);
		spin_unlock_bh(&priv->ps_state_lock);
	} else {
		ieee80211_rx_irqsafe(priv->hw, skb);
	}
	*skb_p = NULL;

	return;

drop:
	/* TODO: update failure counters */
	return;
}

/* ******************************************************************** */
/* Security								*/

int bes2600_alloc_key(struct bes2600_common *hw_priv)
{
	int idx;

	idx = ffs(~hw_priv->key_map) - 1;
	if (idx < 0 || idx > WSM_KEY_MAX_INDEX)
		return -1;

	hw_priv->key_map |= BIT(idx);
	hw_priv->keys[idx].entryIndex = idx;
	return idx;
}

void bes2600_free_key(struct bes2600_common *hw_priv, int idx)
{
	BUG_ON(!(hw_priv->key_map & BIT(idx)));
	memset(&hw_priv->keys[idx], 0, sizeof(hw_priv->keys[idx]));
	hw_priv->key_map &= ~BIT(idx);
}

void bes2600_free_keys(struct bes2600_common *hw_priv)
{
	memset(&hw_priv->keys, 0, sizeof(hw_priv->keys));
	hw_priv->key_map = 0;
}

int bes2600_upload_keys(struct bes2600_vif *priv)
{
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
	int idx, ret = 0;

	for (idx = 0; idx <= WSM_KEY_MAX_IDX; ++idx)
		if (hw_priv->key_map & BIT(idx)) {
			ret = wsm_add_key(hw_priv, &hw_priv->keys[idx], priv->if_id);
			if (ret < 0)
				break;
		}
	return ret;
}
#if defined(CONFIG_BES2600_USE_STE_EXTENSIONS)
/* Workaround for WFD test case 6.1.10 */
void bes2600_link_id_reset(struct work_struct *work)
{
	struct bes2600_vif *priv =
		container_of(work, struct bes2600_vif, linkid_reset_work);
	struct bes2600_common *hw_priv = priv->hw_priv;
	int temp_linkid;

	if (!priv->action_linkid) {
		/* In GO mode we can receive ACTION frames without a linkID */
		temp_linkid = bes2600_alloc_link_id(priv,
				&priv->action_frame_sa[0]);
		WARN_ON(!temp_linkid);
		if (temp_linkid) {
			/* Make sure we execute the WQ */
			flush_workqueue(hw_priv->workqueue);
			/* Release the link ID */
			spin_lock_bh(&priv->ps_state_lock);
			priv->link_id_db[temp_linkid - 1].prev_status =
				priv->link_id_db[temp_linkid - 1].status;
			priv->link_id_db[temp_linkid - 1].status =
				BES2600_LINK_RESET;
			spin_unlock_bh(&priv->ps_state_lock);
			wsm_lock_tx_async(hw_priv);
			if (queue_work(hw_priv->workqueue,
				       &priv->link_id_work) <= 0)
				wsm_unlock_tx(hw_priv);
		}
	} else {
		spin_lock_bh(&priv->ps_state_lock);
		priv->link_id_db[priv->action_linkid - 1].prev_status =
			priv->link_id_db[priv->action_linkid - 1].status;
		priv->link_id_db[priv->action_linkid - 1].status =
			BES2600_LINK_RESET_REMAP;
		spin_unlock_bh(&priv->ps_state_lock);
		wsm_lock_tx_async(hw_priv);
		if (queue_work(hw_priv->workqueue, &priv->link_id_work) <= 0)
				wsm_unlock_tx(hw_priv);
		flush_workqueue(hw_priv->workqueue);
	}
}
#endif
