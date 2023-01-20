/*
 * O(1) TX queue with built-in allocator for BES2600 drivers
 *
 * Copyright (c) 2022, Bestechnic
 * Author:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <net/mac80211.h>
#include <linux/sched.h>
#include <linux/version.h>
#include "bes2600.h"
#include "queue.h"
#include "debug.h"
#ifdef CONFIG_BES2600_TESTMODE
#include <linux/time.h>
#endif /*CONFIG_BES2600_TESTMODE*/

/* private */ struct bes2600_queue_item
{
	struct list_head	head;
	struct sk_buff		*skb;
	u32			packetID;
	unsigned long		queue_timestamp;
	unsigned long		xmit_timestamp;
#ifdef CONFIG_BES2600_TESTMODE
	unsigned long		mdelay_timestamp;
	unsigned long		qdelay_timestamp;
#endif /*CONFIG_BES2600_TESTMODE*/
	struct bes2600_txpriv	txpriv;
	u8			generation;
};

int bes2600_queue_get_skb_and_timestamp(struct bes2600_queue *queue, u32 packetID,
			struct sk_buff **skb, struct bes2600_txpriv **txpriv,
			unsigned long *timestamp)
{
	int ret = 0;
	u8 queue_generation, queue_id, item_generation, item_id, if_id, link_id;
	struct bes2600_queue_item *item;
	bes2600_queue_parse_id(packetID, &queue_generation, &queue_id,
				&item_generation, &item_id, &if_id, &link_id);
	if (unlikely(item_id >= (u8) queue->capacity))
		return -EINVAL;
	item = &queue->pool[item_id];
	spin_lock_bh(&queue->lock);
	BUG_ON(queue_id != queue->queue_id);
	if (unlikely(queue_generation != queue->generation)) {
		WARN(1, "queue generation mismatch, %u, expect %u, if_id: %u.\n",
		queue_generation, queue->generation, if_id);
		ret = -ENOENT;
	} else if (unlikely(item_generation != item->generation)) {
		WARN(1, "item generation mismatch, %u, expect %u.\n",
		item_generation, item->generation);
		ret = -ENOENT;
	} else if (unlikely(WARN_ON(!item->skb))) {
		ret = -ENOENT;
	} else {
		*skb = item->skb;
		*txpriv = &item->txpriv;
		*timestamp = item->xmit_timestamp;
	}
	spin_unlock_bh(&queue->lock);
	return ret;
}


static inline void __bes2600_queue_lock(struct bes2600_queue *queue)
{
	struct bes2600_queue_stats *stats = queue->stats;
	if (queue->tx_locked_cnt++ == 0) {
		bes2600_dbg(BES2600_DBG_TXRX, "[TX] Queue %d is locked.\n",
				queue->queue_id);
		ieee80211_stop_queue(stats->hw_priv->hw, queue->queue_id);
	}
}

static inline void __bes2600_queue_unlock(struct bes2600_queue *queue)
{
	struct bes2600_queue_stats *stats = queue->stats;
	BUG_ON(!queue->tx_locked_cnt);
	if (--queue->tx_locked_cnt == 0) {
		bes2600_dbg(BES2600_DBG_TXRX, "[TX] Queue %d is unlocked.\n",
				queue->queue_id);
		ieee80211_wake_queue(stats->hw_priv->hw, queue->queue_id);
	}
}



static inline u32 bes2600_queue_make_packet_id(u8 queue_generation, u8 queue_id,
						u8 item_generation, u8 item_id,
						u8 if_id, u8 link_id)
{
	/*TODO:COMBO: Add interfaceID to the packetID */
	return ((u32)item_id << 0) |
		((u32)item_generation << 8) |
		((u32)queue_id << 16) |
		((u32)if_id << 20) |
		((u32)link_id << 24) |
		((u32)queue_generation << 28);
}

static void bes2600_queue_post_gc(struct bes2600_queue_stats *stats,
				 struct list_head *gc_list)
{
	struct bes2600_queue_item *item;

	while (!list_empty(gc_list)) {
		item = list_first_entry(
			gc_list, struct bes2600_queue_item, head);
		list_del(&item->head);
		stats->skb_dtor(stats->hw_priv, item->skb, &item->txpriv);
		kfree(item);
	}
}

static void bes2600_queue_register_post_gc(struct list_head *gc_list,
				     struct bes2600_queue_item *item)
{
	struct bes2600_queue_item *gc_item;
	gc_item = kmalloc(sizeof(struct bes2600_queue_item),
			GFP_ATOMIC);
	BUG_ON(!gc_item);
	memcpy(gc_item, item, sizeof(struct bes2600_queue_item));
	list_add_tail(&gc_item->head, gc_list);
}

static void __bes2600_queue_gc(struct bes2600_queue *queue,
			      struct list_head *head,
			      bool unlock)
{
	struct bes2600_queue_stats *stats = queue->stats;
	struct bes2600_queue_item *item = NULL;
	struct bes2600_vif *priv;
	int if_id;
	bool wakeup_stats = false;

	while (!list_empty(&queue->queue)) {
		struct bes2600_txpriv *txpriv;
		item = list_first_entry(
			&queue->queue, struct bes2600_queue_item, head);
		if (jiffies - item->queue_timestamp < queue->ttl)
			break;

		txpriv = &item->txpriv;
		if_id = txpriv->if_id;
		--queue->num_queued;
		--queue->num_queued_vif[if_id];
		--queue->link_map_cache[if_id][txpriv->link_id];
		spin_lock_bh(&stats->lock);
		--stats->num_queued[if_id];
		if (!--stats->link_map_cache[if_id][txpriv->link_id])
			wakeup_stats = true;
		spin_unlock_bh(&stats->lock);
		priv = cw12xx_hwpriv_to_vifpriv(stats->hw_priv, if_id);
		if (priv) {
			bes2600_debug_tx_ttl(priv);
			spin_unlock(&priv->vif_lock);
		}
		bes2600_queue_register_post_gc(head, item);
		item->skb = NULL;
		list_move_tail(&item->head, &queue->free_pool);
	}

	if (wakeup_stats)
		wake_up(&stats->wait_link_id_empty);

	if (queue->overfull) {
		if (queue->num_queued <= ((stats->hw_priv->vif0_throttle +
						stats->hw_priv->vif1_throttle + 2)/2)) {
			queue->overfull = false;
			if (unlock)
				__bes2600_queue_unlock(queue);
		} else if (item) {
			unsigned long tmo = item->queue_timestamp + queue->ttl;
			mod_timer(&queue->gc, tmo);
			bes2600_pwr_set_busy_event_with_timeout(stats->hw_priv,
				BES_PWR_LOCK_ON_QUEUE_GC, jiffies_to_msecs(tmo - jiffies));
		}
	}
}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))
static void bes2600_queue_gc(struct timer_list *t)
{
	LIST_HEAD(list);
	struct bes2600_queue *queue = from_timer(queue, t, gc);

	spin_lock_bh(&queue->lock);
	__bes2600_queue_gc(queue, &list, true);
	spin_unlock_bh(&queue->lock);
	bes2600_queue_post_gc(queue->stats, &list);
}
#else
static void bes2600_queue_gc(unsigned long arg)
{
	LIST_HEAD(list);
	struct bes2600_queue *queue = (struct bes2600_queue *)arg;

	spin_lock_bh(&queue->lock);
	__bes2600_queue_gc(queue, &list, true);
	spin_unlock_bh(&queue->lock);
	bes2600_queue_post_gc(queue->stats, &list);
}
#endif

int bes2600_queue_stats_init(struct bes2600_queue_stats *stats,
			    size_t map_capacity,
			    bes2600_queue_skb_dtor_t skb_dtor,
			    struct bes2600_common *hw_priv)
{
	int i;

	memset(stats, 0, sizeof(*stats));
	stats->map_capacity = map_capacity;
	stats->skb_dtor = skb_dtor;
	stats->hw_priv = hw_priv;
	spin_lock_init(&stats->lock);
	init_waitqueue_head(&stats->wait_link_id_empty);
	for (i = 0; i < CW12XX_MAX_VIFS; i++) {
		stats->link_map_cache[i] = kzalloc(map_capacity * sizeof(int),
			GFP_KERNEL);
		if (!stats->link_map_cache[i]) {
			for (; i >= 0; i--)
				kfree(stats->link_map_cache[i]);
			return -ENOMEM;
		}
	}

	return 0;
}

int bes2600_queue_init(struct bes2600_queue *queue,
		      struct bes2600_queue_stats *stats,
		      u8 queue_id,
		      size_t capacity,
		      unsigned long ttl)
{
	int i;

	memset(queue, 0, sizeof(*queue));
	queue->stats = stats;
	queue->capacity = capacity;
	queue->queue_id = queue_id;
	queue->ttl = ttl;
	INIT_LIST_HEAD(&queue->queue);
	INIT_LIST_HEAD(&queue->pending);
	INIT_LIST_HEAD(&queue->free_pool);
	spin_lock_init(&queue->lock);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))
	timer_setup(&queue->gc, bes2600_queue_gc, 0);
#else
	setup_timer(&queue->gc, bes2600_queue_gc,(unsigned long)queue);
#endif
	queue->pool = kzalloc(sizeof(struct bes2600_queue_item) * capacity,
			GFP_KERNEL);
	if (!queue->pool)
		return -ENOMEM;

	for (i = 0; i < CW12XX_MAX_VIFS; i++) {
		queue->link_map_cache[i] =
				kzalloc(stats->map_capacity * sizeof(int),
			GFP_KERNEL);
		if (!queue->link_map_cache[i]) {
			for (; i >= 0; i--)
				kfree(queue->link_map_cache[i]);
			kfree(queue->pool);
			queue->pool = NULL;
			return -ENOMEM;
		}
	}

	for (i = 0; i < capacity; ++i)
		list_add_tail(&queue->pool[i].head, &queue->free_pool);

	return 0;
}

/* TODO:COMBO: Flush only a particular interface specific parts */
int bes2600_queue_clear(struct bes2600_queue *queue, int if_id)
{
	int i, cnt, iter;
	struct bes2600_queue_stats *stats = queue->stats;
	LIST_HEAD(gc_list);

	cnt = 0;
	spin_lock_bh(&queue->lock);
	queue->generation++;
	queue->generation &= 0xf;
	list_splice_tail_init(&queue->queue, &queue->pending);
	while (!list_empty(&queue->pending)) {
		struct bes2600_queue_item *item = list_first_entry(
			&queue->pending, struct bes2600_queue_item, head);
		WARN_ON(!item->skb);
		if (CW12XX_ALL_IFS == if_id || item->txpriv.if_id == if_id) {
			bes2600_queue_register_post_gc(&gc_list, item);
			item->skb = NULL;
			list_move_tail(&item->head, &queue->free_pool);
			cnt++;
		}
	}
	queue->num_queued -= cnt;
	queue->num_pending -= cnt;
	if (CW12XX_ALL_IFS != if_id) {
		queue->num_queued_vif[if_id] = 0;
		queue->num_pending_vif[if_id] = 0;
	} else {
		for (iter = 0; iter < CW12XX_MAX_VIFS; iter++) {
			queue->num_queued_vif[iter] = 0;
			queue->num_pending_vif[iter] = 0;
		}
	}
	spin_lock_bh(&stats->lock);
	if (CW12XX_ALL_IFS != if_id) {
		for (i = 0; i < stats->map_capacity; ++i) {
			stats->num_queued[if_id] -=
				queue->link_map_cache[if_id][i];
			stats->link_map_cache[if_id][i] -=
				queue->link_map_cache[if_id][i];
			queue->link_map_cache[if_id][i] = 0;
		}
	} else {
		for (iter = 0; iter < CW12XX_MAX_VIFS; iter++) {
			for (i = 0; i < stats->map_capacity; ++i) {
				stats->num_queued[iter] -=
					queue->link_map_cache[iter][i];
				stats->link_map_cache[iter][i] -=
					queue->link_map_cache[iter][i];
				queue->link_map_cache[iter][i] = 0;
			}
		}
	}
	spin_unlock_bh(&stats->lock);
	if (unlikely(queue->overfull)) {
		queue->overfull = false;
		__bes2600_queue_unlock(queue);
	}
	spin_unlock_bh(&queue->lock);
	wake_up(&stats->wait_link_id_empty);
	bes2600_queue_post_gc(stats, &gc_list);
	return 0;
}

void bes2600_queue_stats_deinit(struct bes2600_queue_stats *stats)
{
	int i;

	for (i = 0; i < CW12XX_MAX_VIFS ; i++) {
		kfree(stats->link_map_cache[i]);
		stats->link_map_cache[i] = NULL;
	}
}

void bes2600_queue_deinit(struct bes2600_queue *queue)
{
	int i;

	bes2600_queue_clear(queue, CW12XX_ALL_IFS);
	del_timer_sync(&queue->gc);
	INIT_LIST_HEAD(&queue->free_pool);
	kfree(queue->pool);
	for (i = 0; i < CW12XX_MAX_VIFS; i++) {
		kfree(queue->link_map_cache[i]);
		queue->link_map_cache[i] = NULL;
	}
	queue->pool = NULL;
	queue->capacity = 0;
}

size_t bes2600_queue_get_num_queued(struct bes2600_vif *priv,
				   struct bes2600_queue *queue,
				   u32 link_id_map)
{
	size_t ret;
	int i, bit;
	size_t map_capacity = queue->stats->map_capacity;

	if (!link_id_map)
		return 0;

	spin_lock_bh(&queue->lock);
	if (likely(link_id_map == (u32) -1)) {
		ret = queue->num_queued_vif[priv->if_id] -
			queue->num_pending_vif[priv->if_id];
	} else {
		ret = 0;
		for (i = 0, bit = 1; i < map_capacity; ++i, bit <<= 1) {
			if (link_id_map & bit)
				ret +=
				queue->link_map_cache[priv->if_id][i];
		}
	}
	spin_unlock_bh(&queue->lock);
	return ret;
}

int bes2600_queue_put(struct bes2600_queue *queue,
		     struct sk_buff *skb,
		     struct bes2600_txpriv *txpriv)
{
	int ret = 0;
#ifdef CONFIG_BES2600_TESTMODE
	struct timeval tmval;
#endif /*CONFIG_BES2600_TESTMODE*/

	LIST_HEAD(gc_list);
	struct bes2600_queue_stats *stats = queue->stats;
	/* TODO:COMBO: Add interface ID info to queue item */

	if (txpriv->link_id >= queue->stats->map_capacity)
		return -EINVAL;

	spin_lock_bh(&queue->lock);
	if (!WARN_ON(list_empty(&queue->free_pool))) {
		struct bes2600_queue_item *item = list_first_entry(
			&queue->free_pool, struct bes2600_queue_item, head);
		BUG_ON(item->skb);

		list_move_tail(&item->head, &queue->queue);
		item->skb = skb;
		item->txpriv = *txpriv;
		item->generation = 0;
		item->packetID = bes2600_queue_make_packet_id(
			queue->generation, queue->queue_id,
			item->generation, item - queue->pool,
			txpriv->if_id, txpriv->raw_link_id);
		item->queue_timestamp = jiffies;
#ifdef BES2600_HOST_TIMESTAMP_DEBUG
		if (skb_tailroom(skb) >= 4) {
			u32 *extra_data;
			extra_data = (u32 *)skb_tail_pointer(skb);
			*extra_data = (u32)jiffies_to_msecs(item->queue_timestamp);
		}
#endif
#ifdef CONFIG_BES2600_TESTMODE
		do_gettimeofday(&tmval);
		item->qdelay_timestamp = tmval.tv_usec;
#endif /*CONFIG_BES2600_TESTMODE*/

		++queue->num_queued;
		++queue->num_queued_vif[txpriv->if_id];
		++queue->link_map_cache[txpriv->if_id][txpriv->link_id];

		spin_lock_bh(&stats->lock);
		++stats->num_queued[txpriv->if_id];
		++stats->link_map_cache[txpriv->if_id][txpriv->link_id];
		spin_unlock_bh(&stats->lock);

		/*
		 * TX may happen in parallel sometimes.
		 * Leave extra queue slots so we don't overflow.
		 */
		if (queue->overfull == false &&
				queue->num_queued >=
		((stats->hw_priv->vif0_throttle +
			stats->hw_priv->vif1_throttle + 2)
				- (num_present_cpus() - 1))) {
			queue->overfull = true;
			__bes2600_queue_lock(queue);
			mod_timer(&queue->gc, jiffies);
		}
	} else {
		ret = -ENOENT;
	}
#if 0
	bes2600_dbg(BES2600_DBG_TXRX, "queue_put queue %d, %d, %d\n",
		queue->num_queued,
		queue->link_map_cache[txpriv->if_id][txpriv->link_id],
		queue->num_pending);
	bes2600_dbg(BES2600_DBG_TXRX, "queue_put stats %d, %d\n", stats->num_queued,
		stats->link_map_cache[txpriv->if_id][txpriv->link_id]);
#endif
	spin_unlock_bh(&queue->lock);
	return ret;
}

int bes2600_queue_get(struct bes2600_queue *queue,
			int if_id,
		     u32 link_id_map,
		     struct wsm_tx **tx,
		     struct ieee80211_tx_info **tx_info,
		     struct bes2600_txpriv **txpriv)
{
	int ret = -ENOENT;
	struct bes2600_queue_item *item = NULL;
	struct bes2600_queue_stats *stats = queue->stats;
	bool wakeup_stats = false;
#ifdef CONFIG_BES2600_TESTMODE
	struct timeval tmval;
#endif /*CONFIG_BES2600_TESTMODE*/

	spin_lock_bh(&queue->lock);
	list_for_each_entry(item, &queue->queue, head) {
		if ((item->txpriv.if_id == if_id) &&
			(link_id_map & BIT(item->txpriv.link_id))) {
			ret = 0;
			break;
		}
	}

	if (!WARN_ON(ret)) {
		*tx = (struct wsm_tx *)item->skb->data;
		*tx_info = IEEE80211_SKB_CB(item->skb);
		*txpriv = &item->txpriv;
		(*tx)->packetID = __cpu_to_le32(item->packetID);
		list_move_tail(&item->head, &queue->pending);
		++queue->num_pending;
		++queue->num_pending_vif[item->txpriv.if_id];
		--queue->link_map_cache[item->txpriv.if_id]
				[item->txpriv.link_id];
		item->xmit_timestamp = jiffies;
#ifdef CONFIG_BES2600_TESTMODE
		do_gettimeofday(&tmval);
		item->mdelay_timestamp = tmval.tv_usec;
#endif /*CONFIG_BES2600_TESTMODE*/

		spin_lock_bh(&stats->lock);
		--stats->num_queued[item->txpriv.if_id];
		if (!--stats->link_map_cache[item->txpriv.if_id]
					[item->txpriv.link_id])
			wakeup_stats = true;

		spin_unlock_bh(&stats->lock);
#if 0
		bes2600_dbg(BES2600_DBG_TXRX, "queue_get queue %d, %d, %d\n",
		queue->num_queued,
		queue->link_map_cache[item->txpriv.if_id][item->txpriv.link_id],
		queue->num_pending);
		bes2600_dbg(BES2600_DBG_TXRX, "queue_get stats %d, %d\n", stats->num_queued,
		stats->link_map_cache[item->txpriv.if_id]
		[item->txpriv.link_id]);
#endif
	}
	spin_unlock_bh(&queue->lock);
	if (wakeup_stats)
		wake_up(&stats->wait_link_id_empty);
	return ret;
}

#ifdef CONFIG_BES2600_TESTMODE
int bes2600_queue_requeue(struct bes2600_common *hw_priv,
	struct bes2600_queue *queue, u32 packetID, bool check)
#else
int bes2600_queue_requeue(struct bes2600_queue *queue, u32 packetID, bool check)
#endif
{
	int ret = 0;
	u8 queue_generation, queue_id, item_generation, item_id, if_id, link_id;
	struct bes2600_queue_item *item;
	struct bes2600_queue_stats *stats = queue->stats;

	bes2600_queue_parse_id(packetID, &queue_generation, &queue_id,
				&item_generation, &item_id, &if_id, &link_id);

	item = &queue->pool[item_id];
#ifdef P2P_MULTIVIF
	if (check && item->txpriv.if_id == CW12XX_GENERIC_IF_ID) {
#else
	if (check && item->txpriv.offchannel_if_id == CW12XX_GENERIC_IF_ID) {
#endif
		bes2600_dbg(BES2600_DBG_TXRX, "Requeued frame dropped for "
						"generic interface id.\n");
#ifdef CONFIG_BES2600_TESTMODE
		bes2600_queue_remove(hw_priv, queue, packetID);
#else
		bes2600_queue_remove(queue, packetID);
#endif
		return 0;
	}

#ifndef P2P_MULTIVIF
	if (!check)
		item->txpriv.offchannel_if_id = CW12XX_GENERIC_IF_ID;
#endif

	/*if_id = item->txpriv.if_id;*/

	spin_lock_bh(&queue->lock);
	BUG_ON(queue_id != queue->queue_id);
	if (unlikely(queue_generation != queue->generation)) {
		bes2600_info(BES2600_DBG_TXRX, "%s, Queue Generation is not equal\n", __func__);
		ret = 0;
	} else if (unlikely(item_id >= (unsigned) queue->capacity)) {
		WARN_ON(1);
		ret = -EINVAL;
	} else if (unlikely(item->generation != item_generation)) {
		WARN_ON(1);
		ret = -ENOENT;
	} else {
		--queue->num_pending;
		--queue->num_pending_vif[if_id];
		++queue->link_map_cache[if_id][item->txpriv.link_id];

		spin_lock_bh(&stats->lock);
		++stats->num_queued[item->txpriv.if_id];
		++stats->link_map_cache[if_id][item->txpriv.link_id];
		spin_unlock_bh(&stats->lock);

		item->generation = ++item_generation;
		item->packetID = bes2600_queue_make_packet_id(
			queue_generation, queue_id, item_generation, item_id,
			if_id, link_id);
		list_move(&item->head, &queue->queue);
#if 0
		bes2600_dbg(BES2600_DBG_TXRX, "queue_requeue queue %d, %d, %d\n",
		queue->num_queued,
		queue->link_map_cache[if_id][item->txpriv.link_id],
		queue->num_pending);
		bes2600_dbg(BES2600_DBG_TXRX, "queue_requeue stats %d, %d\n",
		stats->num_queued,
		stats->link_map_cache[if_id][item->txpriv.link_id]);
#endif
	}
	spin_unlock_bh(&queue->lock);
	return ret;
}

int bes2600_sw_retry_requeue(struct bes2600_common *hw_priv,
	struct bes2600_queue *queue, u32 packetID, bool check)
{
	int ret = 0;
	u8 queue_generation, queue_id, item_generation, item_id, if_id, link_id;
	struct bes2600_queue_item *item;
	struct bes2600_queue_stats *stats = queue->stats;
	bes2600_queue_parse_id(packetID, &queue_generation, &queue_id,
				&item_generation, &item_id, &if_id, &link_id);
	item = &queue->pool[item_id];
#ifdef P2P_MULTIVIF
	if (check && item->txpriv.if_id == CW12XX_GENERIC_IF_ID) {
#else
	if (check && item->txpriv.offchannel_if_id == CW12XX_GENERIC_IF_ID) {
#endif
		bes2600_dbg(BES2600_DBG_TXRX, "Requeued frame dropped for "
						"generic interface id.\n");
#ifdef CONFIG_BES2600_TESTMODE
		bes2600_queue_remove(hw_priv, queue, packetID);
#else
		bes2600_queue_remove(queue, packetID);
#endif
		return 0;
	}

#ifndef P2P_MULTIVIF
	if (!check)
		item->txpriv.offchannel_if_id = CW12XX_GENERIC_IF_ID;
#endif
	/*if_id = item->txpriv.if_id;*/
	spin_lock_bh(&queue->lock);
	BUG_ON(queue_id != queue->queue_id);
	if (unlikely(queue_generation != queue->generation)) {
		bes2600_info(BES2600_DBG_TXRX, "%s, Queue Generation is not equal\n", __func__);
		ret = 0;
	} else if (unlikely(item_id >= (unsigned) queue->capacity)) {
		WARN_ON(1);
		ret = -EINVAL;
	} else if (unlikely(item->generation != item_generation)) {
		WARN_ON(1);
		ret = -ENOENT;
	} else {
		--queue->num_pending;
		--queue->num_pending_vif[if_id];
		++queue->link_map_cache[if_id][item->txpriv.link_id];
		spin_lock_bh(&stats->lock);
		++stats->num_queued[item->txpriv.if_id];
		++stats->link_map_cache[if_id][item->txpriv.link_id];
		spin_unlock_bh(&stats->lock);
		item->packetID = bes2600_queue_make_packet_id(
			queue_generation, queue_id, item_generation, item_id,
			if_id, link_id);

		list_move(&item->head, &queue->queue);

	}

	spin_unlock_bh(&queue->lock);
	return ret;
}


int bes2600_queue_requeue_all(struct bes2600_queue *queue)
{
	struct bes2600_queue_stats *stats = queue->stats;
	spin_lock_bh(&queue->lock);
	while (!list_empty(&queue->pending)) {
		struct bes2600_queue_item *item = list_entry(
			queue->pending.prev, struct bes2600_queue_item, head);

		--queue->num_pending;
		--queue->num_pending_vif[item->txpriv.if_id];
		++queue->link_map_cache[item->txpriv.if_id]
				[item->txpriv.link_id];

		spin_lock_bh(&stats->lock);
		++stats->num_queued[item->txpriv.if_id];
		++stats->link_map_cache[item->txpriv.if_id]
				[item->txpriv.link_id];
		spin_unlock_bh(&stats->lock);

		++item->generation;
		item->packetID = bes2600_queue_make_packet_id(
			queue->generation, queue->queue_id,
			item->generation, item - queue->pool,
			item->txpriv.if_id, item->txpriv.raw_link_id);
		list_move(&item->head, &queue->queue);
	}
	spin_unlock_bh(&queue->lock);

	return 0;
}
#ifdef CONFIG_BES2600_TESTMODE
int bes2600_queue_remove(struct bes2600_common *hw_priv,
				struct bes2600_queue *queue, u32 packetID)
#else
int bes2600_queue_remove(struct bes2600_queue *queue, u32 packetID)
#endif /*CONFIG_BES2600_TESTMODE*/
{
	int ret = 0;
	u8 queue_generation, queue_id, item_generation, item_id, if_id, link_id;
	struct bes2600_queue_item *item;
	struct bes2600_queue_stats *stats = queue->stats;
	struct sk_buff *gc_skb = NULL;
	struct bes2600_txpriv gc_txpriv;

	bes2600_queue_parse_id(packetID, &queue_generation, &queue_id,
				&item_generation, &item_id, &if_id, &link_id);

	item = &queue->pool[item_id];

	spin_lock_bh(&queue->lock);
	BUG_ON(queue_id != queue->queue_id);
	/*TODO:COMBO:Add check for interface ID also */
	if (unlikely(queue_generation != queue->generation)) {
		bes2600_info(BES2600_DBG_TXRX, "%s, Queue Generation is not equal\n", __func__);
		ret = 0;
	} else if (unlikely(item_id >= (unsigned) queue->capacity)) {
		WARN_ON(1);
		ret = -EINVAL;
	} else if (unlikely(item->generation != item_generation)) {
		WARN_ON(1);
		ret = -ENOENT;
	} else {
		gc_txpriv = item->txpriv;
		gc_skb = item->skb;
		item->skb = NULL;
		--queue->num_pending;
		--queue->num_pending_vif[if_id];
		--queue->num_queued;
		--queue->num_queued_vif[if_id];
		++queue->num_sent;
		++item->generation;
#ifdef CONFIG_BES2600_TESTMODE
		spin_lock_bh(&hw_priv->tsm_lock);
		if (hw_priv->start_stop_tsm.start) {
			if (queue_id == hw_priv->tsm_info.ac) {
				struct timeval tmval;
				unsigned long queue_delay;
				unsigned long media_delay;
				do_gettimeofday(&tmval);

				if (tmval.tv_usec > item->qdelay_timestamp)
					queue_delay = tmval.tv_usec -
						item->qdelay_timestamp;
				else
					queue_delay = tmval.tv_usec +
					1000000 - item->qdelay_timestamp;

				if (tmval.tv_usec > item->mdelay_timestamp)
					media_delay = tmval.tv_usec -
						item->mdelay_timestamp;
				else
					media_delay = tmval.tv_usec +
					1000000 - item->mdelay_timestamp;
				hw_priv->tsm_info.sum_media_delay +=
							media_delay;
				hw_priv->tsm_info.sum_pkt_q_delay += queue_delay;
				if (queue_delay <= 10000)
					hw_priv->tsm_stats.bin0++;
				else if (queue_delay <= 20000)
					hw_priv->tsm_stats.bin1++;
				else if (queue_delay <= 40000)
					hw_priv->tsm_stats.bin2++;
				else
					hw_priv->tsm_stats.bin3++;
			}
		}
		spin_unlock_bh(&hw_priv->tsm_lock);
#endif /*CONFIG_BES2600_TESTMODE*/
		/* Do not use list_move_tail here, but list_move:
		 * try to utilize cache row.
		 */
		list_move(&item->head, &queue->free_pool);

		if (unlikely(queue->overfull) &&
		    (queue->num_queued <= ((stats->hw_priv->vif0_throttle + stats->hw_priv->vif1_throttle + 2) / 2))) {
			queue->overfull = false;
			__bes2600_queue_unlock(queue);
		}
	}
	spin_unlock_bh(&queue->lock);

#if 0
	bes2600_dbg(BES2600_DBG_TXRX, "queue_drop queue %d, %d, %d\n",
		queue->num_queued, queue->link_map_cache[if_id][0],
		queue->num_pending);
	bes2600_dbg(BES2600_DBG_TXRX, "queue_drop stats %d, %d\n", stats->num_queued,
		stats->link_map_cache[if_id][0]);
#endif
	if (gc_skb)
		stats->skb_dtor(stats->hw_priv, gc_skb, &gc_txpriv);

	return ret;
}

int bes2600_queue_get_skb(struct bes2600_queue *queue, u32 packetID,
			 struct sk_buff **skb,
			 const struct bes2600_txpriv **txpriv)
{
	int ret = 0;
	u8 queue_generation, queue_id, item_generation, item_id, if_id, link_id;
	struct bes2600_queue_item *item;

	bes2600_queue_parse_id(packetID, &queue_generation, &queue_id,
				&item_generation, &item_id, &if_id, &link_id);

	item = &queue->pool[item_id];

	spin_lock_bh(&queue->lock);
	BUG_ON(queue_id != queue->queue_id);
	/* TODO:COMBO: Add check for interface ID here */
	if (unlikely(queue_generation != queue->generation)) {
		bes2600_info(BES2600_DBG_TXRX, "%s, Queue Generation is not equal\n", __func__);
		ret = -EINVAL;
	} else if (unlikely(item_id >= (unsigned) queue->capacity)) {
		WARN_ON(1);
		ret = -EINVAL;
	} else if (unlikely(item->generation != item_generation)) {
		bes2600_info(BES2600_DBG_TXRX, "%s, item_generation =%u, item_id =%u link_id=%u queue_generation =%u packetID =%u\n",
			__func__, item_generation, item_id, link_id, queue_generation, packetID);
		WARN_ON(1);
		ret = -ENOENT;
	} else {
		*skb = item->skb;
		*txpriv = &item->txpriv;
	}
	spin_unlock_bh(&queue->lock);
	return ret;
}

void bes2600_queue_lock(struct bes2600_queue *queue)
{
	spin_lock_bh(&queue->lock);
	__bes2600_queue_lock(queue);
	spin_unlock_bh(&queue->lock);
}

void bes2600_queue_unlock(struct bes2600_queue *queue)
{
	spin_lock_bh(&queue->lock);
	__bes2600_queue_unlock(queue);
	spin_unlock_bh(&queue->lock);
}

bool bes2600_queue_get_xmit_timestamp(struct bes2600_queue *queue,
				     unsigned long *timestamp, int if_id,
				     u32 pending_frameID)
{
	struct bes2600_queue_item *item;
	bool ret;

	spin_lock_bh(&queue->lock);
	ret = !list_empty(&queue->pending);
	if (ret) {
		list_for_each_entry(item, &queue->pending, head) {
			if (((if_id == CW12XX_GENERIC_IF_ID) ||
				(if_id == CW12XX_ALL_IFS) ||
					(item->txpriv.if_id == if_id)) &&
					(item->packetID != pending_frameID)) {
				if (time_before(item->xmit_timestamp,
							*timestamp))
					*timestamp = item->xmit_timestamp;
			}
		}
	}
	spin_unlock_bh(&queue->lock);
	return ret;
}

bool bes2600_queue_stats_is_empty(struct bes2600_queue_stats *stats,
				 u32 link_id_map, int if_id)
{
	bool empty = true;

	spin_lock_bh(&stats->lock);
	if (link_id_map == (u32)-1)
		empty = stats->num_queued[if_id] == 0;
	else {
		int i, if_id;
		for (if_id = 0; if_id < CW12XX_MAX_VIFS; if_id++) {
			for (i = 0; i < stats->map_capacity; ++i) {
				if (link_id_map & BIT(i)) {
					if (stats->link_map_cache[if_id][i]) {
						empty = false;
						break;
					}
				}
			}
		}
	}
	spin_unlock_bh(&stats->lock);

	return empty;
}

void bes2600_queue_iterate_pending_packet(struct bes2600_queue *queue,
	void (*iterate_cb)(struct bes2600_common *hw_priv, struct sk_buff *skb))
{
	struct bes2600_queue_item *item = NULL;

	list_for_each_entry(item, &queue->pending, head) {
		iterate_cb(queue->stats->hw_priv, item->skb);
	}
}