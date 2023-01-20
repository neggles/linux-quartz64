/*
 * O(1) TX queue with built-in allocator for BES2600 drivers
 *
 * Copyright (c) 2010, Bestechnic
 * Author:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef BES2600_QUEUE_H_INCLUDED
#define BES2600_QUEUE_H_INCLUDED

/* private */ struct bes2600_queue_item;

/* extern */ struct sk_buff;
/* extern */ struct wsm_tx;
/* extern */ struct bes2600_common;
/* extern */ struct bes2600_vif;
/* extern */ struct ieee80211_tx_queue_stats;
/* extern */ struct bes2600_txpriv;

/* forward */ struct bes2600_queue_stats;

typedef void (*bes2600_queue_skb_dtor_t)(struct bes2600_common *priv,
					struct sk_buff *skb,
					const struct bes2600_txpriv *txpriv);

struct bes2600_queue {
	struct bes2600_queue_stats *stats;
	size_t			capacity;
	size_t			num_queued;
	size_t			num_queued_vif[CW12XX_MAX_VIFS];
	size_t			num_pending;
	size_t			num_pending_vif[CW12XX_MAX_VIFS];
	size_t			num_sent;
	struct bes2600_queue_item *pool;
	struct list_head	queue;
	struct list_head	free_pool;
	struct list_head	pending;
	int			tx_locked_cnt;
	int			*link_map_cache[CW12XX_MAX_VIFS];
	bool			overfull;
	spinlock_t		lock;
	u8			queue_id;
	u8			generation;
	struct timer_list	gc;
	unsigned long		ttl;
};

struct bes2600_queue_stats {
	spinlock_t		lock;
	int			*link_map_cache[CW12XX_MAX_VIFS];
	int			num_queued[CW12XX_MAX_VIFS];
	size_t			map_capacity;
	wait_queue_head_t	wait_link_id_empty;
	bes2600_queue_skb_dtor_t	skb_dtor;
	struct bes2600_common	*hw_priv;
};

struct bes2600_txpriv {
	u8 link_id;
	u8 raw_link_id;
	u8 tid;
	u8 rate_id;
	u8 offset;
	u8 if_id;
#ifndef P2P_MULTIVIF
	u8 offchannel_if_id;
#else
	u8 raw_if_id;
#endif
	u8 retry_count;
};

int bes2600_queue_stats_init(struct bes2600_queue_stats *stats,
			    size_t map_capacity,
			    bes2600_queue_skb_dtor_t skb_dtor,
			    struct bes2600_common *priv);
int bes2600_queue_init(struct bes2600_queue *queue,
		      struct bes2600_queue_stats *stats,
		      u8 queue_id,
		      size_t capacity,
		      unsigned long ttl);
int bes2600_queue_clear(struct bes2600_queue *queue, int if_id);
void bes2600_queue_stats_deinit(struct bes2600_queue_stats *stats);
void bes2600_queue_deinit(struct bes2600_queue *queue);

size_t bes2600_queue_get_num_queued(struct bes2600_vif *priv,
				   struct bes2600_queue *queue,
				   u32 link_id_map);
int bes2600_queue_put(struct bes2600_queue *queue,
		     struct sk_buff *skb,
		     struct bes2600_txpriv *txpriv);
int bes2600_queue_get(struct bes2600_queue *queue,
			int if_id,
		     u32 link_id_map,
		     struct wsm_tx **tx,
		     struct ieee80211_tx_info **tx_info,
		     struct bes2600_txpriv **txpriv);
#ifdef CONFIG_BES2600_TESTMODE
int bes2600_queue_requeue(struct bes2600_common *hw_priv,
			struct bes2600_queue *queue,
			u32 packetID, bool check);
#else
int bes2600_queue_requeue(struct bes2600_queue *queue, u32 packetID, bool check);
#endif
int bes2600_queue_requeue_all(struct bes2600_queue *queue);
#ifdef CONFIG_BES2600_TESTMODE
int bes2600_queue_remove(struct bes2600_common *hw_priv,
			struct bes2600_queue *queue,
			u32 packetID);
#else
int bes2600_queue_remove(struct bes2600_queue *queue,
			u32 packetID);
#endif /*CONFIG_BES2600_TESTMODE*/
int bes2600_queue_get_skb(struct bes2600_queue *queue, u32 packetID,
			 struct sk_buff **skb,
			 const struct bes2600_txpriv **txpriv);
void bes2600_queue_lock(struct bes2600_queue *queue);
void bes2600_queue_unlock(struct bes2600_queue *queue);
bool bes2600_queue_get_xmit_timestamp(struct bes2600_queue *queue,
				     unsigned long *timestamp, int if_id,
				     u32 pending_frameID);


bool bes2600_queue_stats_is_empty(struct bes2600_queue_stats *stats,
				 u32 link_id_map, int if_id);

static inline void bes2600_queue_parse_id(u32 packetID, u8 *queue_generation,
        u8 *queue_id,
         u8 *item_generation,
        u8 *item_id,
        u8 *if_id,
        u8 *link_id)
{
    *item_id        = (packetID >>  0) & 0xFF;
    *item_generation    = (packetID >>  8) & 0xFF;
    *queue_id       = (packetID >> 16) & 0xF;
    *if_id          = (packetID >> 20) & 0xF;
    *link_id        = (packetID >> 24) & 0xF;
    *queue_generation   = (packetID >> 28) & 0xF;
}
static inline u8 bes2600_queue_get_queue_id(u32 packetID)
{
	return (packetID >> 16) & 0xF;
}

static inline u8 bes2600_queue_get_if_id(u32 packetID)
{
	return (packetID >> 20) & 0xF;
}

static inline u8 bes2600_queue_get_link_id(u32 packetID)
{
	return (packetID >> 24) & 0xF;
}

static inline u8 bes2600_queue_get_generation(u32 packetID)
{
	return (packetID >>  8) & 0xFF;
}

int bes2600_queue_get_skb_and_timestamp(struct bes2600_queue *queue, u32 packetID,
			struct sk_buff **skb, struct bes2600_txpriv **txpriv,
			unsigned long *timestamp);
int bes2600_sw_retry_requeue(struct bes2600_common *hw_priv,
	struct bes2600_queue *queue, u32 packetID, bool check);
void bes2600_queue_iterate_pending_packet(struct bes2600_queue *queue,
	void (*iterate_cb)(struct bes2600_common *hw_priv, struct sk_buff *skb));

#endif /* BES2600_QUEUE_H_INCLUDED */
