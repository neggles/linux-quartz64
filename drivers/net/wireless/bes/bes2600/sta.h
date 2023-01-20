/*
 * Mac80211 STA interface for BES2600 mac80211 drivers
 *
 * Copyright (c) 2010, Bestechnic
 * Author:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/version.h>
#ifndef STA_H_INCLUDED
#define STA_H_INCLUDED

/* ******************************************************************** */
/* mac80211 API								*/

int bes2600_start(struct ieee80211_hw *dev);
void bes2600_stop(struct ieee80211_hw *dev);
int bes2600_add_interface(struct ieee80211_hw *dev,
			 struct ieee80211_vif *vif);
void bes2600_remove_interface(struct ieee80211_hw *dev,
			     struct ieee80211_vif *vif);
int bes2600_change_interface(struct ieee80211_hw *dev,
				struct ieee80211_vif *vif,
				enum nl80211_iftype new_type,
				bool p2p);

int bes2600_config(struct ieee80211_hw *dev, u32 changed);
int bes2600_change_interface(struct ieee80211_hw *dev,
                                struct ieee80211_vif *vif,
                                enum nl80211_iftype new_type,
                                bool p2p);
void bes2600_configure_filter(struct ieee80211_hw *dev,
			     unsigned int changed_flags,
			     unsigned int *total_flags,
			     u64 multicast);
int bes2600_conf_tx(struct ieee80211_hw *dev, struct ieee80211_vif *vif, unsigned int link_id,
		u16 queue, const struct ieee80211_tx_queue_params *params);
int bes2600_get_stats(struct ieee80211_hw *dev,
		     struct ieee80211_low_level_stats *stats);
/* Not more a part of interface?
int bes2600_get_tx_stats(struct ieee80211_hw *dev,
			struct ieee80211_tx_queue_stats *stats);
*/
int bes2600_set_key(struct ieee80211_hw *dev, enum set_key_cmd cmd,
		   struct ieee80211_vif *vif, struct ieee80211_sta *sta,
		   struct ieee80211_key_conf *key);

int bes2600_set_rts_threshold(struct ieee80211_hw *hw, u32 value);

void bes2600_flush(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		  u32 queues, bool drop);

int bes2600_remain_on_channel(struct ieee80211_hw *hw,
				 struct ieee80211_vif *vif,
				 struct ieee80211_channel *chan,
				 int duration,
				 enum ieee80211_roc_type type);

int bes2600_cancel_remain_on_channel(struct ieee80211_hw *hw
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
	, struct ieee80211_vif *vif
#endif
	);

int bes2600_set_arpreply(struct ieee80211_hw *hw, struct ieee80211_vif *vif);

u64 bes2600_prepare_multicast(struct ieee80211_hw *hw,
			     struct netdev_hw_addr_list *mc_list);

int bes2600_set_pm(struct bes2600_vif *priv, const struct wsm_set_pm *arg);

void bes2600_set_data_filter(struct ieee80211_hw *hw,
			   struct ieee80211_vif *vif,
			   void *data,
			   int len);
/* ******************************************************************** */
/* WSM callbacks							*/

/* void bes2600_set_pm_complete_cb(struct bes2600_common *hw_priv,
	struct wsm_set_pm_complete *arg); */
void bes2600_channel_switch_cb(struct bes2600_common *hw_priv);

/* ******************************************************************** */
/* WSM events								*/

void bes2600_free_event_queue(struct bes2600_common *hw_priv);
void bes2600_event_handler(struct work_struct *work);
void bes2600_bss_loss_work(struct work_struct *work);
void bes2600_connection_loss_work(struct work_struct *work);
void bes2600_keep_alive_work(struct work_struct *work);
void bes2600_tx_failure_work(struct work_struct *work);
void bes2600_dynamic_opt_txrx_work(struct work_struct *work);

/* ******************************************************************** */
/* Internal API								*/

int bes2600_setup_mac(struct bes2600_common *hw_priv);
void bes2600_join_work(struct work_struct *work);
void bes2600_join_timeout(struct work_struct *work);
void bes2600_unjoin_work(struct work_struct *work);
void bes2600_offchannel_work(struct work_struct *work);
void bes2600_wep_key_work(struct work_struct *work);
void bes2600_update_filtering(struct bes2600_vif *priv);
void bes2600_update_filtering_work(struct work_struct *work);
int __bes2600_flush(struct bes2600_common *hw_priv, bool drop, int if_id);
void bes2600_set_beacon_wakeup_period_work(struct work_struct *work);
int bes2600_enable_listening(struct bes2600_vif *priv,
			struct ieee80211_channel *chan);
int bes2600_disable_listening(struct bes2600_vif *priv);
int bes2600_set_uapsd_param(struct bes2600_vif *priv,
				const struct wsm_edca_params *arg);
void bes2600_ba_work(struct work_struct *work);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))
void bes2600_ba_timer(struct timer_list *t);
#else
void bes2600_ba_timer(unsigned long arg);
#endif
const u8 *bes2600_get_ie(u8 *start, size_t len, u8 ie);
int bes2600_vif_setup(struct bes2600_vif *priv);
int bes2600_setup_mac_pvif(struct bes2600_vif *priv);
void bes2600_iterate_vifs(void *data, u8 *mac,
			 struct ieee80211_vif *vif);
void bes2600_rem_chan_timeout(struct work_struct *work);
int bes2600_set_macaddrfilter(struct bes2600_common *hw_priv, struct bes2600_vif *priv, u8 *data);
#ifdef IPV6_FILTERING
int bes2600_set_na(struct ieee80211_hw *hw,
			struct ieee80211_vif *vif);
#endif /*IPV6_FILTERING*/
#ifdef CONFIG_BES2600_TESTMODE
void bes2600_device_power_calc(struct bes2600_common *priv,
			      s16 max_output_power, s16 fe_cor, u32 band);
int bes2600_testmode_cmd(struct ieee80211_hw *hw, struct ieee80211_vif *vif, void *data, int len);
int bes2600_testmode_event(struct wiphy *wiphy, const u32 msg_id,
			 const void *data, int len, gfp_t gfp);
int bes2600_get_tx_power_range(struct ieee80211_hw *hw);
int bes2600_get_tx_power_level(struct ieee80211_hw *hw);
#endif /* CONFIG_BES2600_TESTMODE */
#ifdef CONFIG_BES2600_WLAN_BES
int bes2600_wifi_start(struct bes2600_common *hw_priv);
int bes2600_wifi_stop(struct bes2600_common *hw_priv);
#endif


/**
 * tcp & udp alive
 */
#ifdef CONFIG_BES2600_KEEP_ALIVE
#define IP_KEEPALIVE_MAX_LEN	(256 + 8)
#define AES_KEY_IV_LEN			(16 + 16)
#define AES_KEY_LEN				(16)
#define AES_IV_LEN				(16)
#define NUM_IP_FRAMES			8
#define TCP_PROTO				6
#define UDP_PROTO 				17

#define KLV_VENDOR_DEFAULT		0
#define KLV_VENDOR_XM			1
#define WEBSOCKET_HD_LEN		6

#ifdef P2P_MULTIVIF
#define NET_DEVICE_NUM (3)
#else
#define NET_DEVICE_NUM (2)
#endif

struct ip_header {
	/* version / header length */
	uint8_t _v_hl;
	/* type of service */
	uint8_t _tos;
	/* total length */
	uint16_t _len;
	/* identification */
	uint16_t _id;
	/* fragment offset field */
	uint16_t _offset;
	/* time to live */
	uint8_t _ttl;
	/* protocol*/
	uint8_t _proto;
	/* checksum */
	uint16_t _chksum;
	/* source and destination IP addresses */
	uint32_t src;
	uint32_t dest;
} ;

struct tcp_header {
	uint16_t src;
	uint16_t dest;
	uint32_t seqno;
	uint32_t ackno;
	uint16_t _hdrlen_rsvd_flags;
	uint16_t wnd;
	uint16_t chksum;
	uint16_t urgp;
};

struct udp_header {
	uint16_t src;
	uint16_t dest;
	uint16_t len;
	uint16_t chksum;
};

struct ip_alive_info {
	uint8_t idx_used;
	uint8_t proto; /* 0 for udp and 1 for tcp; */
	uint16_t src_port;
	uint16_t dest_port;
	uint32_t src_ip;
	uint32_t dest_ip;
	uint16_t len;
	uint32_t next_seqno;
	uint8_t payload[IP_KEEPALIVE_MAX_LEN];
	uint8_t dest_mac[6];
};

struct ip_alive_cfg {
	struct ip_header iphd;
	struct tcp_header tcphd;
	struct udp_header udphd;
	struct ip_alive_info bd;
	uint8_t aes_key[AES_KEY_LEN];
	uint8_t aes_iv[AES_IV_LEN];
	uint8_t klv_vendor; /* stands for different vendor's keep-alive resolution; */
};

int bes2600_set_ip_offload(struct bes2600_common *hw_priv,
					    struct bes2600_vif *priv,
					    struct ip_alive_cfg *tac,
					    u16 idx);

int bes2600_del_ip_offload(struct bes2600_common *hw_priv,
					    struct bes2600_vif *priv,
					    u8 stream_idx);

int bes2600_en_ip_offload(struct bes2600_common *hw_priv,
					    struct bes2600_vif *priv,
					    u16 period_in_s);
int bes2600_set_ipv4addrfilter(struct bes2600_common *hw_priv, u8 *data, int if_id);
#endif /* CONFIG_BES2600_KEEP_ALIVE */

#endif /* STA_H_INCLUDED */
