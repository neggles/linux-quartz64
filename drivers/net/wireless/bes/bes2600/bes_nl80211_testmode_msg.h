/*
 * Mac80211 driver for BES2600 device
 *
 * Copyright (c) 2010, Bestechnic
 * Author:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef BES_NL80211_TESTMODE_MSG_H
#define BES_NL80211_TESTMODE_MSG_H

/* example command structure for test purposes */
struct bes_msg_test_t {
	int dummy;
};

/* example reply structure for test purposes */
struct bes_reply_test_t {
	int dummy;
};

/* example event structure for test purposes */
struct bes_event_test_t {
	int dummy;
};

/* vendor to mcu cmd msg reply structure */
struct vendor_rf_cmd_msg_reply {
	u32 id;
	u32 msg_len;
	char ret_msg[1028];
};

/* rf cmd msg reply assembly */
void bes2600_rf_cmd_msg_assembly(u32 cmd_type, void *data, u32 msg_len);
/* do rf cmd msg */
int bes2600_vendor_rf_cmd(struct ieee80211_hw *hw, struct ieee80211_vif *vif, u8 *data, int len);

enum bes_msg_id {
	BES_MSG_TEST = 0,	/* for test purposes */
	BES_MSG_EVENT_TEST,	/* for test purposes */
	BES_MSG_SET_SNAP_FRAME,
	BES_MSG_EVENT_FRAME_DATA,
#ifdef CONFIG_BES2600_TESTMODE
	BES_MSG_GET_TX_POWER_LEVEL,
	BES_MSG_GET_TX_POWER_RANGE,
	BES_MSG_SET_ADVANCE_SCAN_ELEMS,
	BES_MSG_SET_TX_QUEUE_PARAMS,
	BES_MSG_START_STOP_TSM,
	BES_MSG_GET_TSM_PARAMS,
	BES_MSG_GET_ROAM_DELAY,
#endif /*CONFIG_BES2600_TESTMODE*/
	BES_MSG_SET_POWER_SAVE,
#ifdef ROAM_OFFLOAD
	BES_MSG_NEW_SCAN_RESULTS,
#endif /* ROAM_OFFLOAD */
	BES_MSG_ADD_IP_OFFLOAD,
	BES_MSG_DEL_IP_OFFLOAD,
	BES_MSG_SET_IP_OFFLOAD_PERIOD,
	BES_MSG_VENDOR_RF_CMD,
	BES_MSG_SAVE_CALI_TXT_TO_FLASH,
	BES_MSG_EPTA_PARM_CONFIG,
	/* Add new IDs here */

	BES_MSG_ID_MAX,
};

enum vendor_rf_cmd_type {
	VENDOR_RF_SIGNALING_CMD = 0,
	VENDOR_RF_NOSIGNALING_CMD,
	VENDOR_RF_GET_SAVE_FREQOFFSET_CMD,
	VENDOR_RF_GET_SAVE_POWERLEVEL_CMD,
	VENDOR_RF_SAVE_FREQOFFSET_CMD,
	VENDOR_RF_SAVE_POWERLEVEL_CMD,
	VENDOR_RF_POWER_CALIB_FINISH,
	/* add new here */

	VENDOR_RF_CMD_MAX,

	VENDOR_RF_SIG_NOSIG_MIX = 0xFFFFFFFF,
};

enum bes_nl80211_testmode_data_attributes {
	BES_TM_MSG_ID = 0x0001,	/* u32 type containing the BES message ID */
	BES_TM_MSG_DATA,	/* message payload */

	/* Max indicator so module test may add its own attributes */
	BES_TM_MSG_ATTR_MAX,
};

/**
 * bes_msg_set_snap_frame - set SNAP frame format
 * @len: length of SNAP frame, if 0 SNAP frame disabled
 * @frame: SNAP frame format
 *
 * In this structure is difference between user space because
 * format and length have to be hidden
 *
 */
struct bes_msg_set_snap_frame {
	u8 len;
	u8 frame[0];
};

struct vendor_epta_parm {
	int wlan_duration;
	int bt_duration;
	int hw_epta_enable;
};

#ifdef CONFIG_BES2600_TESTMODE
/**
 * bes_msg_set_txqueue_params - store Tx queue params
 * @user_priority: User priority for which TSPEC negotiated
 * @medium_time: Allowed medium time
 * @expiry_time: The expiry time of MSDU
 *
 */
struct bes_msg_set_txqueue_params {
	u8 user_priority;
	u16 medium_time;
	u16 expiry_time;
};

/**
 * bes_tsm_stats - To retrieve the Transmit Stream Measurement stats
 * @actual_msrmt_start_time: The TSF at the time at which the measurement
 * started
 * @msrmt_duration: Duration for measurement
 * @peer_sta_addr: Peer STA address
 * @tid: TID for which measurements were made
 * @reporting_reason: Reason for report sent
 * @txed_msdu_count: The number of MSDUs transmitted for the specified TID
 * @msdu_discarded_count: The number of discarded MSDUs for the specified TID
 * @msdu_failed_count: The number of failed MSDUs for the specified TID
 * @multi_retry_count: The number of MSDUs which were retried
 * @qos_cfpolls_lost_count: The number of QOS CF polls frames lost
 * @avg_q_delay: Average queue delay
 * @avg_transmit_delay: Average transmit delay
 * @bin0_range: Delay range of the first bin (Bin 0)
 * @bin0: bin0 transmit delay histogram
 * @bin1: bin1 transmit delay histogram
 * @bin2: bin2 transmit delay histogram
 * @bin3: bin3 transmit delay histogram
 * @bin4: bin4 transmit delay histogram
 * @bin5: bin5 transmit delay histogram
 *
 */
struct bes_tsm_stats {
	u64 actual_msrmt_start_time;
	u16 msrmt_duration;
	u8 peer_sta_addr[6];
	u8 tid;
	u8 reporting_reason;
	u32 txed_msdu_count;
	u32 msdu_discarded_count;
	u32 msdu_failed_count;
	u32 multi_retry_count;
	u32 qos_cfpolls_lost_count;
	u32 avg_q_delay;
	u32 avg_transmit_delay;
	u8 bin0_range;
	u32 bin0;
	u32 bin1;
	u32 bin2;
	u32 bin3;
	u32 bin4;
	u32 bin5;
} __packed;


/**
 * bes_msg_set_start_stop_tsm - To start or stop collecting TSM metrics in
 * bes2600 driver
 * @start: To start or stop collecting TSM metrics
 * @up: up for which metrics to be collected
 * @packetization_delay: Packetization period for this TID
 *
 */
struct bes_msg_start_stop_tsm {
	u8 start;	/*1: To start, 0: To stop*/
	u8 up;
	u16 packetization_delay;
};

/**
 * power_save_elems - To enable/disable legacy power Save
 */
struct power_save_elems {
	int powerSave;
};

#ifdef CONFIG_BES2600_KEEP_ALIVE
/*
 * ip keep alive feature's parameters
 * @idx add(idx=15) a tcp/udp keep alive stream, or the idx number(idx= 0-7) when reconfig one;
 *      set payload_len to 0 and payload to NULL when deleting one stream.
 * @klv_vendor different number stands for different vendor's keepalive configuration
 * @period: alive period
 * @proto 0 for udp and 1 for tcp
 * @src_port local port
 * @dst_port tcp server's listen port
 * @src_ip local ip address
 * @dst_ip tcp server's ip address
 * @key: key
 * @iv: iv
 * @payload payload of the keep alive packet
 * @payload_len length of the payload
 */
struct ip_alive_paras {
	uint16_t idx;
	uint8_t klv_vendor;
	uint8_t period;
	uint8_t proto;
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t src_ip;
	uint32_t dst_ip;
	uint8_t key[16];
	uint8_t iv[16];
	uint16_t payload_len;
	uint8_t payload[0];
};

/**
 * ip_alive_tac_idx - idx of tcp & udp alive stream
 */
struct ip_alive_iac_idx {
    int idx;
};

/**
 * ip_alive_period - tcp & udp alive period
 */
struct ip_alive_period {
    int period;
};
#endif /* CONFIG_BES2600_KEEP_ALIVE */

#endif /* CONFIG_BES2600_TESTMODE */

#define BES_TM_MAX_ATTRIB_SIZE 1024

#endif /* BES_NL80211_TESTMODE_MSG_H*/
