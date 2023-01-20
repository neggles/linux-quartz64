/*
 *  HT-related code for BES2600 driver
 *
 * Copyright (c) 2010, Bestechnic
 * Author:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef BES2600_HT_H_INCLUDED
#define BES2600_HT_H_INCLUDED

#include <net/mac80211.h>

struct bes2600_ht_info {
	struct ieee80211_sta_ht_cap	ht_cap;
	enum nl80211_channel_type	channel_type;
	u16				operation_mode;
};

static inline int bes2600_is_ht(const struct bes2600_ht_info *ht_info)
{
	return ht_info->channel_type != NL80211_CHAN_NO_HT;
}

static inline int bes2600_ht_greenfield(const struct bes2600_ht_info *ht_info)
{
	return bes2600_is_ht(ht_info) &&
		(ht_info->ht_cap.cap & IEEE80211_HT_CAP_GRN_FLD) &&
		!(ht_info->operation_mode &
			IEEE80211_HT_OP_MODE_NON_GF_STA_PRSNT);
}

static inline int bes2600_ht_ampdu_density(const struct bes2600_ht_info *ht_info)
{
	if (!bes2600_is_ht(ht_info))
		return 0;
	return ht_info->ht_cap.ampdu_density;
}

#endif /* BES2600_HT_H_INCLUDED */
