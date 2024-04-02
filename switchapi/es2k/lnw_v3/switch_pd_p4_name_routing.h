/*
 * Copyright (c) 2013-2021 Barefoot Networks, Inc.
 * Copyright 2022-2024 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __SWITCH_PD_P4_NAME_ROUTING_MAPPING__
#define __SWITCH_PD_P4_NAME_ROUTING_MAPPING__

#define LNW_KEY_MATCH_PRIORITY "$MATCH_PRIORITY"
/* List of tables and corresponding actions */

/* RIF_MOD_TABLE */
// Verified for ES2K - 3 tables instead of 1
#define LNW_RIF_MOD_TABLE_START "linux_networking_control.rif_mod_table_start"

#define LNW_RIF_MOD_TABLE_START_KEY_RIF_MOD_MAP_ID0 "rif_mod_map_id0"

#define LNW_RIF_MOD_TABLE_START_ACTION_SET_SRC_MAC_START \
  "linux_networking_control.set_src_mac_start"

#define LNW_RIF_MOD_TABLE_MID "linux_networking_control.rif_mod_table_mid"

#define LNW_RIF_MOD_TABLE_MID_KEY_RIF_MOD_MAP_ID1 "rif_mod_map_id1"

#define LNW_RIF_MOD_TABLE_MID_ACTION_SET_SRC_MAC_MID \
  "linux_networking_control.set_src_mac_mid"

#define LNW_RIF_MOD_TABLE_LAST "linux_networking_control.rif_mod_table_last"

#define LNW_RIF_MOD_TABLE_LAST_KEY_RIF_MOD_MAP_ID2 "rif_mod_map_id2"

#define LNW_RIF_MOD_TABLE_LAST_ACTION_SET_SRC_MAC_LAST \
  "linux_networking_control.set_src_mac_last"

#define LNW_ACTION_SET_SRC_MAC_PARAM_SRC_MAC_ADDR "arg"

/* RX_LAG_TABLE */
#define LNW_RX_LAG_TABLE "linux_networking_control.rx_lag_table"

#define LNW_RX_LAG_TABLE_KEY_PORT_ID "vmeta.common.port_id"
#define LNW_RX_LAG_TABLE_KEY_LAG_ID "user_meta.cmeta.lag_group_id"

#define LNW_RX_LAG_TABLE_ACTION_FWD_TO_VSI "linux_networking_control.fwd_to_vsi"
#define LNW_ACTION_FWD_TO_VSI_PARAM_PORT "port"

/* NEXTHOP_TABLE */
// Verified for ES2K
#define LNW_NEXTHOP_TABLE "linux_networking_control.nexthop_table"

#define LNW_NEXTHOP_TABLE_KEY_NEXTHOP_ID "user_meta.cmeta.nexthop_id"

#define LNW_NEXTHOP_TABLE_ACTION_SET_NEXTHOP_INFO \
  "linux_networking_control.set_nexthop_info_dmac"
#define LNW_ACTION_SET_NEXTHOP_PARAM_RIF "router_interface_id"
#define LNW_ACTION_SET_NEXTHOP_PARAM_EGRESS_PORT "egress_port"
#define LNW_ACTION_SET_NEXTHOP_PARAM_DMAC_HIGH "dmac_high"
#define LNW_ACTION_SET_NEXTHOP_PARAM_DMAC_LOW "dmac_low"

#define LNW_NEXTHOP_TABLE_ACTION_SET_NEXTHOP_LAG \
  "linux_networking_control.set_nexthop_lag"
#define LNW_ACTION_SET_NEXTHOP_LAG_PARAM_RIF "router_interface_id"
#define LNW_ACTION_SET_NEXTHOP_LAG_PARAM_DMAC_HIGH "dmac_high"
#define LNW_ACTION_SET_NEXTHOP_LAG_PARAM_DMAC_LOW "dmac_low"
#define LNW_ACTION_SET_NEXTHOP_LAG_PARAM_LAG_ID "lag_group_id"

/* ECMP_NEXTHOP_TABLE */
// Verified for ES2K
#define LNW_ECMP_NEXTHOP_TABLE "linux_networking_control.ecmp_nexthop_table"

#define LNW_ECMP_NEXTHOP_TABLE_KEY_ECMP_NEXTHOP_ID "user_meta.cmeta.nexthop_id"

#define LNW_ECMP_NEXTHOP_TABLE_ACTION_SET_ECMP_NEXTHOP_INFO_DMAC \
  "linux_networking_control.ecmp_set_nexthop_info_dmac"
#define LNW_ACTION_SET_ECMP_NEXTHOP_PARAM_RIF "router_interface_id"
#define LNW_ACTION_SET_ECMP_NEXTHOP_PARAM_DMAC_HIGH "dmac_high"
#define LNW_ACTION_SET_ECMP_NEXTHOP_PARAM_DMAC_LOW "dmac_low"
#define LNW_ACTION_SET_ECMP_NEXTHOP_PARAM_EGRESS_PORT "egress_port"

/* ECMP_HASH_TABLE */
#define LNW_ECMP_HASH_TABLE "linux_networking_control.ecmp_hash_table"

#define LNW_ECMP_HASH_TABLE_KEY_HOST_INFO_TX_EXT_FLEX \
  "user_meta.cmeta.flex[15:0]"
#define LNW_ECMP_HASH_TABLE_KEY_META_COMMON_HASH "vmeta.common.hash[2:0]"
#define LNW_ECMP_HASH_TABLE_KEY_ZERO_PADDING "zero_padding"

#define LNW_ECMP_HASH_TABLE_ACTION_SET_NEXTHOP_ID \
  "linux_networking_control.set_nexthop_id"

#define LNW_ECMP_HASH_SIZE 65536

/* Only 3 bits is allocated for hash size per group in LNW.p4
 * check LNW_ECMP_HASH_TABLE_KEY_META_COMMON_HASH */
#define LNW_ECMP_PER_GROUP_HASH_SIZE 8

/* TX_LAG_TABLE */
#define LNW_TX_LAG_TABLE "linux_networking_control.tx_lag_table"

#define LNW_TX_LAG_TABLE_KEY_LAG_ID "user_meta.cmeta.lag_group_id"
#define LNW_TX_LAG_TABLE_KEY_VMETA_COMMON_HASH "hash"

#define LNW_TX_LAG_TABLE_ACTION_SET_EGRESS_PORT \
  "linux_networking_control.set_egress_port"

#define ACTION_SET_EGRESS_PORT_PARAM_EGRESS_PORT "egress_port"

#define LNW_LAG_HASH_SIZE 65536

/* Only 3 bits is allocated for hash size per group in LNW.p4
 * check LNW_TX_LAG_TABLE_KEY_VMETA_COMMON_HASH */
#define LNW_LAG_PER_GROUP_HASH_SIZE 8

/* IPV4_TABLE */
#define LNW_IPV4_TABLE "linux_networking_control.ipv4_table"

// TODO_LNW_ES2K: One additional key for ES2K(ipv4_table has 2 keys for ES2K)
#define LNW_IPV4_TABLE_KEY_IPV4_TABLE_LPM_ROOT "ipv4_table_lpm_root"

#define LNW_IPV4_TABLE_KEY_IPV4_DST_MATCH "ipv4_dst_match"

#define LNW_IPV4_TABLE_ACTION_IPV4_SET_NEXTHOP_ID \
  "linux_networking_control.ipv4_set_nexthop_id"
#define LNW_ACTION_SET_NEXTHOP_ID_PARAM_NEXTHOP_ID "nexthop_id"

#define LNW_IPV4_TABLE_ACTION_IPV4_SET_NEXTHOP_ID_WITH_MIRROR \
  "linux_networking_control.ipv4_set_nexthop_id_with_mirror"

#define LNW_IPV4_TABLE_ACTION_ECMP_HASH_ACTION \
  "linux_networking_control.ecmp_hash_action"
#define LNW_ACTION_ECMP_HASH_ACTION_PARAM_ECMP_GROUP_ID "ecmp_group_id"

/* IPV6_TABLE */
#define LNW_IPV6_TABLE "linux_networking_control.ipv6_table"

// TODO_LNW_ES2K: One additional key for ES2K(ipv6_table has 2 keys for ES2K)
#define LNW_IPV6_TABLE_KEY_IPV6_TABLE_LPM_ROOT "ipv6_table_lpm_root"

#define LNW_IPV6_TABLE_KEY_IPV6_DST_MATCH "ipv6_dst_match"

#define LNW_IPV6_TABLE_ACTION_IPV6_SET_NEXTHOP_ID \
  "linux_networking_control.ipv6_set_nexthop_id"

#define LNW_IPV6_TABLE_ACTION_IPV6_SET_NEXTHOP_ID_WITH_MIRROR \
  "linux_networking_control.ipv6_set_nexthop_id_with_mirror"

#define LNW_IPV6_TABLE_ACTION_ECMP_V6_HASH_ACTION \
  "linux_networking_control.ecmp_v6_hash_action"

#endif /* __SWITCH_PD_P4_NAME_ROUTING_MAPPING__ */
