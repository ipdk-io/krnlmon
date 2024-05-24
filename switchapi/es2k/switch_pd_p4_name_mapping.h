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

#ifndef __SWITCH_PD_P4_NAME_MAPPING__
#define __SWITCH_PD_P4_NAME_MAPPING__

#define LNW_KEY_MATCH_PRIORITY "$MATCH_PRIORITY"

/* List of tables and corresponding actions */

/* VXLAN_ENCAP_MOD_TABLE */
#define LNW_VXLAN_ENCAP_MOD_TABLE \
  "linux_networking_control.vxlan_encap_mod_table"

#define LNW_VXLAN_ENCAP_MOD_TABLE_KEY_VENDORMETA_MOD_DATA_PTR \
  "vmeta.common.mod_blob_ptr"

#define LNW_VXLAN_ENCAP_MOD_TABLE_ACTION_VXLAN_ENCAP \
  "linux_networking_control.vxlan_encap"
#define LNW_ACTION_VXLAN_ENCAP_PARAM_SRC_ADDR "src_addr"
#define LNW_ACTION_VXLAN_ENCAP_PARAM_DST_ADDR "dst_addr"
#define LNW_ACTION_VXLAN_ENCAP_PARAM_DST_PORT "dst_port"
#define LNW_ACTION_VXLAN_ENCAP_PARAM_VNI "vni"

/* VXLAN_DECAP_MOD_TABLE */
#define LNW_VXLAN_DECAP_MOD_TABLE \
  "linux_networking_control.vxlan_decap_mod_table"

#define LNW_VXLAN_DECAP_MOD_TABLE_KEY_VENDORMETA_MOD_DATA_PTR \
  "vmeta.common.mod_blob_ptr"

#define LNW_VXLAN_DECAP_MOD_TABLE_ACTION_VXLAN_DECAP_OUTER_IPV4 \
  "linux_networking_control.vxlan_decap_outer_ipv4"

/* RIF_MOD_TABLE */
// Verified for MEV - 3 tables instead of 1
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

/* IPV4_TUNNEL_TERM_TABLE */
// Verified for MEV
#define LNW_IPV4_TUNNEL_TERM_TABLE \
  "linux_networking_control.ipv4_tunnel_term_table"
#define LNW_IPV4_TUNNEL_TERM_TABLE_KEY_TUNNEL_FLAG_TYPE \
  "user_meta.pmeta.tun_flag1_d0"
#define LNW_IPV4_TUNNEL_TERM_TABLE_KEY_IPV4_SRC "ipv4_src"
#define LNW_IPV4_TUNNEL_TERM_TABLE_KEY_IPV4_DST "ipv4_dst"

#define LNW_IPV4_TUNNEL_TERM_TABLE_ACTION_DECAP_OUTER_IPV4 \
  "linux_networking_control.decap_outer_ipv4"
#define LNW_ACTION_DECAP_OUTER_IPV4_PARAM_TUNNEL_ID "tunnel_id"

/* L2_FWD_RX_TABLE */
#define LNW_L2_FWD_RX_TABLE "linux_networking_control.l2_fwd_rx_table"

#define LNW_L2_FWD_RX_TABLE_KEY_DST_MAC "dst_mac"

#define LNW_L2_FWD_RX_TABLE_KEY_BRIDGE_ID "user_meta.pmeta.bridge_id"

#define LNW_L2_FWD_RX_TABLE_KEY_SMAC_LEARNED "user_meta.pmeta.smac_learned"

#define LNW_L2_FWD_RX_TABLE_ACTION_L2_FWD "linux_networking_control.l2_fwd"
#define LNW_ACTION_L2_FWD_PARAM_PORT "port"
#define LNW_L2_FWD_RX_TABLE_ACTION_RX_L2_FWD_LAG_AND_RECIRCULATE \
  "linux_networking_control.l2_fwd_lag_and_recirculate"
#define LNW_ACTION_RX_L2_FWD_LAG_PARAM_LAG_ID "lag_group_id"

/* RX_LAG_TABLE */
#define LNW_RX_LAG_TABLE "linux_networking_control.rx_lag_table"

#define LNW_RX_LAG_TABLE_KEY_PORT_ID "vmeta.common.port_id"
#define LNW_RX_LAG_TABLE_KEY_LAG_ID "user_meta.cmeta.lag_group_id"

#define LNW_RX_LAG_TABLE_ACTION_FWD_TO_VSI "linux_networking_control.fwd_to_vsi"
#define LNW_ACTION_FWD_TO_VSI_PARAM_PORT "port"

// NOP TODO
/* L2_FWD_RX_WITH_TUNNEL_TABLE */
#define LNW_L2_FWD_RX_WITH_TUNNEL_TABLE \
  "linux_networking_control.l2_fwd_rx_with_tunnel_table"

#define LNW_L2_FWD_RX_WITH_TUNNEL_TABLE_KEY_DST_MAC "dst_mac"

#define LNW_L2_FWD_RX_WITH_TUNNEL_TABLE_ACTION_L2_FWD \
  "linux_networking_control.l2_fwd"

// NOP TODO
/* L2_FWD_TX_TABLE */
#define LNW_L2_FWD_TX_TABLE "linux_networking_control.l2_fwd_tx_table"
#define LNW_L2_FWD_TX_TABLE_KEY_BRIDGE_ID "user_meta.pmeta.bridge_id"
#define LNW_L2_FWD_TX_TABLE_KEY_DST_MAC "dst_mac"

#define LNW_L2_FWD_TX_TABLE_ACTION_L2_FWD "linux_networking_control.l2_fwd"

#define LNW_L2_FWD_TX_TABLE_ACTION_L2_FWD_LAG \
  "linux_networking_control.l2_fwd_lag"
#define LNW_ACTION_L2_FWD_LAG_PARAM_LAG_ID "lag_group_id"

#define LNW_L2_FWD_TX_TABLE_ACTION_SET_TUNNEL \
  "linux_networking_control.set_tunnel"
#define LNW_ACTION_SET_TUNNEL_PARAM_TUNNEL_ID "tunnel_id"
#define LNW_ACTION_SET_TUNNEL_PARAM_DST_ADDR "dst_addr"

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

// TODO_LNW_MEV: One additional key for MEV(ipv4_table has 2 keys for MEV)
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

// TODO_LNW_MEV: One additional key for MEV(ipv6_table has 2 keys for MEV)
#define LNW_IPV6_TABLE_KEY_IPV6_TABLE_LPM_ROOT "ipv6_table_lpm_root"

#define LNW_IPV6_TABLE_KEY_IPV6_DST_MATCH "ipv6_dst_match"

#define LNW_IPV6_TABLE_ACTION_IPV6_SET_NEXTHOP_ID \
  "linux_networking_control.ipv6_set_nexthop_id"

#define LNW_IPV6_TABLE_ACTION_IPV6_SET_NEXTHOP_ID_WITH_MIRROR \
  "linux_networking_control.ipv6_set_nexthop_id_with_mirror"

#define LNW_IPV6_TABLE_ACTION_ECMP_V6_HASH_ACTION \
  "linux_networking_control.ecmp_v6_hash_action"

/* LNW_HANDLE_TX_ACC_VSI TABLE */
#define LNW_TX_ACC_VSI_TABLE "linux_networking_control.tx_acc_vsi"

#define LNW_TX_ACC_VSI_TABLE_KEY_META_COMMON_VSI "vmeta.common.vsi"

#define LNW_TX_ACC_VSI_TABLE_KEY_ZERO_PADDING "zero_padding"

#define LNW_TX_ACC_VSI_TABLE_ACTION_L2_FWD_AND_BYPASS_BRIDGE \
  "linux_networking_control.l2_fwd_and_bypass_bridge"

#define ACTION_L2_FWD_AND_BYPASS_BRIDGE_PARAM_PORT "port"

/* LNW_SOURCE_PORT_TO_BRIDGE_MAP TABLE */
#define LNW_SOURCE_PORT_TO_BRIDGE_MAP_TABLE \
  "linux_networking_control.source_port_to_bridge_map"

#define LNW_SOURCE_PORT_TO_BRIDGE_MAP_TABLE_KEY_SOURCE_PORT \
  "user_meta.cmeta.source_port"

#define LNW_SOURCE_PORT_TO_BRIDGE_MAP_TABLE_KEY_VID \
  "hdrs.vlan_ext[vmeta.common.depth].hdr.vid"

#define LNW_SOURCE_PORT_TO_BRIDGE_MAP_TABLE_ACTION_SET_BRIDGE_ID \
  "linux_networking_control.set_bridge_id"

#define LNW_SOURCE_PORT_TO_BRIDGE_MAP_TABLE_ACTION_PARAM_BRIDGE_ID "bridge_id"

#endif /* __SWITCH_PD_P4_NAME_MAPPING__ */
