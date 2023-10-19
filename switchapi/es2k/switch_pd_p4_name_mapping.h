/*
 * Copyright (c) 2013-2021 Barefoot Networks, Inc.
 * Copyright 2022-2023 Intel Corporation.
 *
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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

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

/* NEIGHBOR_MOD_TABLE */
#define LNW_NEIGHBOR_MOD_TABLE "linux_networking_control.neighbor_mod_table"

#define LNW_NEIGHBOR_MOD_TABLE_KEY_VENDORMETA_MOD_DATA_PTR \
  "vmeta.common.mod_blob_ptr"

#define LNW_NEIGHBOR_MOD_TABLE_ACTION_SET_OUTER_MAC \
  "linux_networking_control.set_outer_mac"
#define LNW_ACTION_SET_OUTER_MAC_PARAM_DST_MAC_ADDR "dst_mac_addr"

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

#define LNW_L2_FWD_RX_TABLE_ACTION_L2_FWD "linux_networking_control.l2_fwd"
#define LNW_ACTION_L2_FWD_PARAM_PORT "port"
#define LNW_L2_FWD_RX_TABLE_ACTION_RX_L2_FWD_LAG \
  "linux_networking_control.rx_l2_fwd_lag"
#define LNW_ACTION_RX_L2_FWD_LAG_PARAM_LAG_ID "lag_group_id"

/* RX_LAG_TABLE */
#define LNW_RX_LAG_TABLE "linux_networking_control.rx_lag_table"

#define LNW_RX_LAG_TABLE_KEY_PORT_ID "vmeta.common.port_id"
#define LNW_RX_LAG_TABLE_KEY_LAG_ID "user_meta.cmeta.lag_group_id"

#define LNW_RX_LAG_TABLE_ACTION_SET_EGRESS_PORT \
  "linux_networking_control.set_egress_port"
#define LNW_ACTION_SET_EGRESS_PORT_PARAM_EGRESS_PORT "egress_port"

/* L2_FWD_RX_WITH_TUNNEL_TABLE */
#define LNW_L2_FWD_RX_WITH_TUNNEL_TABLE \
  "linux_networking_control.l2_fwd_rx_with_tunnel_table"

#define LNW_L2_FWD_RX_WITH_TUNNEL_TABLE_KEY_DST_MAC "dst_mac"

#define LNW_L2_FWD_RX_WITH_TUNNEL_TABLE_ACTION_L2_FWD \
  "linux_networking_control.l2_fwd"

/* L2_FWD_TX_TABLE */
#define LNW_L2_FWD_TX_TABLE "linux_networking_control.l2_fwd_tx_table"
#define LNW_L2_FWD_TX_TABLE_KEY_DST_MAC "dst_mac"
#define LNW_L2_FWD_TX_TABLE_KEY_TUN_FLAG "user_meta.pmeta.tun_flag1_d0"

#define LNW_L2_FWD_TX_TABLE_ACTION_L2_FWD "linux_networking_control.l2_fwd"

#define LNW_L2_FWD_TX_TABLE_ACTION_L2_FWD_LAG \
  "linux_networking_control.l2_fwd_lag"
#define LNW_ACTION_L2_FWD_LAG_PARAM_LAG_ID "lag_group_id"

#define LNW_L2_FWD_TX_TABLE_ACTION_SET_TUNNEL \
  "linux_networking_control.set_tunnel"
#define LNW_ACTION_SET_TUNNEL_PARAM_TUNNEL_ID "tunnel_id"
#define LNW_ACTION_SET_TUNNEL_PARAM_DST_ADDR "dst_addr"

/* L2_FWD_TX_TABLE */
#define LNW_L2_FWD_TX_IPV6_TABLE "linux_networking_control.l2_fwd_tx_ipv6_table"
#define LNW_L2_FWD_TX_IPV6_TABLE_KEY_DST_MAC "dst_mac"
#define LNW_L2_FWD_TX_IPV6_TABLE_KEY_TUN_FLAG "user_meta.pmeta.tun_flag1_d0"

#define LNW_L2_FWD_TX_IPV6_TABLE_ACTION_L2_FWD "linux_networking_control.l2_fwd"

#define LNW_L2_FWD_TX_IPV6_TABLE_ACTION_L2_FWD_LAG \
  "linux_networking_control.l2_fwd_lag"

/* NEXTHOP_TABLE */
// Verified for MEV
#define LNW_NEXTHOP_TABLE "linux_networking_control.nexthop_table"

#define LNW_NEXTHOP_TABLE_KEY_NEXTHOP_ID "user_meta.cmeta.nexthop_id"
#define LNW_NEXTHOP_TABLE_KEY_BIT32_ZEROS "user_meta.cmeta.bit32_zeros"

#define LNW_NEXTHOP_TABLE_ACTION_SET_NEXTHOP \
  "linux_networking_control.set_nexthop"
#define LNW_ACTION_SET_NEXTHOP_PARAM_RIF "router_interface_id"
#define LNW_ACTION_SET_NEXTHOP_PARAM_NEIGHBOR_ID "neighbor_id"
#define LNW_ACTION_SET_NEXTHOP_PARAM_EGRESS_PORT "egress_port"

#define LNW_NEXTHOP_TABLE_ACTION_SET_NEXTHOP_LAG \
  "linux_networking_control.set_nexthop_lag"
#define LNW_ACTION_SET_NEXTHOP_LAG_PARAM_RIF "router_interface_id"
#define LNW_ACTION_SET_NEXTHOP_LAG_PARAM_NEIGHBOR_ID "neighbor_id"
#define LNW_ACTION_SET_NEXTHOP_LAG_PARAM_LAG_ID "lag_group_id"

/* ECMP_HASH_TABLE */
#define LNW_ECMP_HASH_TABLE "linux_networking_control.ecmp_hash_table"

#define LNW_ECMP_HASH_TABLE_KEY_HOST_INFO_TX_EXT_FLEX \
  "user_meta.cmeta.flex[15:0]"
#define LNW_ECMP_HASH_TABLE_KEY_META_COMMON_HASH "vmeta.common.hash[2:0]"
#define LNW_ECMP_HASH_TABLE_KEY_USER_META_BIT32_ZEROS \
  "user_meta.cmeta.bit32_zeros[15:3]"

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

/* SEM_BYPASS TABLE */
#define LNW_SEM_BYPASS_TABLE "linux_networking_control.sem_bypass"

#define LNW_SEM_BYPASS_TABLE_KEY_DST_MAC "dst_mac"

#define LNW_SEM_BYPASS_TABLE_ACTION_SET_DEST "linux_networking_control.set_dest"

#define LNW_ACTION_SET_DEST_PARAM_PORT_ID "port_id"

/* HANDLE_TX_FROM_HOST_TO_OVS_AND_OVS_TO_WIRE_TABLE */
#define LNW_HANDLE_TX_FROM_HOST_TO_OVS_AND_OVS_TO_WIRE_TABLE \
  "linux_networking_control.handle_tx_from_host_to_ovs_and_ovs_to_wire_table"

#define LNW_HANDLE_OVS_TO_WIRE_TABLE_KEY_META_COMMON_VSI "vmeta.common.vsi"

#define LNW_HANDLE_OVS_TO_WIRE_TABLE_KEY_USER_META_BIT32_ZEROS \
  "user_meta.cmeta.bit32_zeros"

#define LNW_HANDLE_OVS_TO_WIRE_TABLE_ACTION_SET_DEST \
  "linux_networking_control.set_dest"

#define LNW_HANDLE_OVS_TO_WIRE_TABLE_ACTION_SET_DEST_PARAM_PORT_ID "port_id"

#ifdef __cplusplus
}
#endif

#endif /* __SWITCH_PD_P4_NAME_MAPPING__ */
