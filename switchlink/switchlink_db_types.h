/*
 * Copyright 2013-present Barefoot Networks, Inc.
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

#ifndef __SWITCHLINK_DB_TYPES_H__
#define __SWITCHLINK_DB_TYPES_H__

#include <stdbool.h>
#include <stdint.h>

#include "switchlink_link_types.h"
#include "switchlink_types.h"

#define SWITCHLINK_INTERFACE_NAME_LEN_MAX 32
#define SWITCHLINK_ECMP_NUM_MEMBERS_MAX 16

typedef enum {
  SWITCHLINK_DB_STATUS_SUCCESS,
  SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND,
} switchlink_db_status_t;

typedef struct switchlink_db_tuntap_info_ {
  char ifname[SWITCHLINK_INTERFACE_NAME_LEN_MAX];
  uint32_t ifindex;
  switchlink_handle_t tunp_h;
  switchlink_mac_addr_t mac_addr;
  switchlink_link_type_t link_type;
  // struct tuntap_flags {
  // bool <?>_enabled;
  // uint8_t <?>_mode;
  //} flags;
} switchlink_db_tuntap_info_t;

typedef struct switchlink_db_interface_info_ {
  char ifname[SWITCHLINK_INTERFACE_NAME_LEN_MAX];
  uint32_t ifindex;
  uint16_t port_id;
  switchlink_handle_t intf_h;
  switchlink_intf_type_t intf_type;
  switchlink_link_type_t link_type;
  switchlink_handle_t vrf_h;
  switchlink_handle_t bridge_h;
  switchlink_handle_t stp_h;
  switchlink_handle_t lag_h;
  switchlink_handle_t vlan_member_h;
  switchlink_handle_t stp_port_h;
  switchlink_mac_addr_t mac_addr;
  switchlink_ip_addr_t intf_ip;
  struct interface_flags {
    bool ipv4_unicast_enabled;
    bool ipv6_unicast_enabled;
    bool ipv4_multicast_enabled;
    bool ipv6_multicast_enabled;
    uint8_t ipv4_urpf_mode;
    uint8_t ipv6_urpf_mode;
  } flags;
  // LAG attributes
  uint8_t bond_mode;
  uint8_t oper_state;
  uint32_t active_slave;
} switchlink_db_interface_info_t;

typedef struct switchlink_db_bridge_info_ {
  switchlink_handle_t bridge_h;
  switchlink_handle_t vrf_h;
  switchlink_handle_t stp_h;
  switchlink_mac_addr_t mac_addr;
} switchlink_db_bridge_info_t;

typedef struct switchlink_db_neigh_info_ {
  switchlink_handle_t vrf_h;
  switchlink_handle_t nhop_h;
  switchlink_handle_t intf_h;
  switchlink_ip_addr_t ip_addr;
  switchlink_mac_addr_t mac_addr;
} switchlink_db_neigh_info_t;

typedef struct switchlink_db_nexthop_info_ {
  switchlink_handle_t vrf_h;
  switchlink_handle_t nhop_h;
#if defined(DPDK_TARGET)
  switchlink_handle_t nhop_member_h;
#endif
  switchlink_handle_t intf_h;
  switchlink_ip_addr_t ip_addr;
  uint32_t using_by;
} switchlink_db_nexthop_info_t;

typedef struct switchlink_db_ecmp_info_ {
  switchlink_handle_t ecmp_h;
  uint8_t num_nhops;
  switchlink_handle_t nhops[SWITCHLINK_ECMP_NUM_MEMBERS_MAX];
  switchlink_handle_t nhop_member_handles[SWITCHLINK_ECMP_NUM_MEMBERS_MAX];
} switchlink_db_ecmp_info_t;

typedef struct switchlink_db_route_info_ {
  switchlink_handle_t vrf_h;
  switchlink_ip_addr_t ip_addr;
  bool ecmp;
  switchlink_handle_t nhop_h;
  switchlink_handle_t intf_h;
} switchlink_db_route_info_t;

typedef struct switchlink_db_tunnel_interface_info_ {
  char ifname[SWITCHLINK_INTERFACE_NAME_LEN_MAX];
  switchlink_handle_t orif_h;
  switchlink_handle_t urif_h;
  switchlink_handle_t tnl_term_h;
  switchlink_ip_addr_t src_ip;
  switchlink_ip_addr_t dst_ip;
  switchlink_link_type_t link_type;
  uint32_t ifindex;
  uint32_t vni_id;
  uint16_t dst_port;
  uint8_t ttl;
} switchlink_db_tunnel_interface_info_t;

/*** LAG member structure ***/
typedef struct switchlink_db_lag_member_info_ {
  char ifname[SWITCHLINK_INTERFACE_NAME_LEN_MAX];
  uint32_t ifindex;
  uint8_t oper_state;
  uint8_t slave_state;
  switchlink_handle_t lag_member_h;
  switchlink_handle_t lag_h;
  switchlink_mac_addr_t mac_addr;
  switchlink_mac_addr_t perm_hwaddr;
  bool is_lacp_member;
} switchlink_db_lag_member_info_t;

#endif /* __SWITCHLINK_DB_TYPES_H__ */
