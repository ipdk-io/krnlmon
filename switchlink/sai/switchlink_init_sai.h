/*
 * Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2022-2023 Intel Corporation.
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

#ifndef __SWITCHLINK_INIT_SAI_H__
#define __SWITCHLINK_INIT_SAI_H__

#include <stdbool.h>                   // for bool
#include <stdint.h>                    // for uint32_t

#include "switchlink/switchlink.h"     // for switchlink_handle_t, switchlin...
#include "switchlink/switchlink_db.h"  // for switchlink_db_ecmp_info_t, swi...
#include "saitypes.h"                  // for sai_status_t

// Init SAI API
void switchlink_init_api(void);
sai_status_t sai_init_tunnel_api();
sai_status_t sai_init_rintf_api();
sai_status_t sai_init_vrf_api();
sai_status_t sai_init_fdb_api();
sai_status_t sai_init_neigh_api();
sai_status_t sai_init_route_api();
sai_status_t sai_init_nhop_api();
sai_status_t sai_init_nhop_group_api();

// SWITCHLINK_LINK_TYPE_VXLAN handlers
void switchlink_create_tunnel_interface(
    switchlink_db_tunnel_interface_info_t* tnl_intf);
void switchlink_delete_tunnel_interface(uint32_t ifindex);

// SWITCHLINK_LINK_TYPE_TUN handlers
void switchlink_create_interface(switchlink_db_interface_info_t* intf);
void switchlink_delete_interface(uint32_t ifindex);

// RTM_NEWNEIGH/ RTM_DELNEIGH handlers
void switchlink_create_neigh(switchlink_handle_t vrf_h,
                             const switchlink_ip_addr_t* ipaddr,
                             switchlink_mac_addr_t mac_addr,
                             switchlink_handle_t intf_h);
void switchlink_delete_neigh(switchlink_handle_t vrf_h,
                             const switchlink_ip_addr_t* ipaddr,
                             switchlink_handle_t intf_h);
void switchlink_create_mac(switchlink_mac_addr_t mac_addr,
                           switchlink_handle_t bridge_h,
                           switchlink_handle_t intf_h);
void switchlink_delete_mac(switchlink_mac_addr_t mac_addr,
                           switchlink_handle_t bridge_h);

// Nexthop handlers
int switchlink_create_nexthop(switchlink_db_nexthop_info_t* nexthop_info);
int switchlink_delete_nexthop(switchlink_handle_t nhop_h);

// RTM_NEWROUTE/ RTM_DELROUTE handlers
void switchlink_create_route(switchlink_handle_t vrf_h,
                             const switchlink_ip_addr_t* dst,
                             const switchlink_ip_addr_t* gateway,
                             switchlink_handle_t ecmp_h,
                             switchlink_handle_t intf_h);
void switchlink_delete_route(switchlink_handle_t vrf_h,
                             const switchlink_ip_addr_t* dst);

// ECMP handlers
int switchlink_create_ecmp(switchlink_db_ecmp_info_t* ecmp_info);
void switchlink_delete_ecmp(switchlink_handle_t ecmp_h);

// VRF handler
int switchlink_create_vrf(switchlink_handle_t* vrf_h);

// General utility function
bool validate_delete_nexthop(uint32_t using_by,
                             switchlink_nhop_using_by_e type);

#endif /* __SWITCHLINK_INIT_SAI_H__ */
