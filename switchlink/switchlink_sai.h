/*
 * Copyright 2013-present Barefoot Networks, Inc.
 * Copyright (c) 2022 Intel Corporation.
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

#ifndef __SWITCHLINK_SAI_H__
#define __SWITCHLINK_SAI_H__

#include <saitypes.h>
#include <netinet/in.h>

#include "switchlink.h"
#include "switchlink_link.h"
#include "switchlink_neigh.h"
#include "switchlink_db.h"
#include "sai.h"

extern sai_router_interface_api_t *sai_rintf_api;
extern sai_tunnel_api_t *sai_tunnel_intf_api;
extern sai_port_api_t *sai_port_api;
extern sai_virtual_router_api_t *sai_vrf_api;
extern sai_fdb_api_t *sai_fdb_api;
extern sai_router_interface_api_t *sai_rintf_api;
extern sai_neighbor_api_t *sai_neigh_api;
extern sai_next_hop_api_t *sai_nhop_api;
extern sai_next_hop_group_api_t *sai_nhop_group_api;
extern sai_route_api_t *sai_route_api;
extern sai_hostif_api_t *sai_host_intf_api;
extern sai_tunnel_api_t *sai_tunnel_intf_api;

extern void switchlink_init_api(void);

#endif /* __SWITCHLINK_SAI_H__ */
