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

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <linux/if_ether.h>

#include "config.h"
#include "sai.h"
#include "switchsai/saiinternal.h"
#include "switchlink_sai.h"

extern sai_status_t sai_initialize(void);

sai_port_api_t *sai_port_api = NULL;
sai_virtual_router_api_t *sai_vrf_api = NULL;
sai_fdb_api_t *sai_fdb_api = NULL;
sai_router_interface_api_t *sai_rintf_api = NULL;
sai_neighbor_api_t *sai_neigh_api = NULL;
sai_next_hop_api_t *sai_nhop_api = NULL;
sai_next_hop_group_api_t *sai_nhop_group_api = NULL;
sai_route_api_t *sai_route_api = NULL;
sai_hostif_api_t *sai_host_intf_api = NULL;
sai_tunnel_api_t *sai_tunnel_intf_api = NULL;

// This object ID is not used.
// Introduced this variable to be inline with submodules/SAI declarations
//static sai_object_id_t obj_id = 0;

/*
 * Routine Description:
 *    Initialize SAI API's
 *
 * Arguments:
 *    void
 *
 * Return Values:
 *    void
 */

void switchlink_init_api(void) {
  sai_status_t status = SAI_STATUS_SUCCESS;

  status = sai_initialize();
  krnlmon_assert(status == SAI_STATUS_SUCCESS);

  status = sai_api_query(SAI_API_PORT, (void **)&sai_port_api);
  krnlmon_assert(status == SAI_STATUS_SUCCESS);
  status = sai_api_query(SAI_API_VIRTUAL_ROUTER, (void **)&sai_vrf_api);
  krnlmon_assert(status == SAI_STATUS_SUCCESS);
  status = sai_api_query(SAI_API_FDB, (void **)&sai_fdb_api);
  krnlmon_assert(status == SAI_STATUS_SUCCESS);
  status = sai_api_query(SAI_API_ROUTER_INTERFACE, (void **)&sai_rintf_api);
  krnlmon_assert(status == SAI_STATUS_SUCCESS);
  status = sai_api_query(SAI_API_NEIGHBOR, (void **)&sai_neigh_api);
  krnlmon_assert(status == SAI_STATUS_SUCCESS);
  status = sai_api_query(SAI_API_NEXT_HOP, (void **)&sai_nhop_api);
  krnlmon_assert(status == SAI_STATUS_SUCCESS);
  status = sai_api_query(SAI_API_ROUTE, (void **)&sai_route_api);
  krnlmon_assert(status == SAI_STATUS_SUCCESS);
  status = sai_api_query(SAI_API_HOSTIF, (void **)&sai_host_intf_api);
  krnlmon_assert(status == SAI_STATUS_SUCCESS);
  status = sai_api_query(SAI_API_TUNNEL, (void **)&sai_tunnel_intf_api);
  krnlmon_assert(status == SAI_STATUS_SUCCESS);
  status = sai_api_query(SAI_API_NEXT_HOP_GROUP, (void **)&sai_nhop_group_api);
  krnlmon_assert(status == SAI_STATUS_SUCCESS);
  return;
}
