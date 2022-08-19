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

#include "switchlink_handle.h"

/*
 * Routine Description:
 *    SAI call to create route entry
 *
 * Arguments:
 *    [in] route_info - route info
 *
 * Return Values:
 *    0 on success
 *   -1 in case of error
 */

static int route_create(const switchlink_db_route_info_t *route_info) {
  sai_status_t status = SAI_STATUS_SUCCESS;

  sai_route_entry_t route_entry;
  memset(&route_entry, 0, sizeof(route_entry));
  route_entry.vr_id = route_info->vrf_h;
  if (route_info->ip_addr.family == AF_INET) {
    route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
    route_entry.destination.addr.ip4 =
        htonl(route_info->ip_addr.ip.v4addr.s_addr);
    route_entry.destination.mask.ip4 =
        htonl(ipv4_prefix_len_to_mask(route_info->ip_addr.prefix_len));
  } else {
    krnlmon_assert(route_info->ip_addr.family == AF_INET6);
    route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
    memcpy(route_entry.destination.addr.ip6,
           &(route_info->ip_addr.ip.v6addr),
           sizeof(sai_ip6_t));
    struct in6_addr mask =
        ipv6_prefix_len_to_mask(route_info->ip_addr.prefix_len);
    memcpy(route_entry.destination.mask.ip6, &mask, sizeof(sai_ip6_t));
  }

  sai_attribute_t attr_list[1];
  memset(attr_list, 0, sizeof(attr_list));
  if (route_info->nhop_h == g_cpu_rx_nhop_h) {
    attr_list[0].id = SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION;
    attr_list[0].value.s32 = SAI_PACKET_ACTION_TRAP;
  } else {
    attr_list[0].id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
    attr_list[0].value.oid = route_info->nhop_h;
  }

  status = sai_route_api->create_route_entry(&route_entry, 1, attr_list);
  return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

/*
 * Routine Description:
 *    SAI call to delete route entry
 *
 * Arguments:
 *    [in] route_info - route info
 *
 * Return Values:
 *    0 on success
 *   -1 in case of error
 */

static int route_delete(const switchlink_db_route_info_t *route_info) {
  sai_status_t status = SAI_STATUS_SUCCESS;

  sai_route_entry_t route_entry;
  memset(&route_entry, 0, sizeof(route_entry));
  route_entry.vr_id = route_info->vrf_h;
  if (route_info->ip_addr.family == AF_INET) {
    route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
    route_entry.destination.addr.ip4 =
        htonl(route_info->ip_addr.ip.v4addr.s_addr);
    route_entry.destination.mask.ip4 =
        htonl(ipv4_prefix_len_to_mask(route_info->ip_addr.prefix_len));
  } else {
    krnlmon_assert(route_info->ip_addr.family == AF_INET6);
    route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
    memcpy(route_entry.destination.addr.ip6,
           &(route_info->ip_addr.ip.v6addr),
           sizeof(sai_ip6_t));
    struct in6_addr mask =
        ipv6_prefix_len_to_mask(route_info->ip_addr.prefix_len);
    memcpy(route_entry.destination.mask.ip6, &mask, sizeof(sai_ip6_t));
  }

  status = sai_route_api->remove_route_entry(&route_entry);
  return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

/*
 * Routine Description:
 *    Create route and add entry to the database
 *
 * Arguments:
 *    [in] vrf_h - vrf handle
 *    [in] dst - IP address associated with route
 *    [in] gateway - gateway associated with route
 *    [in] ecmp_h - route interface handle
 *    [in] intf_h - ecmp handle
 *
 * Return Values:
 *    void
 */

void switchlink_create_route(switchlink_handle_t vrf_h,
                             const switchlink_ip_addr_t *dst,
                             const switchlink_ip_addr_t *gateway,
                             switchlink_handle_t ecmp_h,
                             switchlink_handle_t intf_h) {
  if (!dst || (!gateway && !ecmp_h)) {
    if (ecmp_h) {
      switchlink_delete_ecmp(ecmp_h);
    }
    return;
  }

  bool ecmp_valid = false;
  switchlink_handle_t nhop_h = g_cpu_rx_nhop_h;
  if (!ecmp_h) {
    // Ignore NULL gateway address, dont create a NHOP for that
    if (gateway->ip.v4addr.s_addr) {
      switchlink_db_nexthop_info_t nexthop_info;
      memset(&nexthop_info, 0, sizeof(switchlink_db_nexthop_info_t));
      memcpy(&(nexthop_info.ip_addr), gateway, sizeof(switchlink_ip_addr_t));
      nexthop_info.intf_h = intf_h;
      nexthop_info.vrf_h = vrf_h;
      switchlink_db_status_t status;
      status = switchlink_db_nexthop_get_info(&nexthop_info);
      if (status == SWITCHLINK_DB_STATUS_SUCCESS) {
          dzlog_debug("Received nhop 0x%lx handler, update from"
                   " route", nexthop_info.nhop_h);
        nhop_h = nexthop_info.nhop_h;
        nexthop_info.using_by |= SWITCHLINK_NHOP_FROM_ROUTE;
        switchlink_db_nexthop_update_using_by(&nexthop_info);
      } else {
        if (!switchlink_create_nexthop(&nexthop_info)) {
          dzlog_debug("Created nhop 0x%lx handle, update from "
                   " route", nexthop_info.nhop_h);
          nhop_h = nexthop_info.nhop_h;
          nexthop_info.using_by |= SWITCHLINK_NHOP_FROM_ROUTE;
          switchlink_db_nexthop_add(&nexthop_info);
        }
      }
    }
    ecmp_valid = false;
  } else {
    ecmp_valid = true;
    nhop_h = ecmp_h;
  }

  // get the route from the db (if it already exists)
  switchlink_db_route_info_t route_info;
  memset(&route_info, 0, sizeof(switchlink_db_route_info_t));
  route_info.vrf_h = vrf_h;
  memcpy(&(route_info.ip_addr), dst, sizeof(switchlink_ip_addr_t));
  switchlink_db_status_t status = switchlink_db_route_get_info(&route_info);
  if (status == SWITCHLINK_DB_STATUS_SUCCESS) {
    if ((route_info.ecmp == ecmp_valid) && (route_info.nhop_h == nhop_h)) {
      // no change
      return;
    }
    // nexthop has changed, delete the current route
    switchlink_delete_route(vrf_h, dst);
  }

  memset(&route_info, 0, sizeof(switchlink_db_route_info_t));
  route_info.vrf_h = vrf_h;
  memcpy(&(route_info.ip_addr), dst, sizeof(switchlink_ip_addr_t));
  route_info.ecmp = ecmp_valid;
  route_info.nhop_h = nhop_h;
  route_info.intf_h = intf_h;

  // add the route
  dzlog_info("Create route: 0x%x/%d", dst->ip.v4addr.s_addr,
             dst->prefix_len);
  if (route_create(&route_info) == -1) {
    if (route_info.ecmp) {
      switchlink_delete_ecmp(route_info.nhop_h);
    }
    return;
  }

  // add the route to the db
  if (switchlink_db_route_add(&route_info) == SWITCHLINK_DB_STATUS_SUCCESS) {
    if (route_info.ecmp) {
      switchlink_db_ecmp_ref_inc(route_info.nhop_h);
    }
  }
}

/*
 * Routine Description:
 *    Delete route and remove entry from the database
 *
 * Arguments:
 *    [in] vrf_h - vrf handle
 *    [in] dst - IP address associated with route
 *
 * Return Values:
 *    void
 */

void switchlink_delete_route(switchlink_handle_t vrf_h,
                             const switchlink_ip_addr_t *dst) {
  bool ecmp_enable = false;
  switchlink_handle_t ecmp_h;

  if (!dst) {
    return;
  }

  switchlink_db_status_t status;
  switchlink_db_route_info_t route_info;
  memset(&route_info, 0, sizeof(switchlink_db_route_info_t));
  route_info.vrf_h = vrf_h;
  memcpy(&(route_info.ip_addr), dst, sizeof(switchlink_ip_addr_t));
  status = switchlink_db_route_get_info(&route_info);
  if (status != SWITCHLINK_DB_STATUS_SUCCESS) {
    return;
  }

  if (route_delete(&route_info) == -1) {
    return;
  }

  dzlog_info("Route deleted: 0x%x/%d", dst->ip.v4addr.s_addr,
             dst->prefix_len);
  ecmp_enable = route_info.ecmp;
  ecmp_h = route_info.nhop_h;

  status = switchlink_db_route_delete(&route_info);
  if (status == SWITCHLINK_DB_STATUS_SUCCESS) {
    if (ecmp_enable) {
      switchlink_delete_ecmp(ecmp_h);
    }
  }
}

