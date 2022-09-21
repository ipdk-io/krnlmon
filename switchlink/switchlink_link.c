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

#include <fcntl.h>
#include <unistd.h>
#include <linux/if_bridge.h>
#include <linux/if.h>
#include <linux/version.h>

#include "config.h"
#include "switchlink.h"
#include "switchlink_int.h"
#include "switchlink_link.h"
#include "switchlink_handle.h"

switchlink_handle_t g_default_vrf_h = 0;
switchlink_handle_t g_default_bridge_h = 0;
switchlink_handle_t g_cpu_rx_nhop_h = 0;

/*
 * Routine Description:
 *    Get the link type
 *
 * Arguments:
 *    [in] info_kind - link related info
 *
 * Return Values:
 *    link type
 */

static switchlink_link_type_t get_link_type(char *info_kind) {
  switchlink_link_type_t link_type = SWITCHLINK_LINK_TYPE_ETH;

  if (!strcmp(info_kind, "bridge")) {
    link_type = SWITCHLINK_LINK_TYPE_BRIDGE;
  } else if (!strcmp(info_kind, "vxlan")) {
    link_type = SWITCHLINK_LINK_TYPE_VXLAN;
  } else if (!strcmp(info_kind, "bond")) {
    link_type = SWITCHLINK_LINK_TYPE_BOND;
  } else if (!strcmp(info_kind, "tun")) {
    link_type = SWITCHLINK_LINK_TYPE_TUN;
  }

  return link_type;
}

// Supports Port(tuntap), Routing and Vxlan features
/*
 * Routine Description:
 *    Process link netlink messages
 *
 * Arguments:
 *    [in] nlmsg - netlink msg header
 *    [in] type - type of netlink messages
 *
 * Return Values:
 *    void
 */

void process_link_msg(struct nlmsghdr *nlmsg, int type) {
  int hdrlen, attrlen;
  struct nlattr *attr, *nest_attr, *nest_attr_new;
  struct ifinfomsg *ifmsg;
  int nest_attr_type;

  switchlink_db_interface_info_t intf_info;
  switchlink_db_tunnel_interface_info_t tnl_intf_info;
  switchlink_link_type_t link_type = SWITCHLINK_LINK_TYPE_NONE;

  uint32_t vni_id = 0;
  switchlink_ip_addr_t remote_ip_addr;
  switchlink_ip_addr_t src_ip_addr;
  uint32_t vxlan_dst_port = 0;
  uint8_t ttl = 0;

  krnlmon_assert((type == RTM_NEWLINK) || (type == RTM_DELLINK));
  ifmsg = nlmsg_data(nlmsg);
  hdrlen = sizeof(struct ifinfomsg);

  dzlog_debug("%slink: family = %d, type = %d, ifindex = %d, flags = 0x%x,"\
           "change = 0x%x\n", ((type == RTM_NEWLINK) ? "new" : "del"),
           ifmsg->ifi_family, ifmsg->ifi_type, ifmsg->ifi_index,
           ifmsg->ifi_flags, ifmsg->ifi_change);

  memset(&intf_info, 0, sizeof(switchlink_db_interface_info_t));
  memset(&tnl_intf_info, 0, sizeof(switchlink_db_tunnel_interface_info_t));
  attrlen = nlmsg_attrlen(nlmsg, hdrlen);
  attr = nlmsg_attrdata(nlmsg, hdrlen);

  while (nla_ok(attr, attrlen)) {
    int attr_type = nla_type(attr);
    switch (attr_type) {
      case IFLA_IFNAME:
        snprintf(intf_info.ifname,
                 SWITCHLINK_INTERFACE_NAME_LEN_MAX,
                 nla_get_string(attr));
        dzlog_debug("Interface name is %s\n", intf_info.ifname);
        break;
      case IFLA_LINKINFO:
        nla_for_each_nested(nest_attr, attr, attrlen) {
          nest_attr_type = nla_type(nest_attr);
          switch (nest_attr_type) {
            case IFLA_INFO_KIND:
              link_type = get_link_type(nla_get_string(nest_attr));
              break;
            case IFLA_INFO_DATA:
              nla_for_each_nested(nest_attr_new, nest_attr, attrlen) {
                  int nest_attr_type_new = nla_type(nest_attr_new);
                  switch (nest_attr_type_new) {
                      case IFLA_VXLAN_ID:
                        vni_id = *(uint32_t *) nla_data(nest_attr_new);
                        dzlog_debug("Interface VNI ID: %d\n", vni_id);
                        break;
                      case IFLA_VXLAN_PORT:
                        vxlan_dst_port =
                            htons(*(uint16_t *) nla_data(nest_attr_new));
                        dzlog_debug("Interface Dst port: %d\n", vxlan_dst_port);
                        break;
                      case IFLA_VXLAN_GROUP:
                        memset(&remote_ip_addr, 0,
                               sizeof(switchlink_ip_addr_t));
                        remote_ip_addr.family = AF_INET;
                        remote_ip_addr.ip.v4addr.s_addr =
                            ntohl(nla_get_u32(nest_attr_new));
                        remote_ip_addr.prefix_len = 32;
                        dzlog_debug("Remote Ipv4 address: 0x%x\n",
                                   remote_ip_addr.ip.v4addr.s_addr);
                        break;
                      case IFLA_VXLAN_LOCAL:
                        memset(&src_ip_addr, 0, sizeof(switchlink_ip_addr_t));
                        src_ip_addr.family = AF_INET;
                        src_ip_addr.ip.v4addr.s_addr =
                            ntohl(nla_get_u32(nest_attr_new));
                        src_ip_addr.prefix_len = 32;
                        dzlog_debug("Src Ipv4 address: 0x%x\n",
                                   src_ip_addr.ip.v4addr.s_addr);
                        break;
                      case IFLA_VXLAN_TTL:
                        ttl = nla_get_u8(nest_attr_new);
                        dzlog_debug("TTL: %d\n", ttl);
                        break;
                    default:
                      break;
                  }
              }
              break;
            default:
              break;
          }
        }
        break;
      case IFLA_ADDRESS: {
        krnlmon_assert(nla_len(attr) == sizeof(switchlink_mac_addr_t));
        memcpy(&(intf_info.mac_addr), nla_data(attr), nla_len(attr));

        dzlog_debug("Interface Mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
               (unsigned char) intf_info.mac_addr[0],
               (unsigned char) intf_info.mac_addr[1],
               (unsigned char) intf_info.mac_addr[2],
               (unsigned char) intf_info.mac_addr[3],
               (unsigned char) intf_info.mac_addr[4],
               (unsigned char) intf_info.mac_addr[5]
               );

        break;
      }
      case IFLA_MASTER:
        break;
      case IFLA_PROTINFO:
      case IFLA_AF_SPEC:
        break;
      default:
        break;
    }
    attr = nla_next(attr, &attrlen);
  }

  if (type == RTM_NEWLINK) {
    switch (link_type) {
      case SWITCHLINK_LINK_TYPE_BRIDGE:
      case SWITCHLINK_LINK_TYPE_BOND:
      case SWITCHLINK_LINK_TYPE_NONE:
      case SWITCHLINK_LINK_TYPE_ETH:
        break;

      case SWITCHLINK_LINK_TYPE_TUN:
          intf_info.ifindex = ifmsg->ifi_index;
          intf_info.vrf_h = g_default_vrf_h;
          intf_info.intf_type = SWITCHLINK_INTF_TYPE_L3;

          switchlink_create_interface(&intf_info);
        break;

      case SWITCHLINK_LINK_TYPE_VXLAN: {
        snprintf(tnl_intf_info.ifname,
                 SWITCHLINK_INTERFACE_NAME_LEN_MAX,
                 intf_info.ifname);
        tnl_intf_info.dst_ip = remote_ip_addr;
        tnl_intf_info.src_ip = src_ip_addr;
        tnl_intf_info.link_type = link_type;
        tnl_intf_info.ifindex = ifmsg->ifi_index;
        tnl_intf_info.vni_id = vni_id;
        tnl_intf_info.dst_port = vxlan_dst_port;
        tnl_intf_info.ttl = ttl;

        switchlink_create_tunnel_interface(&tnl_intf_info);
      }
      break;
      default:
        break;
    }
  } else {
    krnlmon_assert(type == RTM_DELLINK);
    if (link_type == SWITCHLINK_LINK_TYPE_VXLAN) {
        switchlink_delete_tunnel_interface(ifmsg->ifi_index);
    } else if (link_type == SWITCHLINK_LINK_TYPE_TUN) {
      switchlink_delete_interface(ifmsg->ifi_index);
    } else {
      dzlog_debug("Unhandled link type");
    }
  }
}

void switchlink_init_link(void) {
  /* P4OVS: create default vrf*/
  switchlink_create_vrf(&g_default_vrf_h);
}
