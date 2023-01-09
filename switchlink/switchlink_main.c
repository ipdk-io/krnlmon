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
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>

#include "switchlink.h"
#include "switchlink_int.h"

static struct nl_sock *g_nlsk = NULL;
static pthread_t switchlink_thread;
static pthread_mutex_t cookie_mutex;
static pthread_cond_t cookie_cv;
static int cookie = 0;

// Switchlink_main pthread variables
extern pthread_cond_t rpc_start_cond;
extern pthread_mutex_t rpc_start_lock;
extern int rpc_start_cookie;

// Switchlink stop pthread varaibles
extern pthread_cond_t rpc_stop_cond;
extern pthread_mutex_t rpc_stop_lock;
extern int rpc_stop_cookie;

enum {
  SWITCHLINK_MSG_LINK,
  SWITCHLINK_MSG_ADDR,
  SWITCHLINK_MSG_NETCONF,
  SWITCHLINK_MSG_NETCONF6,
  SWITCHLINK_MSG_NEIGH_MAC,
  SWITCHLINK_MSG_NEIGH_IP,
  SWITCHLINK_MSG_NEIGH_IP6,
  SWITCHLINK_MSG_MDB,
  SWITCHLINK_MSG_UNICAST_ROUTE,
  SWITCHLINK_MSG_UNICAST_ROUTE6,
  SWITCHLINK_MSG_MULTICAST_ROUTE,
  SWITCHLINK_MSG_MULTICAST_ROUTE6,
  SWITCHLINK_MSG_MAX,
} switchlink_msg_t;

// Currently we dont want to dump any existing kernel data when target is DPDK
static void nl_sync_state(void) {
  static uint8_t msg_idx = SWITCHLINK_MSG_LINK;
  if (msg_idx == SWITCHLINK_MSG_MAX) {
    return;
  }

  struct rtgenmsg rt_hdr = {
      .rtgen_family = AF_UNSPEC,
  };

  int msg_type = -1;
  switch (msg_idx) {
    case SWITCHLINK_MSG_LINK:
      msg_type = RTM_GETLINK;
      break;

    case SWITCHLINK_MSG_ADDR:
      msg_type = RTM_GETADDR;
      break;

    case SWITCHLINK_MSG_NETCONF:
      msg_type = RTM_GETNETCONF;
      rt_hdr.rtgen_family = AF_INET;
      break;

    case SWITCHLINK_MSG_NETCONF6:
      msg_type = RTM_GETNETCONF;
      rt_hdr.rtgen_family = AF_INET6;
      break;

    case SWITCHLINK_MSG_NEIGH_MAC:
      msg_type = RTM_GETNEIGH;
      rt_hdr.rtgen_family = AF_BRIDGE;
      break;

    case SWITCHLINK_MSG_NEIGH_IP:
      msg_type = RTM_GETNEIGH;
      rt_hdr.rtgen_family = AF_INET;
      break;

    case SWITCHLINK_MSG_NEIGH_IP6:
      msg_type = RTM_GETNEIGH;
      rt_hdr.rtgen_family = AF_INET6;
      break;

    case SWITCHLINK_MSG_MDB:
      msg_type = RTM_GETMDB;
      rt_hdr.rtgen_family = AF_BRIDGE;
      break;

    case SWITCHLINK_MSG_UNICAST_ROUTE:
      msg_type = RTM_GETROUTE;
      rt_hdr.rtgen_family = AF_INET;
      break;

    case SWITCHLINK_MSG_UNICAST_ROUTE6:
      msg_type = RTM_GETROUTE;
      rt_hdr.rtgen_family = AF_INET6;
      break;

    case SWITCHLINK_MSG_MULTICAST_ROUTE:
      msg_type = RTM_GETROUTE;
      rt_hdr.rtgen_family = RTNL_FAMILY_IPMR;
      break;

    case SWITCHLINK_MSG_MULTICAST_ROUTE6:
      msg_type = RTM_GETROUTE;
      rt_hdr.rtgen_family = RTNL_FAMILY_IP6MR;
      break;
  }

  if (msg_type != -1) {
    nl_send_simple(g_nlsk, msg_type, NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr));
    msg_idx++;
  }
}

/*
 * Routine Description:
 *    Process netlink messages
 *
 * Arguments:
 *    [in] nlmsg - netlink msg header
 *
 * Return Values:
 *    void
 */

static void nl_process_message(struct nlmsghdr *nlmsg) {
  /* TODO: P4OVS: Enabling callback for link msg type only and prints for
     few protocol families to avoid flood of messages. Enable, as needed.
  */
  switch (nlmsg->nlmsg_type) {
    case RTM_NEWLINK:
      krnlmon_log_debug("Switchlink Notification RTM_NEWLINK\n");
      process_link_msg(nlmsg, nlmsg->nlmsg_type);
      break;
    case RTM_DELLINK:
      krnlmon_log_debug("Switchlink Notification RTM_DELLINK\n");
      process_link_msg(nlmsg, nlmsg->nlmsg_type);
      break;
    case RTM_NEWADDR:
      krnlmon_log_debug("Switchlink Notification RTM_NEWADDR\n");
      process_address_msg(nlmsg, nlmsg->nlmsg_type);
      break;
    case RTM_DELADDR:
      krnlmon_log_debug("Switchlink Notification RTM_DELADDR\n");
      process_address_msg(nlmsg, nlmsg->nlmsg_type);
      break;
    case RTM_NEWROUTE:
      krnlmon_log_debug("Switchlink Notification RTM_NEWROUTE\n");
      process_route_msg(nlmsg, nlmsg->nlmsg_type);
      break;
    case RTM_DELROUTE:
      krnlmon_log_debug("Switchlink Notification RTM_DELROUTE\n");
      process_route_msg(nlmsg, nlmsg->nlmsg_type);
      break;
    case RTM_NEWNEIGH:
      krnlmon_log_debug("Switchlink Notification RTM_NEWNEIGH\n");
      process_neigh_msg(nlmsg, nlmsg->nlmsg_type);
      break;
    case RTM_DELNEIGH:
      krnlmon_log_debug("Switchlink Notification RTM_DELNEIGH\n");
      process_neigh_msg(nlmsg, nlmsg->nlmsg_type);
      break;
    case RTM_NEWNETCONF:
    case RTM_GETMDB:
    case RTM_NEWMDB:
    case RTM_DELMDB:
      break;
    case NLMSG_DONE:
      // P4-OVS comment nl_sync_state();
      break;
    default:
      krnlmon_log_debug("Unknown netlink message(%d). Ignoring\n", nlmsg->nlmsg_type);
      break;
  }
}

static int nl_recv_sock_msg(struct nl_msg *msg, void *arg) {
  struct nlmsghdr *nl_msg = nlmsg_hdr(msg);
  int nl_msg_sz = nlmsg_get_max_size(msg);
  while (nlmsg_ok(nl_msg, nl_msg_sz)) {
    nl_process_message(nl_msg);
    nl_msg = nlmsg_next(nl_msg, &nl_msg_sz);
  }

  return 0;
}

static void nl_cleanup_sock(void) {
  // free the socket
  nl_socket_free(g_nlsk);
  g_nlsk = NULL;
}

static void switchlink_nl_sock_intf_init(void) {
  int nlsk_fd, sock_flags;

  // allocate a new socket
  g_nlsk = nl_socket_alloc();
  if (g_nlsk == NULL) {
    perror("nl_socket_alloc");
    return;
  }

  nl_socket_set_local_port(g_nlsk, 0);

  // disable sequence number checking
  nl_socket_disable_seq_check(g_nlsk);

  // set the callback function
  nl_socket_modify_cb(
      g_nlsk, NL_CB_VALID, NL_CB_CUSTOM, nl_recv_sock_msg, NULL);
  nl_socket_modify_cb(
      g_nlsk, NL_CB_FINISH, NL_CB_CUSTOM, nl_recv_sock_msg, NULL);

  // connect to the netlink route socket
  if (nl_connect(g_nlsk, NETLINK_ROUTE) < 0) {
    perror("nl_connect:NETLINK_ROUTE");
    nl_cleanup_sock();
    return;
  }

  // register for the following messages
  nl_socket_add_memberships(g_nlsk, RTNLGRP_LINK, 0);
  nl_socket_add_memberships(g_nlsk, RTNLGRP_NOTIFY, 0);
  nl_socket_add_memberships(g_nlsk, RTNLGRP_NEIGH, 0);
  nl_socket_add_memberships(g_nlsk, RTNLGRP_IPV4_IFADDR, 0);
  nl_socket_add_memberships(g_nlsk, RTNLGRP_IPV4_ROUTE, 0);
  //nl_add_socket_memberships(g_nlsk, RTNLGRP_IPV4_RULE, 0);
  //nl_add_socket_memberships(g_nlsk, RTNLGRP_IPV6_IFADDR, 0);
  //nl_add_socket_memberships(g_nlsk, RTNLGRP_IPV6_ROUTE, 0);
  //nl_add_socket_memberships(g_nlsk, RTNLGRP_IPV6_RULE, 0);

  // set socket to be non-blocking
  nlsk_fd = nl_socket_get_fd(g_nlsk);
  if (nlsk_fd < 0) {
    perror("nl_socket_get_fd");
    nl_cleanup_sock();
    return;
  }
  sock_flags = fcntl(nlsk_fd, F_GETFL, 0);
  if (fcntl(nlsk_fd, F_SETFL, sock_flags | O_NONBLOCK) < 0) {
    perror("fcntl");
    nl_cleanup_sock();
    return;
  }

  // start building state from the kernel
  nl_sync_state();
}

static void nl_process_event_loop(void) {
  int nlsk_fd;
  nlsk_fd = nl_socket_get_fd(g_nlsk);
  krnlmon_assert(nlsk_fd > 0);

  while (1) {
    int ret, num_fds;
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(nlsk_fd, &read_fds);
    num_fds = nlsk_fd + 1;

    ret = select(num_fds, &read_fds, NULL, NULL, NULL);
    if (ret == -1) {
      perror("pselect");
      return;
    } else if (ret == 0) {
    } else {
      if (FD_ISSET(nlsk_fd, &read_fds)) {
        nl_recvmsgs_default(g_nlsk);
      }
    }
  }
}

struct nl_sock *switchlink_get_nl_sock(void) {
  return g_nlsk;
}

void *switchlink_main(void *args) {
  pthread_mutex_lock(&rpc_start_lock);
  while (!rpc_start_cookie) {
      pthread_cond_wait(&rpc_start_cond, &rpc_start_lock);
  }
  pthread_mutex_unlock(&rpc_start_lock);

  krnlmon_log_debug("switchlink main started");

  switchlink_init_db();
  switchlink_init_api();
  switchlink_init_link();
  switchlink_nl_sock_intf_init();

  if (g_nlsk) {
    usleep(20000);
    nl_process_event_loop();
    nl_cleanup_sock();
  }

  return NULL;
}

void *switchlink_stop(void *args) {
  pthread_mutex_lock(&rpc_stop_lock);
  while (!rpc_stop_cookie) {
      pthread_cond_wait(&rpc_stop_cond, &rpc_stop_lock);
  }
  pthread_mutex_unlock(&rpc_stop_lock);
  int status = pthread_cancel(switchlink_thread);
  if (status == 0) {
    pthread_join(switchlink_thread, NULL);
  }

  return NULL;
}
