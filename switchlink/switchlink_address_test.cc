#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <memory.h>
#include <netlink/msg.h>
#include <vector>

#include "netlink/msg.h"
#include "gtest/gtest.h"

extern "C" {
#include "switchlink/switchlink_handle.h"
#include "switchlink/switchlink_int.h"
#include "switchlink/switchlink_route.h"
}

using namespace std;

#define IPV4_ADDR(a, b, c, d) (((a) << 24) | ((b) << 16) | ((c) << 8) | (d))

// enum for diff operation types
enum operation_type {
  ADD_ADDRESS = 1,
  DELETE_ADDRESS = 2,
};

/*
 * Result variables.
 */
struct test_results {
  // Parameter values
  switchlink_ip_addr_t addr;
  switchlink_ip_addr_t gateway;
  switchlink_handle_t intf_h;
  // Handler tracking
  enum operation_type opType;
  int num_handler_calls;
};

vector<test_results> results(2);

/*
 * Dummy function for switchlink_create_route(). This function is
 * invoked by switchlink_process_address_msg() when the msgtype is
 * RTM_NEWADDR for both IPv4 and IPv6 type of addresses. The actual
 * method creates route and adds entry to the database. Since this is
 * dummy method, here the objective is to validate the invocation of
 * this method with correct arguments. All the input params are stored
 * in the test results structure and validated against each test case.
 */

void switchlink_create_route(switchlink_handle_t vrf_h,
                             const switchlink_ip_addr_t *addr,
                             const switchlink_ip_addr_t *gateway,
                             switchlink_handle_t ecmp_h,
                             switchlink_handle_t intf_h) {
  struct test_results temp = {};
  if (addr) {
    temp.addr = *addr;
  }
  if (gateway) {
    temp.gateway = *gateway;
  }
  if (intf_h) {
    temp.intf_h = intf_h;
  }
  temp.opType = ADD_ADDRESS;
  temp.num_handler_calls++;
  results.push_back(temp);
}

/*
 * Dummy function for switchlink_delete_route(). This function is
 * invoked by switchlink_process_address_msg() when the msgtype is
 * RTM_DELADDR for both IPv4 and IPv6 type of addresses. The actual
 * method deletes route and removes entry from the database. Since this
 * is dummy method, here the objective is to validate the invocation of
 * this method with correct arguments. All the input params are stored
 * in the test results structure and validated against each test case.
 */

void switchlink_delete_route(switchlink_handle_t vrf_h,
                             const switchlink_ip_addr_t *addr) {
  struct test_results temp = {};
  if (addr) {
    temp.addr = *addr;
  }
  temp.opType = DELETE_ADDRESS;
  temp.num_handler_calls++;
  results.push_back(temp);
}

/*
 * Dummy function for switchlink_db_get_interface_info(). This function
 * is invoked by switchlink_process_address_msg() for getting the intf
 * info from the database. Since this is a dummy method, we are passing
 * an ifindex 1 to this method and expects it to return an intf_info
 * successfully with ifhandle being 0x10001.
 */

switchlink_db_status_t
switchlink_db_get_interface_info(uint32_t ifindex,
                                 switchlink_db_interface_info_t *intf_info) {
  if (ifindex == 1) {
    intf_info->intf_h = 0x10001;
  }
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

/*
 * Test fixture.
 */

class SwitchlinkAddressTest : public ::testing::Test {
protected:
  struct nl_msg *nlmsg_ = nullptr;

  // Sets up the test fixture.
  void SetUp() override { ResetVariables(); }

  // Tears down the test fixture.
  void TearDown() override {
    if (nlmsg_) {
      nlmsg_free(nlmsg_);
      nlmsg_ = nullptr;
    }
  }

  void ResetVariables() {
    // result variables
    memset(&results, 0, sizeof(results));
  }
};

/*
 * Creates an IPv4 route
 *
 * Validates the switchlink_process_address_msg(). It parses an
 * RTM_NEWADDR message which contains an IPv4 address and invokes
 * switchlink_create_route() with the correct attributes.
 *
 * We invoke the switchlink_create_route() 2 times, one with the
 * subnet mask derived from IFA_ADDRESS and another one with /32
 * prefix. Hence we expect 2 test_results here, and this is the
 * reason why test_results has been taken as a vector of size 2.
 */

TEST_F(SwitchlinkAddressTest, addIpv4Address) {
  struct ifaddrmsg hdr = {
      .ifa_family = AF_INET,
      .ifa_prefixlen = 24,
      .ifa_index = 1,
  };

  int prefix_len = 0;
  const uint32_t ipv4_addr = IPV4_ADDR(10, 10, 10, 1);

  // Arrange
  nlmsg_ = nlmsg_alloc_size(1024);
  ASSERT_NE(nlmsg_, nullptr);
  nlmsg_put(nlmsg_, 0, 0, RTM_NEWADDR, 0, 0);
  nlmsg_append(nlmsg_, &hdr, sizeof(hdr), NLMSG_ALIGNTO);
  nla_put_u32(nlmsg_, IFA_ADDRESS, htonl(ipv4_addr));

  // Act
  const struct nlmsghdr *nlmsg = nlmsg_hdr(nlmsg_);
  switchlink_process_address_msg(nlmsg, nlmsg->nlmsg_type);

  // Assert
  EXPECT_EQ(results.size(), 2);
  for (int i = 0; i < results.size(); i++) {
    EXPECT_EQ(results[i].num_handler_calls, 1);
    EXPECT_EQ(results[i].opType, ADD_ADDRESS);
    EXPECT_EQ(results[i].addr.family, AF_INET);
    EXPECT_EQ(results[i].addr.ip.v4addr.s_addr, ipv4_addr);
    EXPECT_EQ(results[i].gateway.family, AF_INET);
    EXPECT_EQ(results[i].intf_h, 0x10001);
    (i == 0) ? prefix_len = hdr.ifa_prefixlen : prefix_len = 32;
    EXPECT_EQ(results[i].addr.prefix_len, prefix_len);
  }
}

/*
 * Deletes an IPv4 route
 *
 * Validates the switchlink_process_address_msg(). It parses an
 * RTM_DELADDR message which contains an IPv4 address and invokes
 * switchlink_delete_route() with the correct attributes.
 *
 * We invoke the switchlink_delete_route() 2 times, one with the
 * subnet mask derived from IFA_ADDRESS and another one with /32
 * prefix. Hence we expect 2 test_results here, and this is the
 * reason why test_results has been taken as a vector of size 2.
 */

TEST_F(SwitchlinkAddressTest, deleteIpv4Address) {
  struct ifaddrmsg hdr = {
      .ifa_family = AF_INET,
      .ifa_prefixlen = 24,
      .ifa_index = 1,
  };

  int prefix_len = 0;
  const uint32_t ipv4_addr = IPV4_ADDR(10, 10, 10, 1);

  // Arrange
  nlmsg_ = nlmsg_alloc_size(1024);
  ASSERT_NE(nlmsg_, nullptr);
  nlmsg_put(nlmsg_, 0, 0, RTM_DELADDR, 0, 0);
  nlmsg_append(nlmsg_, &hdr, sizeof(hdr), NLMSG_ALIGNTO);
  nla_put_u32(nlmsg_, IFA_ADDRESS, htonl(ipv4_addr));

  // Act
  const struct nlmsghdr *nlmsg = nlmsg_hdr(nlmsg_);
  switchlink_process_address_msg(nlmsg, nlmsg->nlmsg_type);

  // Assert
  EXPECT_EQ(results.size(), 2);
  for (int i = 0; i < results.size(); i++) {
    EXPECT_EQ(results[i].num_handler_calls, 1);
    EXPECT_EQ(results[i].opType, DELETE_ADDRESS);
    EXPECT_EQ(results[i].addr.family, AF_INET);
    EXPECT_EQ(results[i].addr.ip.v4addr.s_addr, ipv4_addr);
    (i == 0) ? prefix_len = hdr.ifa_prefixlen : prefix_len = 32;
    EXPECT_EQ(results[i].addr.prefix_len, prefix_len);
  }
}

/*
 * Creates an IPv6 route
 *
 * Validates the switchlink_process_address_msg(). It parses an
 * RTM_NEWADDR message which contains an IPv6 address and invokes
 * switchlink_create_route() with the correct attributes.
 *
 * We invoke the switchlink_create_route() 2 times, one with the
 * subnet mask derived from IFA_ADDRESS and another one with /128
 * prefix. Hence we expect 2 test_results here, and this is the
 * reason why test_results has been taken as a vector of size 2.
 */

TEST_F(SwitchlinkAddressTest, addIpv6Address) {
  struct ifaddrmsg hdr = {
      .ifa_family = AF_INET6,
      .ifa_prefixlen = 64,
      .ifa_index = 1,
  };

  int prefix_len = 0;
  struct in6_addr addr6;
  inet_pton(AF_INET6, "2001::1", &addr6);

  // Arrange
  nlmsg_ = nlmsg_alloc_size(1024);
  ASSERT_NE(nlmsg_, nullptr);
  nlmsg_put(nlmsg_, 0, 0, RTM_NEWADDR, 0, 0);
  nlmsg_append(nlmsg_, &hdr, sizeof(hdr), NLMSG_ALIGNTO);
  nla_put(nlmsg_, IFA_ADDRESS, sizeof(addr6), &addr6);

  // Act
  const struct nlmsghdr *nlmsg = nlmsg_hdr(nlmsg_);
  switchlink_process_address_msg(nlmsg, nlmsg->nlmsg_type);

  // Assert
  EXPECT_EQ(results.size(), 2);
  for (int i = 0; i < results.size(); i++) {
    EXPECT_EQ(results[i].num_handler_calls, 1);
    EXPECT_EQ(results[i].opType, ADD_ADDRESS);
    EXPECT_EQ(results[i].addr.family, AF_INET6);
    EXPECT_EQ(results[i].gateway.family, AF_INET6);
    EXPECT_EQ(results[i].intf_h, 0x10001);
    EXPECT_EQ(results[i].addr.ip.v6addr.__in6_u.__u6_addr16[0], 288);
    EXPECT_EQ(results[i].addr.ip.v6addr.__in6_u.__u6_addr16[7], 256);
    (i == 0) ? prefix_len = hdr.ifa_prefixlen : prefix_len = 128;
    EXPECT_EQ(results[i].addr.prefix_len, prefix_len);
  }
}

/*
 * Deletes an IPv6 route
 *
 * Validates the switchlink_process_address_msg(). It parses an
 * RTM_DELADDR message which contains an IPv6 address and invokes
 * switchlink_delete_route() with the correct attributes.
 *
 * We invoke the switchlink_delete_route() 2 times, one with the
 * subnet mask derived from IFA_ADDRESS and another one with /128
 * prefix. Hence we expect 2 test_results here, and this is the
 * reason why test_results has been taken as a vector of size 2.
 */

TEST_F(SwitchlinkAddressTest, deleteIpv6Address) {
  struct ifaddrmsg hdr = {
      .ifa_family = AF_INET6,
      .ifa_prefixlen = 64,
      .ifa_index = 1,
  };

  int prefix_len = 0;
  struct in6_addr addr6;
  inet_pton(AF_INET6, "2001::1", &addr6);

  // Arrange
  nlmsg_ = nlmsg_alloc_size(1024);
  ASSERT_NE(nlmsg_, nullptr);
  nlmsg_put(nlmsg_, 0, 0, RTM_DELADDR, 0, 0);
  nlmsg_append(nlmsg_, &hdr, sizeof(hdr), NLMSG_ALIGNTO);
  nla_put(nlmsg_, IFA_ADDRESS, sizeof(addr6), &addr6);

  // Act
  const struct nlmsghdr *nlmsg = nlmsg_hdr(nlmsg_);
  switchlink_process_address_msg(nlmsg, nlmsg->nlmsg_type);

  // Assert
  EXPECT_EQ(results.size(), 2);
  for (int i = 0; i < results.size(); i++) {
    EXPECT_EQ(results[i].num_handler_calls, 1);
    EXPECT_EQ(results[i].opType, DELETE_ADDRESS);
    EXPECT_EQ(results[i].addr.family, AF_INET6);
    EXPECT_EQ(results[i].addr.ip.v6addr.__in6_u.__u6_addr16[0], 288);
    EXPECT_EQ(results[i].addr.ip.v6addr.__in6_u.__u6_addr16[7], 256);
    (i == 0) ? prefix_len = hdr.ifa_prefixlen : prefix_len = 128;
    EXPECT_EQ(results[i].addr.prefix_len, prefix_len);
  }
}
