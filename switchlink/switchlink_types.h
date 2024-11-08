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

#ifndef __SWITCHLINK_TYPES_H__
#define __SWITCHLINK_TYPES_H__

#include <netinet/in.h>
#include <stdint.h>

#define SWITCH_LINK_INVALID_HANDLE 0x0

typedef uint64_t switchlink_handle_t;

typedef uint8_t switchlink_mac_addr_t[6];

typedef struct switchlink_ip_addr_ {
  uint8_t family;
  uint8_t prefix_len;
  union {
    struct in_addr v4addr;
    struct in6_addr v6addr;
  } ip;
} switchlink_ip_addr_t;

enum switchlink_nhop_using_by {
  SWITCHLINK_NHOP_FROM_NONE = 0,
  SWITCHLINK_NHOP_FROM_NEIGHBOR = 1 << 0,
  SWITCHLINK_NHOP_FROM_ROUTE = 1 << 1,
};

#endif /* __SWITCHLINK_TYPES_H__ */
