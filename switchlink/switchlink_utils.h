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

#ifndef __SWITCHLINK_UTILS_H__
#define __SWITCHLINK_UTILS_H__

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#include "switchutils/switch_utils.h"

uint32_t ipv4_prefix_len_to_mask(uint32_t prefix_len);
struct in6_addr ipv6_prefix_len_to_mask(uint32_t prefix_len);
#endif /* __SWITCHLINK_UTILS_H__ */
