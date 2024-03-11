/*
 * Copyright 2024 Intel Corporation.
 * SPDX-License-Identifier: Apache 2.0
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

// Proxy for the target-specific switch_pd_routing header file.
//
// We use a unique include guard to avoid aliasing the ones in the
// target-specific header files (which would cause their contents
// to be ignored).

#ifndef __SWITCHAPI_PD_ROUTING_H__
#define __SWITCHAPI_PD_ROUTING_H__

#if defined(DPDK_TARGET)
#include "dpdk/switch_pd_routing.h"
#elif defined(ES2K_TARGET)
#include "es2k/switch_pd_routing.h"
#endif

#endif  // __SWITCHAPI_PD_ROUTING_H__
