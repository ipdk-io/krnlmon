/*
 * Copyright 2024 Intel Corporation.
 * SPDX-License_Identifier: Apache-2.0
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

// Proxy for the target-specific switch_pd_routing header files.
//
// We use a unique include guard to avoid aliasing the ones in the
// target-specific header files (which would cause their contents
// to be ignored).

#ifndef __SWITCH_PD_ROUTING_WRAPPER_H__
#define __SWITCH_PD_ROUTING_WRAPPER_H__

#if defined(DPDK_TARGET)
#include "dpdk/switch_pd_routing.h"
#elif defined(ES2K_TARGET)
#ifdef LNW_V2
#include "es2k/lnw_v2/switch_pd_routing.h"
#else  // LNW_V3
#include "es2k/lnw_v3/switch_pd_routing.h"
#endif  // LNW_V2
#endif
#endif  // __SWITCH_PD_ROUTING_WRAPPER_H__
