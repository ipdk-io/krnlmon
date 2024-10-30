/*
 * Copyright 2024 Intel Corporation.
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
 *
 * ---------------------------------------------------------------------
 * This header file maps compile-time symbol definitions (such as
 * ES2K_TARGET) to internal symbol definitions that specify which
 * features the compile-time symbols enable (such as LAG_OPTION).
 *
 * This is infinitely better than leaving the reader scratching
 * their head, trying to figure out why some random piece of code
 * is wrapped in an "#if !defined(OVSP4RT_SUPPORT)" conditional
 * (which the original author didn't bother to comment).
 * ---------------------------------------------------------------------
 */

#ifndef KRNLMON_OPTIONS_H_
#define KRNLMON_OPTIONS_H_

#if defined(DPDK_TARGET)
// DPDK options
#elif defined(ES2K_TARGET)
// ES2K options
#define LAG_OPTION 1
#else
#error "ASSERT: Unknown TARGET type!"
#endif

#if !defined(OVSP4RT_SUPPORT)
#define VXLAN_OPTION 1
#endif

#endif  // KRNLMON_OPTIONS_H_
