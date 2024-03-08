/*
 * Copyright 2021-2024 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef _PDAL_H_
#define _PDAL_H_

#include <stdint.h>

/** Specifies an ASIC in the system. */
typedef int pdal_dev_id_t;

/**
 * Specifies a port on the ASIC. This is a 9-bit value, where the upper two
 * bits specify the pipeline and the lower 7 bits specify the port number
 * local to that pipeline.
 */
typedef int pdal_dev_port_t;

#ifndef PDAL_STATUS_DEFINED_
/** Specifies an error code. */
typedef int pdal_status_t;
#define PDAL_STATUS_DEFINED_
#endif

#define P4_SDE_TABLE_NAME_LEN 64
#define P4_SDE_NAME_LEN 64
#define P4_SDE_PROG_NAME_LEN 50
#define P4_SDE_VERSION_LEN 3
#define P4_SDE_MAX_SESSIONS 16
#define P4_SDE_NAME_SUFFIX 16
#define P4_SDE_ARCH_NAME_LEN 4
#define P4_SDE_COUNTER_TARGET_LEN (P4_SDE_TABLE_NAME_LEN + 8)

#define MAC_FORMAT "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"

#define MAC_FORMAT_VALUE(var) \
  (int)var[0], (int)var[1], (int)var[2], (int)var[3], (int)var[4], (int)var[5]

#define IP_FORMAT "%u.%u.%u.%u"

#define IP_FORMAT_VALUE(var)                            \
  ((unsigned char*)&var)[3], ((unsigned char*)&var)[2], \
      ((unsigned char*)&var)[1], ((unsigned char*)&var)[0]

struct port_info_t;

pdal_status_t pdal_pal_get_port_id_from_mac(pdal_dev_id_t dev_id, char* mac,
                                            uint32_t* port_id);

pdal_status_t pdal_pal_port_info_get(pdal_dev_id_t dev_id,
                                     pdal_dev_port_t dev_port,
                                     struct port_info_t** port_info);

#endif  // _PDAL_H_
