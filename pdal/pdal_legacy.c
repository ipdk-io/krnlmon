/*
 * Copyright 2024 Intel Corporation
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
 *
 * Maps PDAL functions to their equivalents in the P4 SDEs for DPDK and Tofino.
 */

#include "bf_pal/bf_pal_port_intf.h"
#include "pdal.h"

pdal_status_t pdal_pal_get_port_id_from_mac(pdal_dev_id_t dev_id, char* mac,
                                            uint32_t* port_id) {
  return bf_pal_get_port_id_from_mac(dev_id, mac, port_id);
}

pdal_status_t pdal_pal_port_info_get(pdal_dev_id_t dev_id,
                                     pdal_dev_port_t dev_port,
                                     struct port_info_t** port_info) {
  return bf_pal_port_info_get(dev_id, dev_port, port_info);
}
