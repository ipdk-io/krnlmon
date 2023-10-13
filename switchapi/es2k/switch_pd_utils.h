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

#ifndef __ES2K_SWITCH_PD_UTILS_H__
#define __ES2K_SWITCH_PD_UTILS_H__

#include <stdbool.h>  // for bool
#include <stdint.h>   // for uint32_t, uint8_t

#include "bf_rt/bf_rt_common.h"           // for bf_rt_session_hdl, bf_rt_in...
#include "bf_types.h"                     // for bf_status_t, bf_dev_id_t
#include "switchapi/switch_base_types.h"  // for switch_device_t, switch_sta...
#include "switchapi/switch_rif.h"         // for switch_api_rif_info_t
#include "tdi/common/tdi_defs.h"          // for tdi_status_t, tdi_flags_hdl

#ifdef __cplusplus
extern "C" {
#endif

#define PROGRAM_NAME "fxp-net_linux-networking"

// Currently this value is picked from dpdk_port_config.pb.txt
#define MAX_NO_OF_PORTS 312
#define CONFIG_PORT_INDEX 256
#define SWITCH_PD_TARGET_VPORT_OFFSET 16

#define SWITCH_PD_MAC_STR_LENGTH 18
#define RMAC_BASE 0
#define RMAC_BYTES_OFFSET 2
#define RMAC_START_OFFSET RMAC_BASE
#define RMAC_MID_OFFSET RMAC_START_OFFSET + RMAC_BYTES_OFFSET
#define RMAC_LAST_OFFSET RMAC_MID_OFFSET + RMAC_BYTES_OFFSET

tdi_status_t switch_pd_get_physical_port_id(switch_device_t device,
                                            uint32_t netdev_port_id,
                                            uint8_t* physical_port_id);

bf_status_t switch_pd_allocate_handle_session(const bf_dev_id_t device_id,
                                              const char* pipeline_name,
                                              bf_rt_info_hdl** bfrt_info_hdl_t,
                                              bf_rt_session_hdl** session_t);

bf_status_t switch_pd_deallocate_handle_session(
    bf_rt_table_key_hdl* key_hdl_t, bf_rt_table_data_hdl* data_hdl_t,
    bf_rt_session_hdl* session_t, bool entry_type);

void switch_pd_to_get_port_id(switch_api_rif_info_t* port_rif_info);

tdi_status_t tdi_switch_pd_deallocate_resources(tdi_flags_hdl* flags_hdl,
                                                tdi_target_hdl* target_hdl,
                                                tdi_table_key_hdl* key_hdl,
                                                tdi_table_data_hdl* data_hdl,
                                                tdi_session_hdl* session,
                                                bool entry_type);

switch_status_t switch_pd_tdi_status_to_status(tdi_status_t pd_status);

tdi_status_t tdi_deallocate_flag(tdi_flags_hdl* flags_hdl);

tdi_status_t tdi_deallocate_target(tdi_target_hdl* target_hdl);

tdi_status_t tdi_deallocate_table_data(tdi_table_data_hdl* data_hdl);

tdi_status_t tdi_deallocate_table_key(tdi_table_key_hdl* key_hdl);

tdi_status_t tdi_deallocate_session(tdi_session_hdl* session);

#ifdef __cplusplus
}
#endif

#endif
