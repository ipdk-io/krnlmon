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

#ifndef __SWITCH_PD_UTILS_H__
#define __SWITCH_PD_UTILS_H__

#include "bf_pal/bf_pal_port_intf.h"
#include "bf_rt/bf_rt_common.h"
#include "bf_types/bf_types.h"
#include "port_mgr/dpdk/bf_dpdk_port_if.h"
#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"
#include "switchapi/switch_rif.h"

// clang-format off
// tdi_info.h does not include the header files it depends on,
// so we force tdi_defs.h to precede it.
#include "tdi/common/tdi_defs.h"
#include "tdi/common/c_frontend/tdi_info.h"
#include "tdi/common/c_frontend/tdi_init.h"
#include "tdi/common/c_frontend/tdi_session.h"
#include "tdi/common/c_frontend/tdi_table.h"
#include "tdi/common/c_frontend/tdi_table_info.h"
// clang-format on

#ifdef __cplusplus
extern "C" {
#endif

#define PROGRAM_NAME "linux_networking"

// Currently this value is picked from dpdk_port_config.pb.txt
#define MAX_NO_OF_PORTS 312
#define CONFIG_PORT_INDEX 256

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
