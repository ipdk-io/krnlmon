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

#include <net/if.h>

#include "switch_pd_utils.h"

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_internal.h"
#include "switchapi/switch_rmac_int.h"
#include "switch_pd_p4_name_mapping.h"

#include "bf_types.h"
#include "port_mgr/dpdk/bf_dpdk_port_if.h"
#include "bf_rt/bf_rt_common.h"

tdi_status_t switch_pd_get_physical_port_id(switch_device_t device,
                                            uint32_t netdev_port_id,
                                            uint8_t *physical_port_id) {
    tdi_status_t status;

    tdi_id_t field_id = 0;
    tdi_id_t action_id = 0;
    tdi_id_t data_field_id = 0;

    tdi_dev_id_t dev_id = device;

    tdi_flags_hdl *flags_hdl = NULL;
    tdi_target_hdl *target_hdl = NULL;
    const tdi_device_hdl *dev_hdl = NULL;
    tdi_session_hdl *session = NULL;
    const tdi_info_hdl *info_hdl = NULL;
    tdi_table_key_hdl *key_hdl = NULL;
    tdi_table_data_hdl *data_hdl = NULL;
    const tdi_table_hdl *table_hdl = NULL;
    const tdi_table_info_hdl *table_info_hdl = NULL;
    uint32_t network_byte_order = 0;
    uint64_t get_pd_phy_port = 0;

    krnlmon_log_debug("Entered: %s", __func__);

    status = tdi_info_get(dev_id, PROGRAM_NAME, &info_hdl);
    if (status != TDI_SUCCESS) {
        krnlmon_log_error("Failed to get tdi info handle, error: %d", status);
        goto dealloc_resources;
    }

    status = tdi_flags_create(0, &flags_hdl);
    if (status != TDI_SUCCESS) {
        krnlmon_log_error("Failed to create flags handle, error: %d", status);
        goto dealloc_resources;
    }

    status = tdi_device_get(dev_id, &dev_hdl);
    if (status != TDI_SUCCESS) {
        krnlmon_log_error("Failed to get device handle, error: %d", status);
        goto dealloc_resources;
    }

    status = tdi_target_create(dev_hdl, &target_hdl);
    if (status != TDI_SUCCESS) {
        krnlmon_log_error("Failed to create target handle, error: %d", status);
        goto dealloc_resources;
    }

    status = tdi_session_create(dev_hdl, &session);
    if (status != TDI_SUCCESS) {
        krnlmon_log_error("Failed to create tdi session, error: %d", status);
        goto dealloc_resources;
    }

    status = tdi_table_from_name_get(
                         info_hdl,
                         LNW_HANDLE_TX_FROM_HOST_TO_OVS_AND_OVS_TO_WIRE_TABLE,
                         &table_hdl);
    if (status != TDI_SUCCESS || !table_hdl) {
        krnlmon_log_error("Unable to get table handle for: %s, error: %d",
                 LNW_HANDLE_TX_FROM_HOST_TO_OVS_AND_OVS_TO_WIRE_TABLE,
                 status);
        goto dealloc_resources;
    }

    status = tdi_table_key_allocate(table_hdl, &key_hdl);
    if (status != TDI_SUCCESS) {
        krnlmon_log_error("Unable to allocate key handle for: %s, error: %d",
                 LNW_HANDLE_TX_FROM_HOST_TO_OVS_AND_OVS_TO_WIRE_TABLE,
                 status);
        goto dealloc_resources;
    }

    status = tdi_table_info_get(table_hdl, &table_info_hdl);
    if (status != TDI_SUCCESS) {
        krnlmon_log_error("Unable to get table info handle for table, error: %d", status);
        goto dealloc_resources;
    }

    status = tdi_key_field_id_get(table_info_hdl,
                            LNW_HANDLE_OVS_TO_WIRE_TABLE_KEY_META_COMMON_VSI,
                            &field_id);
    if (status != TDI_SUCCESS) {
      krnlmon_log_error("Unable to get field ID for key: %s, error: %d",
               LNW_HANDLE_OVS_TO_WIRE_TABLE_KEY_META_COMMON_VSI, status);
        goto dealloc_resources;
    }

    status = tdi_key_field_set_value(key_hdl, field_id, netdev_port_id - SWITCH_PD_TARGET_VPORT_OFFSET);
    if (status != TDI_SUCCESS) {
        krnlmon_log_error("Unable to set value for key ID: %d for vxlan_encap_mod_table"
                 ", error: %d", field_id, status);
        goto dealloc_resources;
    }

    status = tdi_key_field_id_get(table_info_hdl,
                        LNW_HANDLE_OVS_TO_WIRE_TABLE_KEY_USER_META_BIT32_ZEROS,
                        &field_id);
    if (status != TDI_SUCCESS) {
      krnlmon_log_error("Unable to get field ID for key: %s, error: %d",
               LNW_HANDLE_OVS_TO_WIRE_TABLE_KEY_USER_META_BIT32_ZEROS, status);
        goto dealloc_resources;
    }

    status = tdi_key_field_set_value(key_hdl, field_id, 0);
    if (status != TDI_SUCCESS) {
        krnlmon_log_error("Unable to set value for key ID: %d for vxlan_encap_mod_table"
                 ", error: %d", field_id, status);
        goto dealloc_resources;
    }

    status = tdi_action_name_to_id(table_info_hdl,
                                   LNW_HANDLE_OVS_TO_WIRE_TABLE_ACTION_SET_DEST,
                                   &action_id);
    if (status != TDI_SUCCESS) {
        krnlmon_log_error("Unable to get action allocator ID for: %s, error: %d",
                 LNW_HANDLE_OVS_TO_WIRE_TABLE_ACTION_SET_DEST, status);
        goto dealloc_resources;
    }

    status = tdi_table_action_data_allocate(table_hdl, action_id, &data_hdl);
    if (status != TDI_SUCCESS) {
        krnlmon_log_error("Unable to get action allocator for ID: %s, "
                 "error: %d", LNW_HANDLE_OVS_TO_WIRE_TABLE_ACTION_SET_DEST,
                 status);
        goto dealloc_resources;
    }

    status = tdi_table_entry_get(table_hdl, session, target_hdl, flags_hdl,
                                 key_hdl, data_hdl);
    if (status != TDI_SUCCESS) {
        krnlmon_log_error("Failed to get data handle for netdev: %d", status);
        goto dealloc_resources;
    }

    status = tdi_data_field_id_with_action_get(table_info_hdl,
                     LNW_HANDLE_OVS_TO_WIRE_TABLE_ACTION_SET_DEST_PARAM_PORT_ID,
                     action_id,
                     &data_field_id);
    if (status != TDI_SUCCESS) {
        krnlmon_log_error("Unable to get action allocator ID for: %s, error: %d",
                 LNW_HANDLE_OVS_TO_WIRE_TABLE_ACTION_SET_DEST_PARAM_PORT_ID,
                 status);
        goto dealloc_resources;
    }
//    status = tdi_data_field_get_value_ptr(data_hdl, data_field_id,
//                                          sizeof(*physical_port_id),
//                                          physical_port_id);
    status = tdi_data_field_get_value(data_hdl, data_field_id,
                                      &get_pd_phy_port);
    if (status != TDI_SUCCESS) {
        krnlmon_log_error("Failed to get value for the handle: %d", status);
        goto dealloc_resources;
    }
    *physical_port_id = (uint8_t) (get_pd_phy_port & 0xff);
dealloc_resources:
    status = tdi_switch_pd_deallocate_resources(flags_hdl, target_hdl,
                                                key_hdl, data_hdl,
                                                session, true);
    return switch_pd_tdi_status_to_status(status);
}

void
switch_pd_to_get_port_id(switch_api_rif_info_t *port_rif_info)
{
    switch_handle_t rmac_handle = SWITCH_API_INVALID_HANDLE;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_rmac_info_t *rmac_info = NULL;
    switch_rmac_entry_t *rmac_entry = NULL;
    switch_node_t *node = NULL;
    bf_dev_id_t bf_dev_id = 0;
    static char mac_str[SWITCH_PD_MAC_STR_LENGTH];
    bf_status_t bf_status;
    uint32_t port_id = 0;

    /*rmac_handle will have source mac info. get rmac_info from rmac_handle */
    rmac_handle = port_rif_info->rmac_handle;
    status = switch_rmac_get(bf_dev_id, rmac_handle, &rmac_info);
    if (status != SWITCH_STATUS_SUCCESS) {
        krnlmon_log_error("Cannot get rmac info for handle 0x%x, error: %d",
                  rmac_handle, status);
        return;
    }

    SWITCH_LIST_GET_HEAD(rmac_info->rmac_list, node);
    rmac_entry = (switch_rmac_entry_t *)node->data;

    if (!rmac_entry) {
        krnlmon_log_error("Cannot get rmac_entry for handle 0x%x", rmac_handle);
        return;
    }

    snprintf(mac_str, sizeof(mac_str),
             "%02x:%02x:%02x:%02x:%02x:%02x", rmac_entry->mac.mac_addr[0],
                                              rmac_entry->mac.mac_addr[1],
                                              rmac_entry->mac.mac_addr[2],
                                              rmac_entry->mac.mac_addr[3],
                                              rmac_entry->mac.mac_addr[4],
                                              rmac_entry->mac.mac_addr[5]);
    mac_str[SWITCH_PD_MAC_STR_LENGTH-1] = '\0';

    bf_status = bf_pal_get_port_id_from_mac(bf_dev_id, mac_str, &port_id);
    if (bf_status != BF_SUCCESS) {
        // First SWITCH_PD_TARGET_VPORT_OFFSET entries are reserved for
        // MEV h/w ports. Hence VSI ID/Port ID should be offset with
        // SWITCH_PD_TARGET_VPORT_OFFSET
        // As per CP_INIT conf file on IMC, VSI_ID/Port ID is added as part of
        // 2nd byte in interface MAC address.
        // Example: If MAC address of an IPDF interface is 00:11:22:33:44:55,
        //          then VSI_ID/Port ID is 0x11 for that interface.
        port_id = rmac_entry->mac.mac_addr[1] + SWITCH_PD_TARGET_VPORT_OFFSET;
        krnlmon_log_error("Failed to get the port ID, error: %d, Deriving "
                          "port ID from second byte of MAC address: "
                          "%s", bf_status, mac_str);
    }

    port_rif_info->port_id = port_id;

    krnlmon_log_debug("Found port ID: %d for MAC: %s", port_id, mac_str);
    return;
}

void
switch_pd_to_get_lag_port_id(switch_api_lag_info_t *port_lag_info)
{
    switch_handle_t rmac_handle = SWITCH_API_INVALID_HANDLE;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_rmac_info_t *rmac_info = NULL;
    switch_rmac_entry_t *rmac_entry = NULL;
    switch_node_t *node = NULL;
    bf_dev_id_t bf_dev_id = 0;
    static char mac_str[SWITCH_PD_MAC_STR_LENGTH];
    bf_status_t bf_status;
    uint32_t port_id = 0;

    /*rmac_handle will have source mac info. get rmac_info from rmac_handle */
    rmac_handle = port_lag_info->rmac_handle;
    status = switch_rmac_get(bf_dev_id, rmac_handle, &rmac_info);
    if (status != SWITCH_STATUS_SUCCESS) {
        krnlmon_log_error("Cannot get rmac info for handle 0x%x, error: %d",
                  rmac_handle, status);
        return;
    }

    SWITCH_LIST_GET_HEAD(rmac_info->rmac_list, node);
    rmac_entry = (switch_rmac_entry_t *)node->data;

    if (!rmac_entry) {
        krnlmon_log_error("Cannot get rmac_entry for handle 0x%x", rmac_handle);
        return;
    }

    snprintf(mac_str, sizeof(mac_str),
             "%02x:%02x:%02x:%02x:%02x:%02x", rmac_entry->mac.mac_addr[0],
                                              rmac_entry->mac.mac_addr[1],
                                              rmac_entry->mac.mac_addr[2],
                                              rmac_entry->mac.mac_addr[3],
                                              rmac_entry->mac.mac_addr[4],
                                              rmac_entry->mac.mac_addr[5]);
    mac_str[SWITCH_PD_MAC_STR_LENGTH-1] = '\0';

    bf_status = bf_pal_get_port_id_from_mac(bf_dev_id, mac_str, &port_id);
    if (bf_status != BF_SUCCESS) {
        port_id = rmac_entry->mac.mac_addr[1] + SWITCH_PD_TARGET_VPORT_OFFSET;
        krnlmon_log_error("Failed to get the port ID, error: %d, Deriving "
                          "port ID from second byte of MAC address: "
                          "%s", bf_status, mac_str);
    }

    port_lag_info->port_id = port_id;

    krnlmon_log_debug("Found port ID: %d for MAC: %s", port_id, mac_str);
    return;
}

tdi_status_t tdi_switch_pd_deallocate_resources(tdi_flags_hdl *flags_hdl,
                                                tdi_target_hdl *target_hdl,
                                                tdi_table_key_hdl *key_hdl,
                                                tdi_table_data_hdl *data_hdl,
                                                tdi_session_hdl *session,
                                                bool entry_type) {
    tdi_status_t retval = TDI_SUCCESS;
    tdi_status_t status;

    status = tdi_deallocate_flag(flags_hdl);
    if (!retval) retval = status;

    status = tdi_deallocate_target(target_hdl);
    if (!retval) retval = status;

    if (entry_type) {
        // Data handle is created only when entry is added to backend
        status = tdi_deallocate_table_data(data_hdl);
        if (!retval) retval = status;
    }

    status = tdi_deallocate_table_key(key_hdl);
    if (!retval) retval = status;

    status = tdi_deallocate_session(session);
    if (!retval) retval = status;

    return retval;
}

tdi_status_t tdi_deallocate_flag(tdi_flags_hdl *flags_hdl) {
    tdi_status_t status = TDI_SUCCESS;
    if (flags_hdl) {
        status = tdi_flags_delete(flags_hdl);
        if (status != TDI_SUCCESS) {
            krnlmon_log_error("Unable to deallocate flags handle, error: %d", status);
        }
    }
    return status;
}

tdi_status_t tdi_deallocate_target(tdi_target_hdl *target_hdl) {
    tdi_status_t status = TDI_SUCCESS;
    if (target_hdl) {
        status = tdi_target_delete(target_hdl);
        if (status != TDI_SUCCESS) {
            krnlmon_log_error("Unable to deallocate target handle, error: %d", status);
        }
    }
    return status;
}

tdi_status_t tdi_deallocate_table_data(tdi_table_data_hdl *data_hdl) {
    tdi_status_t status = TDI_SUCCESS;
    if (data_hdl) {
        status = tdi_table_data_deallocate(data_hdl);
        if(status != TDI_SUCCESS) {
            krnlmon_log_error("Failed to deallocate data handle, error: %d", status);
        }
    }
    return status;
}

tdi_status_t tdi_deallocate_table_key(tdi_table_key_hdl *key_hdl) {
    tdi_status_t status = TDI_SUCCESS;
    if (key_hdl) {
        status = tdi_table_key_deallocate(key_hdl);
        if (status != TDI_SUCCESS) {
            krnlmon_log_error("Failed to deallocate key handle, error: %d", status);
        }
    }
    return status;
}

tdi_status_t tdi_deallocate_session(tdi_session_hdl *session) {
    tdi_status_t status = TDI_SUCCESS;
    if (session) {
        status = tdi_session_destroy(session);
        if (status != TDI_SUCCESS) {
            krnlmon_log_error("Failed to destroy session, error: %d", status);
        }
    }
    return status;
}
