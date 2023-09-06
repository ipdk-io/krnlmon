/*
 * Copyright (c) 2023 Intel Corporation.
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

#include "switchapi/switch_lag.h"
#include "switch_pd_lag.h"

#include "switchapi/switch_internal.h"
#include "switch_pd_p4_name_mapping.h"
#include "switch_pd_utils.h"

switch_status_t switch_pd_lag_entry(
    switch_device_t device,
    const switch_lag_info_t *lag_info,
    bool entry_add) {

    tdi_status_t status;

    tdi_id_t field_id_lag_id = 0;
    tdi_id_t field_id_meta_bit32_zero = 0;
    tdi_id_t field_id_meta_common_hash = 0;
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

    uint16_t network_byte_order_lag_id = -1;
    uint32_t network_byte_order = -1;
    static uint32_t total_lag_list = 0;
    switch_list_t lag_members;
    uint32_t lag_list = 0;
    uint8_t port_count = 0;

    switch_node_t *node = NULL;
    switch_lag_member_info_t *lag_member = NULL;
    switch_handle_t lag_handle = SWITCH_API_INVALID_HANDLE;
    switch_handle_t lag_member_handle = SWITCH_API_INVALID_HANDLE;

    krnlmon_log_debug("%s", __func__);

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
    status = tdi_info_get(dev_id, PROGRAM_NAME, &info_hdl);
    if (status != TDI_SUCCESS) {
        krnlmon_log_error("Failed to get tdi info handle, error: %d", status);
        goto dealloc_resources;
    }

    status = tdi_table_from_name_get(info_hdl,
                                     LNW_LAG_HASH_TABLE,
                                     &table_hdl);
    if (status != TDI_SUCCESS || !table_hdl) {
        krnlmon_log_error("Unable to get table handle for: %s, error: %d",
                 LNW_LAG_HASH_TABLE, status);
        goto dealloc_resources;
    }

    status = tdi_table_key_allocate(table_hdl, &key_hdl);
    if (status != TDI_SUCCESS) {
        krnlmon_log_error("Unable to allocate key handle for: %s, error: %d",
                 LNW_LAG_HASH_TABLE, status);
        goto dealloc_resources;
    }

    status = tdi_table_info_get(table_hdl, &table_info_hdl);
    if (status != TDI_SUCCESS) {
        krnlmon_log_error("Unable to get table info handle for table, error: %d", status);
        goto dealloc_resources;
    }

    status = tdi_key_field_id_get(table_info_hdl,
                                  LNW_LAG_HASH_TABLE_KEY_LAG_ID,
                                  &field_id_lag_id);
    if (status != TDI_SUCCESS) {
      krnlmon_log_error("Unable to get field ID for key: %s, error: %d",
               LNW_LAG_HASH_TABLE_KEY_LAG_ID, status);
        goto dealloc_resources;
    }

    status = tdi_key_field_id_get(table_info_hdl,
                                  LNW_LAG_HASH_TABLE_KEY_META_COMMON_HASH,
                                  &field_id_meta_common_hash);
    if (status != TDI_SUCCESS) {
      krnlmon_log_error("Unable to get field ID for key: %s, error: %d",
               LNW_LAG_HASH_TABLE_KEY_META_COMMON_HASH, status);
        goto dealloc_resources;
    }

    status = tdi_key_field_id_get(table_info_hdl,
                                  LNW_LAG_HASH_TABLE_KEY_USER_META_BIT32_ZEROS,
                                  &field_id_meta_bit32_zero);
    if (status != TDI_SUCCESS) {
      krnlmon_log_error("Unable to get field ID for key: %s, error: %d",
               LNW_LAG_HASH_TABLE_KEY_USER_META_BIT32_ZEROS, status);
        goto dealloc_resources;
    }

    status = tdi_action_name_to_id(table_info_hdl,
                                   LNW_LAG_HASH_TABLE_ACTION_SEND_TO_LAG_MEMBER,
                                   &action_id);
    if (status != TDI_SUCCESS) {
        krnlmon_log_error("Unable to get action allocator ID for: %s, error: %d",
                 LNW_LAG_HASH_TABLE_ACTION_SEND_TO_LAG_MEMBER, status);
        goto dealloc_resources;
    }

    status = tdi_table_action_data_allocate(table_hdl, action_id, &data_hdl);
    if (status != TDI_SUCCESS) {
        krnlmon_log_error("Unable to get action allocator for ID: %d, "
                 "error: %d", action_id, status);
        goto dealloc_resources;
    }

    status = tdi_data_field_id_with_action_get(table_info_hdl,
                                               LNW_ACTION_SEND_TO_LAG_MEMBER_PARAM_PORT_ID,
                                               action_id, &data_field_id);
    if (status != TDI_SUCCESS) {
    krnlmon_log_error("Unable to get data field id param for: %s, error: %d",
             LNW_ACTION_SEND_TO_LAG_MEMBER_PARAM_PORT_ID, status);
        goto dealloc_resources;
    }

    lag_handle = lag_info->lag_handle;
    lag_members = (switch_list_t) lag_info->lag_members;

    // For ES2K program LAG ID in host byte order
    network_byte_order_lag_id = lag_handle &
                                  ~(SWITCH_HANDLE_TYPE_LAG <<
                                   SWITCH_HANDLE_TYPE_SHIFT);

    while ((total_lag_list < LNW_LAG_HASH_SIZE) &&
           (lag_list < LNW_LAG_PER_GROUP_HASH_SIZE)) {
        port_count = 0;
        FOR_EACH_IN_LIST(lag_members, node) {
            lag_member = (switch_lag_member_info_t *)node->data;
            lag_member_handle = lag_member->lag_member_handle;

            status = tdi_key_field_set_value(key_hdl, field_id_lag_id,
                                             network_byte_order_lag_id);
            if (status != TDI_SUCCESS) {
                krnlmon_log_error("Unable to set value for key ID: %d for lag_hash_table"
                         ", error: %d", field_id_lag_id, status);
                goto dealloc_resources;
            }

            status = tdi_key_field_set_value(key_hdl, field_id_meta_common_hash,
                                             lag_list + port_count);
            if (status != TDI_SUCCESS) {
                krnlmon_log_error("Unable to set value for key ID: %d for lag_hash_table"
                         ", error: %d", field_id_meta_common_hash, status);
                goto dealloc_resources;
            }

            status = tdi_key_field_set_value(key_hdl, field_id_meta_bit32_zero,
                                             0);
            if (status != TDI_SUCCESS) {
                krnlmon_log_error("Unable to set value for key ID: %d for lag_hash_table"
                         ", error: %d", field_id_meta_bit32_zero, status);
                goto dealloc_resources;
            }

            if (entry_add) {
                network_byte_order = lag_member_handle &
                                      ~(SWITCH_HANDLE_TYPE_LAG_MEMBER <<
                                      SWITCH_HANDLE_TYPE_SHIFT);

                status = tdi_data_field_set_value(data_hdl, data_field_id,
                                                  network_byte_order);
                if (status != TDI_SUCCESS) {
                    krnlmon_log_error("Unable to set action value for ID: %d, error: %d",
                             data_field_id, status);
                    goto dealloc_resources;
                }

                status = tdi_table_entry_add(table_hdl, session, target_hdl,
                                             flags_hdl, key_hdl, data_hdl);
                if (status != TDI_SUCCESS) {
                krnlmon_log_error("Unable to add %s entry, error: %d", LNW_LAG_HASH_TABLE, status);
                    goto dealloc_resources;
                }
                total_lag_list++;
            } else {
                /* Delete an entry from target */
                krnlmon_log_info("Delete lag_hash_table entry");
                status = tdi_table_entry_del(table_hdl, session, target_hdl,
                                             flags_hdl, key_hdl);
                if (status != TDI_SUCCESS) {
                    krnlmon_log_error("Unable to delete %s entry, error: %d",
                             LNW_LAG_HASH_TABLE, status);
                    goto dealloc_resources;
                }
                total_lag_list--;
            }
            port_count++;
        }
        FOR_EACH_IN_LIST_END();
        lag_list += port_count;
    }
    krnlmon_log_debug("Total LAG hash entries created are: %d", total_lag_list);

dealloc_resources:
    status = tdi_switch_pd_deallocate_resources(flags_hdl, target_hdl,
                                                key_hdl, data_hdl,
                                                session, entry_add);
    return switch_pd_tdi_status_to_status(status);
}

