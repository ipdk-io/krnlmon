/*
 * Copyright 2023 Intel Corporation.
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

#include "sailag.h"

#include "saiinternal.h"
#include "switchapi/switch_device.h"
#include "switchapi/switch_lag.h"
#include "switchapi/switch_status.h"

/*
 * Routine Description:
 *    Create LAG
 *
 * Arguments:
 *    [out] lag_id - LAG id
 *    [in] switch_id - Switch Id
 *    [in] attr_count - Number of attributes
 *    [in] attr_list - Array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 *
 */
static sai_status_t sai_create_lag(_Out_ sai_object_id_t* lag_id,
                                   _In_ sai_object_id_t switch_id,
                                   _In_ uint32_t attr_count,
                                   _In_ const sai_attribute_t* attr_list) {
  switch_api_lag_info_t api_lag_info = {0};
  switch_handle_t lag_handle = SWITCH_API_INVALID_HANDLE;
  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
  sai_status_t status = SAI_STATUS_SUCCESS;

  switch_status = switch_api_lag_create(switch_id, &api_lag_info, &lag_handle);
  status = sai_switch_status_to_sai_status(switch_status);
  if (status != SAI_STATUS_SUCCESS) {
    krnlmon_log_error("Failed to create lag, error: %s \n",
                      sai_status_to_string(status));
    return status;
  }

  *lag_id = lag_handle;
  krnlmon_log_debug("LAG created for handle : 0x%lx", lag_handle);

  return status;
}

/*
 * Routine Description:
 *    Remove LAG
 *
 * Arguments:
 *    [in] lag_id - LAG id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t sai_remove_lag(_In_ sai_object_id_t lag_id) {
  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;

  switch_status = switch_api_lag_delete(0, (switch_handle_t)lag_id);
  status = sai_switch_status_to_sai_status(switch_status);
  if (status != SAI_STATUS_SUCCESS) {
    krnlmon_log_error("Failed to remove lag, error: %s",
                  sai_status_to_string(status));
  }

  return (sai_status_t)status;
}

/*
 * Routine Description:
 *    Create LAG member
 *
 * Arguments:
 *    [out] lag_member_id - LAG member id
 *    [in] switch_id - Switch Id
 *    [in] attr_count - Number of attributes
 *    [in] attr_list - Array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 *
 */
static sai_status_t sai_create_lag_member(_Out_ sai_object_id_t* lag_member_id,
                                          _In_ sai_object_id_t switch_id,
                                          _In_ uint32_t attr_count,
                                          _In_ const sai_attribute_t* attr_list) {
  switch_api_lag_member_info_t api_lag_member_info = {0};
  switch_lag_info_t lag_info = {0};
  switch_handle_t lag_member_handle = SWITCH_API_INVALID_HANDLE;
  switch_handle_t lag_handle = SWITCH_API_INVALID_HANDLE;

  const sai_attribute_t *attribute;
  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
  sai_status_t status = SAI_STATUS_SUCCESS;

  attribute = get_attr_from_list(SAI_LAG_MEMBER_ATTR_LAG_ID,
		                 attr_list, attr_count);
  if (attribute == NULL) {
    status = SAI_STATUS_INVALID_PARAMETER;
    krnlmon_log_error("missing attribute %s", sai_status_to_string(status));
    return status;
  }

  lag_handle = attribute->value.oid;

  switch_status = switch_api_lag_member_create(switch_id,
                  &api_lag_member_info, &lag_member_handle);
  status = sai_switch_status_to_sai_status(switch_status);
  if (status != SAI_STATUS_SUCCESS) {
    krnlmon_log_error("Failed to create lag member, error: %s \n",
                      sai_status_to_string(status));
    return status;
  }

  *lag_member_id = lag_member_handle;
  krnlmon_log_debug("LAG Member created for handle : 0x%lx", lag_member_handle);

  // update the lag_info with the new lag member handle to establish
  // relationship between lag and lag members
  if (lag_handle != SWITCH_API_INVALID_HANDLE) {
    // update the members field of lag_info with the new lag memeber.
    switch_api_lag_update(switch_id, lag_handle, lag_member_handle);
  }

  return status;
}

/*
 * Routine Description:
 *    Remove LAG member
 *
 * Arguments:
 *    [in] lag_member_id - LAG Member id
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
static sai_status_t sai_remove_lag_member(_In_ sai_object_id_t lag_member_id) {
  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;

  switch_status = switch_api_lag_member_delete(0, (switch_handle_t)lag_member_id);
  status = sai_switch_status_to_sai_status(switch_status);
  if (status != SAI_STATUS_SUCCESS) {
    krnlmon_log_error("Failed to remove lag member, error: %s",
                  sai_status_to_string(status));
  }

  return (sai_status_t)status;
}

static sai_status_t
sai_set_lag_attribute(_In_ sai_object_id_t lag_id,
                      _In_ const sai_attribute_t *attr) {
  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
  switch_lag_info_t lag_info = {0};
  switch_handle_t lag_handle = lag_id;
  switch_handle_t active_lag_member_h = attr->value.objlist.list[0];

  switch_status = switch_api_program_lag_hw(lag_handle, active_lag_member_h);
  status = sai_switch_status_to_sai_status(switch_status);
  if (status != SAI_STATUS_SUCCESS) {
    krnlmon_log_error("Failed to program LAG in HW, error: %s",
                  sai_status_to_string(status));
  }

  krnlmon_log_debug("LAG HW Block programmed in MEV-TS");
  return (sai_status_t)status;
}

/*
 *  LAG methods table retrieved with sai_api_query()
 */
sai_lag_api_t lag_api = {
    .create_lag = sai_create_lag,
    .remove_lag = sai_remove_lag,
    .create_lag_member = sai_create_lag_member,
    .remove_lag_member = sai_remove_lag_member,
    .set_lag_attribute = sai_set_lag_attribute,

    // TODO: Aashish
    //.get_lag_attribute = sai_get_lag_attribute,
    //.set_lag_member_attribute = sai_set_lag_member_attribute,
    //.get_lag_member_attribute = sai_get_lag_member_attribute,
};

sai_lag_api_t* sai_lag_api_get() { return &lag_api; }

sai_status_t sai_lag_initialize(sai_api_service_t* sai_api_service) {
  sai_api_service->lag_api = lag_api;
  return SAI_STATUS_SUCCESS;
}
