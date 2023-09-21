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

#include "bf_types.h"
#include "switch_pd_utils.h"
#include "switchapi/es2k/switch_pd_lag.h"
#include "switchapi/switch_base_types.h"
#include "switchapi/switch_device.h"
#include "switchapi/switch_internal.h"
#include "switchapi/switch_status.h"

/*
 * Routine Description:
 *   @brief Create LAG
 *
 * Arguments:
 *   @param[in] device - device
 *   @param[in] api_lag_info - LAG info
 *   @param[out] lag_h - LAG handle
 *
 * Return Values:
 *    @return  SWITCH_STATUS_SUCCESS on success
 *             Failure status code on error
 */
switch_status_t switch_api_lag_create(switch_device_t device,
                                      switch_api_lag_info_t* api_lag_info,
                                      switch_handle_t* lag_h) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_lag_info_t* lag_info = NULL;

  if (api_lag_info->rmac_handle == SWITCH_API_INVALID_HANDLE) {
    status = switch_api_device_default_rmac_handle_get(
        device, &api_lag_info->rmac_handle);
    CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);
  }

  if (!SWITCH_RMAC_HANDLE(api_lag_info->rmac_handle)) {
    status = SWITCH_STATUS_INVALID_HANDLE;
    krnlmon_log_error(
        "lag create: Invalid rmac handle on device %d: "
        "error: %s\n",
        device, switch_error_to_string(status));
    return status;
  }

  *lag_h = switch_lag_handle_create(device);
  CHECK_RET(*lag_h == SWITCH_API_INVALID_HANDLE, SWITCH_STATUS_NO_MEMORY);

  status = switch_lag_get(device, *lag_h, &lag_info);
  CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);

  api_lag_info->port_id = -1;
  api_lag_info->phy_port_id = -1;
  switch_pd_to_get_lag_port_id(api_lag_info);

  status = SWITCH_LIST_INIT(&(lag_info->lag_members));
  SWITCH_ASSERT(status == SWITCH_STATUS_SUCCESS);

  SWITCH_MEMCPY(&lag_info->api_lag_info, api_lag_info,
                sizeof(switch_api_lag_info_t));

  return status;
}

/*
 * Routine Description:
 *   @brief Delete LAG
 *
 * Arguments:
 *   @param[in] device - device
 *   @param[out] lag_h - LAG handle
 *
 * Return Values:
 *    @return  SWITCH_STATUS_SUCCESS on success
 *             Failure status code on error
 */
switch_status_t switch_api_lag_delete(switch_device_t device,
                                      switch_handle_t lag_h) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_lag_info_t* lag_info = NULL;

  status = switch_lag_get(device, lag_h, &lag_info);
  CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);

  status = switch_lag_handle_delete(device, lag_h);
  CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);

  return status;
}

/*
 * Routine Description:
 *   @brief Create LAG member
 *
 * Arguments:
 *   @param[in] device - device
 *   @param[in] api_lag_member_info - LAG member info
 *   @param[out] lag_member_h - LAG member handle
 *
 * Return Values:
 *    @return  SWITCH_STATUS_SUCCESS on success
 *             Failure status code on error
 */
switch_status_t switch_api_lag_member_create(
    switch_device_t device, switch_api_lag_member_info_t* api_lag_member_info,
    switch_handle_t* lag_member_h) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_lag_member_info_t* lag_member_info = NULL;

  *lag_member_h = switch_lag_member_handle_create(device);
  CHECK_RET(*lag_member_h == SWITCH_API_INVALID_HANDLE,
            SWITCH_STATUS_NO_MEMORY);

  status = switch_lag_member_get(device, *lag_member_h, &lag_member_info);
  CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);

  SWITCH_MEMCPY(&lag_member_info->api_lag_member_info, api_lag_member_info,
                sizeof(switch_api_lag_member_info_t));

  return status;
}

/*
 * Routine Description:
 *   @brief Delete LAG member
 *
 * Arguments:
 *   @param[in] device - device
 *   @param[in] lag_member_h - LAG member handle
 *
 * Return Values:
 *    @return  SWITCH_STATUS_SUCCESS on success
 *             Failure status code on error
 */
switch_status_t switch_api_lag_member_delete(switch_device_t device,
                                             switch_handle_t lag_member_h) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_lag_member_info_t* lag_member_info = NULL;

  status = switch_lag_member_get(device, lag_member_h, &lag_member_info);
  CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);

  status = switch_lag_member_handle_delete(device, lag_member_h);
  CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);

  return status;
}

/*
 * Routine Description:
 *   @brief On creation of a LAG member, update the
 *   structure of parent LAG indicating new member
 *   addition in the lag_members list.
 *
 * Arguments:
 *   @param[in] device - device
 *   @param[in] lag_h - LAG handle
 *   @param[in] lag_member_h - handle of LAG member
 *
 * Return Values:
 *    @return  SWITCH_STATUS_SUCCESS on success
 *             Failure status code on error
 */
switch_status_t switch_api_lag_update(const switch_device_t device,
                                      const switch_handle_t lag_h,
                                      const switch_handle_t lag_member_h) {
  switch_lag_info_t* lag_info = NULL;
  switch_lag_member_info_t* lag_member_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (!SWITCH_LAG_HANDLE(lag_h)) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    krnlmon_log_error(
        "lag get: Invalid lag handle on device %d, "
        "lag handle 0x%lx: "
        "error: %s\n",
        device, lag_h, switch_error_to_string(status));
    return status;
  }

  status = switch_lag_get(device, lag_h, &lag_info);
  CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);

  if (!SWITCH_LAG_MEMBER_HANDLE(lag_member_h)) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    krnlmon_log_error(
        "lag get: Invalid lag member handle on device %d, "
        "lag member handle 0x%lx: "
        "error: %s\n",
        device, lag_member_h, switch_error_to_string(status));
    return status;
  }

  status = switch_lag_member_get(device, lag_member_h, &lag_member_info);
  CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);

  // update lag members list with the lag_member_h
  status = SWITCH_LIST_INSERT(&(lag_info->lag_members),
                              &(lag_member_info->node), lag_member_info);
  SWITCH_ASSERT(status == SWITCH_STATUS_SUCCESS);

  return status;
}

/*
 * Routine Description:
 *   @brief Get LAG attributes
 *
 * Arguments:
 *   @param[in] device - device
 *   @param[in] lag_h - LAG handle
 *   @param[in] lag_flags - LAG flags
 *   @param[out] api_lag_info - LAG info struct
 *
 * Return Values:
 *    @return  SWITCH_STATUS_SUCCESS on success
 *             Failure status code on error
 */
switch_status_t switch_api_lag_attribute_get(
    const switch_device_t device, const switch_handle_t lag_h,
    const switch_uint64_t lag_flags, switch_api_lag_info_t* api_lag_info) {
  switch_lag_info_t* lag_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (!SWITCH_LAG_HANDLE(lag_h)) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    krnlmon_log_error(
        "lag attribute get: Invalid lag handle on device %d, "
        "lag handle 0x%lx: "
        "error: %s\n",
        device, lag_h, switch_error_to_string(status));
    return status;
  }

  status = switch_lag_get(device, lag_h, &lag_info);
  CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);

  *api_lag_info = lag_info->api_lag_info;

  return status;
}

/*
 * Routine Description:
 *   @brief Program the Tx and Rx LAG tables
 *
 * Arguments:
 *   @param[in] lag_h : LAG handle
 *   @param[in] active_lag_member_h : Active
 *              LAG member handle
 *
 * Return Values:
 *    @return  SWITCH_STATUS_SUCCESS on success
 *             Failure status code on error
 */
switch_status_t switch_api_program_lag_hw(const switch_device_t device,
                                          switch_handle_t lag_h,
                                          switch_handle_t active_lag_member_h) {
  switch_lag_info_t* lag_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (!SWITCH_LAG_HANDLE(lag_h)) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    krnlmon_log_error(
        "lag get: Invalid lag handle on device %d, "
        "lag handle 0x%lx: "
        "error: %s\n",
        device, lag_h, switch_error_to_string(status));
    return status;
  }

  status = switch_lag_get(device, lag_h, &lag_info);
  CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);
  lag_info->active_lag_member = active_lag_member_h;

  //--------------------- Tx Path ----------------------//
  status = switch_pd_tx_lag_table_entry(device, lag_info, true);
  if (status != SWITCH_STATUS_SUCCESS) {
    krnlmon_log_error(
        "Failed to create tx lag table entry on device %d: "
        ",error: %s\n",
        device, switch_error_to_string(status));
    return status;
  }

  //--------------------- Rx Path ----------------------//
  status = switch_pd_rx_lag_table_entry(device, lag_info, true);
  if (status != SWITCH_STATUS_SUCCESS) {
    krnlmon_log_error(
        "Failed to create rx lag table entry on device %d: "
        ",error: %s\n",
        device, switch_error_to_string(status));
    return status;
  }

  return status;
}
