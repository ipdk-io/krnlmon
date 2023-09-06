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
#include "switchapi/switch_base_types.h"
#include "switchapi/switch_device.h"
#include "switchapi/switch_internal.h"
#include "switchapi/switch_status.h"
#include "switchapi/es2k/switch_pd_lag.h"

switch_status_t switch_api_lag_create(switch_device_t device,
                                      switch_api_lag_info_t* api_lag_info,
                                      switch_handle_t* lag_handle) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_lag_info_t* lag_info = NULL;

  *lag_handle = switch_lag_handle_create(device);
  if (*lag_handle == SWITCH_API_INVALID_HANDLE) {
    status = SWITCH_STATUS_NO_MEMORY;
    krnlmon_log_error("Failed to create lag handle on device %d: error: %s\n",
                      device, switch_error_to_string(status));
    return status;
  }

  status = switch_lag_get(device, *lag_handle, &lag_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    krnlmon_log_error("Failed to get lag info on device %d: error: %s\n",
                      device, switch_error_to_string(status));
    return status;
  }

  status = SWITCH_LIST_INIT(&(lag_info->lag_members));
  SWITCH_ASSERT(status == SWITCH_STATUS_SUCCESS);

  SWITCH_MEMCPY(&lag_info->api_lag_info, api_lag_info,
                sizeof(switch_api_lag_info_t));

  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_lag_delete(switch_device_t device,
                                      switch_handle_t lag_handle) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_lag_info_t* lag_info = NULL;

  status = switch_lag_get(device, lag_handle, &lag_info);
  CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);

  status = switch_lag_handle_delete(device, lag_handle);
  CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);

  return status;
}

switch_status_t switch_api_lag_member_create(
    switch_device_t device, switch_api_lag_member_info_t* api_lag_member_info,
    switch_handle_t* lag_member_handle) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_lag_member_info_t* lag_member_info = NULL;

  *lag_member_handle = switch_lag_member_handle_create(device);
  if (*lag_member_handle == SWITCH_API_INVALID_HANDLE) {
    status = SWITCH_STATUS_NO_MEMORY;
    krnlmon_log_error(
        "Failed to create lag member handle on device %d: error: %s\n", device,
        switch_error_to_string(status));
    return status;
  }

  status = switch_lag_member_get(device, *lag_member_handle, &lag_member_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    krnlmon_log_error("Failed to get lag member info on device %d: error: %s\n",
                      device, switch_error_to_string(status));
    return status;
  }

  SWITCH_MEMCPY(&lag_member_info->api_lag_member_info, api_lag_member_info,
                sizeof(switch_api_lag_member_info_t));

  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_lag_member_delete(
    switch_device_t device, switch_handle_t lag_member_handle) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_lag_member_info_t* lag_member_info = NULL;

  status = switch_lag_member_get(device, lag_member_handle, &lag_member_info);
  CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);

  status = switch_lag_member_handle_delete(device, lag_member_handle);
  CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);

  return status;
}

switch_status_t switch_api_lag_update(
    const switch_device_t device,
    const switch_handle_t lag_handle,
    const switch_handle_t lag_member_handle) {
  switch_lag_info_t *lag_info = NULL;
  switch_lag_member_info_t *lag_member_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (!SWITCH_LAG_HANDLE(lag_handle)) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    krnlmon_log_error(
        "lag get: Invalid lag handle on device %d, "
        "lag handle 0x%lx: "
        "error: %s\n",
        device,
        lag_handle,
        switch_error_to_string(status));
    return status;
  }

  status = switch_lag_get(device, lag_handle, &lag_info);
  CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);

  if (!SWITCH_LAG_MEMBER_HANDLE(lag_member_handle)) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    krnlmon_log_error(
        "lag get: Invalid lag member handle on device %d, "
        "lag member handle 0x%lx: "
        "error: %s\n",
        device,
        lag_member_handle,
        switch_error_to_string(status));
    return status;
  }

  status = switch_lag_member_get(device,
      lag_member_handle, &lag_member_info);
  CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);

  // update lag member list with the lag_member_handle
  status = SWITCH_LIST_INSERT(
        &(lag_info->lag_members), &(lag_member_info->node), lag_member_info);
  SWITCH_ASSERT(status == SWITCH_STATUS_SUCCESS);

  return status;
}

switch_status_t switch_api_program_lag_hw(switch_handle_t lag_h,
    switch_handle_t active_lag_member_handle) {
  switch_lag_info_t *lag_info = NULL;
  switch_device_t device = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  
  if (!SWITCH_LAG_HANDLE(lag_h)) {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    krnlmon_log_error(
        "lag get: Invalid lag handle on device %d, "
        "lag handle 0x%lx: "
        "error: %s\n",
        device,
        lag_h,
        switch_error_to_string(status));
    return status;
  }

  status = switch_lag_get(device, lag_h, &lag_info);
  CHECK_RET(status != SWITCH_STATUS_SUCCESS, status);

  // pd call to program MEV-TS
  status = switch_pd_lag_entry(device, lag_info, true);
  if (status != SWITCH_STATUS_SUCCESS) {
      krnlmon_log_error(
          "Failed to create lag entry on device %d: "
          ",error: %s\n",
          device,
          switch_error_to_string(status));
      return status;
  }
  return status;
}
