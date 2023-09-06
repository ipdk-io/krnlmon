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

#ifndef __SWITCH_LAG_H__
#define __SWITCH_LAG_H__

#include "switch_base_types.h"
#include "switch_types_int.h"
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SWITCH_LAG_MAX 4

/** lag handle wrappers */
#define switch_lag_handle_create(_device)               \
  switch_handle_create(_device, SWITCH_HANDLE_TYPE_LAG, \
                       sizeof(switch_lag_info_t))

#define switch_lag_handle_delete(_device, _handle) \
  switch_handle_delete(_device, SWITCH_HANDLE_TYPE_LAG, _handle)

#define switch_lag_get(_device, _handle, _info)                 \
  ({                                                            \
    switch_lag_info_t* _tmp_lag_info = NULL;                    \
    (void)(_tmp_lag_info == *_info);                            \
    switch_handle_get(_device, SWITCH_HANDLE_TYPE_LAG, _handle, \
                      (void**)_info);                           \
  })

#define switch_lag_member_handle_create(_device)               \
  switch_handle_create(_device, SWITCH_HANDLE_TYPE_LAG_MEMBER, \
                       sizeof(switch_lag_member_info_t))

#define switch_lag_member_handle_delete(_device, _handle) \
  switch_handle_delete(_device, SWITCH_HANDLE_TYPE_LAG_MEMBER, _handle)

#define switch_lag_member_get(_device, _handle, _info)                 \
  ({                                                                   \
    switch_lag_member_info_t* _tmp_lag_member_info = NULL;             \
    (void)(_tmp_lag_member_info == *_info);                            \
    switch_handle_get(_device, SWITCH_HANDLE_TYPE_LAG_MEMBER, _handle, \
                      (void**)_info);                                  \
  })

/** Lag information */
typedef struct switch_api_lag_info_s {
  uint32_t lag_ifindex;
  uint32_t lag_mode;
  uint32_t active_slave;
} switch_api_lag_info_t;

typedef struct switch_lag_info_s {
  switch_api_lag_info_t api_lag_info;
  switch_list_t lag_members;
  switch_handle_t lag_handle;
  switch_handle_t active_lag_member;
} switch_lag_info_t;

/** Lag member information */
typedef struct switch_api_lag_member_info_s {
  uint32_t lag_member_ifindex;
  uint8_t slave_state;
} switch_api_lag_member_info_t;

typedef struct switch_lag_member_info_s {
  switch_api_lag_member_info_t api_lag_member_info;
  switch_handle_t lag_member_handle;
  switch_node_t node;
} switch_lag_member_info_t;

switch_status_t switch_api_lag_create(switch_device_t device,
                                      switch_api_lag_info_t* api_lag_info,
                                      switch_handle_t* lag_handle);

switch_status_t switch_api_lag_delete(switch_device_t device,
                                      switch_handle_t lag_handle);

switch_status_t switch_api_lag_member_create(
    switch_device_t device, switch_api_lag_member_info_t* api_lag_member_info,
    switch_handle_t* lag_member_handle);

switch_status_t switch_api_lag_member_delete(switch_device_t device,
                                             switch_handle_t lag_member_handle);

switch_status_t switch_api_lag_update(
    const switch_device_t device, const switch_handle_t lag_handle,
    const switch_handle_t lag_member_handle);

switch_status_t switch_api_program_lag_hw(switch_handle_t lag_handle,
		switch_handle_t lag_member_handle);

#ifdef __cplusplus
}
#endif

#endif /* __SWITCH_LAG_H__ */
