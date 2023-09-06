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

#include "switchlink_init_sai.h"

static sai_lag_api_t* sai_lag_api = NULL;

/*
 * Routine Description:
 *    Initialize LAG SAI API
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t sai_init_lag_api() {
  sai_status_t status = SAI_STATUS_SUCCESS;

  status = sai_api_query(SAI_API_LAG, (void**)&sai_lag_api);
  krnlmon_assert(status == SAI_STATUS_SUCCESS);

  return status;
}

/*
 * Routine Description:
 *    SAI call to create lag
 *
 * Arguments:
 *    [in] lag - lag info
 *    [out] lag_h - lag handle
 *
 * Return Values:
 *    0 on success
 *   -1 in case of error
 */
static int create_lag(const switchlink_db_lag_info_t* lag_intf,
                      switchlink_handle_t* lag_h) {
  int ac = 0;
  sai_attribute_t attr_list[5];
  memset(attr_list, 0, sizeof(attr_list));
  return sai_lag_api->create_lag(lag_h, 0, ac, attr_list);
}

/*
 * Routine Description:
 *    SAI call to delete lag
 *
 * Arguments:
 *    [in] lag - lag info
 *    [in] lag_h - lag handle
 *
 * Return Values:
 *    0 on success
 *   -1 in case of error
 */
static int delete_lag(const switchlink_db_lag_info_t* lag,
                      switchlink_handle_t lag_h) {
  sai_status_t status = SAI_STATUS_SUCCESS;
  status = sai_lag_api->remove_lag(lag_h);
  return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

/*
 * Routine Description:
 *    SAI call to set lag attribute
 *
 * Arguments:
 *    [in] lag - lag info
 *    [out] lag_h - lag member handle
 *
 * Return Values:
 *    0 on success
 *   -1 in case of error
 */
static int set_lag_attribute(const switchlink_db_lag_info_t* lag_info,
                             switchlink_handle_t lag_member_h) {
  sai_attribute_t attr;
  memset(&attr, 0, sizeof(attr));

  attr.id = SAI_LAG_ATTR_PORT_LIST;
  attr.value.objlist.list[0] = lag_member_h;
  return sai_lag_api->set_lag_attribute(lag_info->lag_h, &attr);
}

/*
 * Routine Description:
 *    SAI call to create lag member
 *
 * Arguments:
 *    [in] lag - lag member info
 *    [out] lag_member_h - lag member handle
 *
 * Return Values:
 *    0 on success
 *   -1 in case of error
 */
static int create_lag_member(
    const switchlink_db_lag_member_info_t* lag_member_intf,
    switchlink_handle_t* lag_member_h) {
  sai_attribute_t attr_list[5];
  int ac = 0;
  memset(attr_list, 0, sizeof(attr_list));
  attr_list[ac].id = SAI_LAG_MEMBER_ATTR_LAG_ID;
  attr_list[ac].value.oid = lag_member_intf->lag_h;
  ac++;
  return sai_lag_api->create_lag_member(lag_member_h, 0, ac, attr_list);
}

/*
 * Routine Description:
 *    SAI call to delete lag member
 *
 * Arguments:
 *    [in] lag - lag member info
 *    [in] lag_member_h - lag member handle
 *
 * Return Values:
 *    0 on success
 *   -1 in case of error
 */
static int delete_lag_member(const switchlink_db_lag_member_info_t* lag_member,
                             switchlink_handle_t lag_member_h) {
  sai_status_t status = SAI_STATUS_SUCCESS;
  status = sai_lag_api->remove_lag_member(lag_member_h);
  return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

/*
 * Routine Description:
 *    Wrapper function to create lag
 *
 * Arguments:
 *    [in/out] lag - lag info
 *
 * Return Values:
 *    void
 */
void switchlink_create_lag(switchlink_db_lag_info_t* lag_intf) {
  switchlink_db_status_t status;
  switchlink_db_lag_info_t lag_info;

  memset(&lag_info, 0, sizeof(switchlink_db_lag_info_t));
  lag_info.ifindex = lag_intf->ifindex;

  status = switchlink_db_get_lag_info(&lag_info);
  if (status == SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND) {
    // create the lag
    krnlmon_log_debug("Switchlink LAG Create: %s", lag_intf->ifname);

    status = create_lag(lag_intf, &(lag_intf->lag_h));
    if (status) {
      krnlmon_log_error(
          "newlink: Failed to create switchlink lag: %s, error: %d\n",
          lag_intf->ifname, status);
      return;
    }
    // add the mapping to the db
    switchlink_db_add_lag(lag_intf);
    return;
  } else {
    krnlmon_log_debug("Switchlink DB already has LAG config: %s",
                      lag_intf->ifname);
    // check if active_slave attribute is updated.
    if (lag_intf->active_slave != lag_info.active_slave) {
      // need to program MEV-TS with new active_slave info
      // get the lag member handle with ifindex = active_slave
      switchlink_db_lag_member_info_t lag_member_info;
      memset(&lag_member_info, 0, sizeof(switchlink_db_lag_member_info_t));
      lag_member_info.ifindex = lag_intf->active_slave;
      status = switchlink_db_get_lag_member_info(&lag_member_info);
      if (status == SWITCHLINK_DB_STATUS_SUCCESS) {
        status = set_lag_attribute(lag_intf, lag_member_info.lag_member_h);
        if (status) {
          krnlmon_log_error(
              "newlink: Failed to update switchlink lag: %s, error: %d\n",
              lag_intf->ifname, status);
          return;
        }
      }
    }
    // update the db structure
    switchlink_db_update_lag_active_slave(lag_intf);
    return;
  }
  return;
}

/*
 * Routine Description:
 *    Wrapper function to delete lag
 *
 * Arguments:
 *    [in] ifindex - lag ifindex
 *
 * Return Values:
 *    void
 */
void switchlink_delete_lag(uint32_t ifindex) {
  switchlink_db_lag_info_t lag_info;
  memset(&lag_info, 0, sizeof(switchlink_db_lag_info_t));
  lag_info.ifindex = ifindex;
  if (switchlink_db_get_lag_info(&lag_info) ==
      SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND) {
    return;
  }

  // delete the lag from backend and DB
  delete_lag(&lag_info, lag_info.lag_h);
  switchlink_db_delete_lag(&lag_info);
}

/*
 * Routine Description:
 *    Wrapper function to create lag member
 *
 * Arguments:
 *    [in/out] lag - lag member info
 *
 * Return Values:
 *    void
 */
void switchlink_create_lag_member(
    switchlink_db_lag_member_info_t* lag_member_intf) {
  switchlink_db_status_t status;
  switchlink_db_lag_member_info_t lag_member_info;

  memset(&lag_member_info, 0, sizeof(switchlink_db_lag_member_info_t));
  lag_member_info.ifindex = lag_member_intf->ifindex;

  status = switchlink_db_get_lag_member_info(&lag_member_info);
  if (status == SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND) {
    // find the parent lag handle
    lag_member_intf->lag_h =
        switchlink_db_get_lag_handle(lag_member_intf->mac_addr);
    if (lag_member_intf->lag_h == SWITCH_API_INVALID_HANDLE) {
      krnlmon_log_debug("Not able to find parent lag handle");
    }

    // create the lag member
    krnlmon_log_debug("Switchlink LAG Member Create: %s",
                      lag_member_intf->ifname);
    status =
        create_lag_member(lag_member_intf, &(lag_member_intf->lag_member_h));
    if (status) {
      krnlmon_log_error(
          "newlink: Failed to create switchlink lag member: %s, error: %d\n",
          lag_member_intf->ifname, status);
      return;
    }
    // add the mapping to the db
    switchlink_db_add_lag_member(lag_member_intf);
    return;
  }
  // lag member has already been created
  krnlmon_log_debug("Switchlink DB already has LAG config: %s",
                    lag_member_intf->ifname);
  return;
}

/*
 * Routine Description:
 *    Wrapper function to delete lag member
 *
 * Arguments:
 *    [in] ifindex - lag member ifindex
 *
 * Return Values:
 *    void
 */
void switchlink_delete_lag_member(uint32_t ifindex) {
  switchlink_db_lag_member_info_t lag_member_info;
  memset(&lag_member_info, 0, sizeof(switchlink_db_lag_member_info_t));
  lag_member_info.ifindex = ifindex;
  if (switchlink_db_get_lag_member_info(&lag_member_info) ==
      SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND) {
    return;
  }

  // delete the lag member from backend and DB
  delete_lag_member(&lag_member_info, lag_member_info.lag_member_h);
  switchlink_db_delete_lag_member(&lag_member_info);
}
