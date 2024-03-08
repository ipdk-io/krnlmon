/*
 * Copyright 2021-2024 Intel Corporation.
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
 */

#ifndef _PDAL_STATUS_H_
#define _PDAL_STATUS_H_

#ifndef PDAL_STATUS_DEFINED_
/** Specifies an error code. */
typedef int pdal_status_t;
#define PDAL_STATUS_DEFINED_
#endif

#define PDAL_STATUS_VALUES                                                    \
  PDAL_STATUS_(PDAL_SUCCESS, "Success"),                                      \
      PDAL_STATUS_(PDAL_NOT_READY, "Not ready"),                              \
      PDAL_STATUS_(PDAL_NO_SYS_RESOURCES, "No system resources"),             \
      PDAL_STATUS_(PDAL_INVALID_ARG, "Invalid arguments"),                    \
      PDAL_STATUS_(PDAL_ALREADY_EXISTS, "Already exists"),                    \
      PDAL_STATUS_(PDAL_HW_COMM_FAIL, "HW access fails"),                     \
      PDAL_STATUS_(PDAL_OBJECT_NOT_FOUND, "Object not found"),                \
      PDAL_STATUS_(PDAL_MAX_SESSIONS_EXCEEDED, "Max sessions exceeded"),      \
      PDAL_STATUS_(PDAL_SESSION_NOT_FOUND, "Session not found"),              \
      PDAL_STATUS_(PDAL_NO_SPACE, "Not enough space"),                        \
      PDAL_STATUS_(PDAL_EAGAIN,                                               \
                   "Resource temporarily not available, try again later"),    \
      PDAL_STATUS_(PDAL_INIT_ERROR, "Initialization error"),                  \
      PDAL_STATUS_(PDAL_TXN_NOT_SUPPORTED, "Not supported in transaction"),   \
      PDAL_STATUS_(PDAL_TABLE_LOCKED, "Resource held by another session"),    \
      PDAL_STATUS_(PDAL_IO, "IO error"),                                      \
      PDAL_STATUS_(PDAL_UNEXPECTED, "Unexpected error"),                      \
      PDAL_STATUS_(PDAL_ENTRY_REFERENCES_EXIST,                               \
                   "Action data entry is being referenced by match entries"), \
      PDAL_STATUS_(PDAL_NOT_SUPPORTED, "Operation not supported"),            \
      PDAL_STATUS_(PDAL_HW_UPDATE_FAILED, "Updating hardware failed"),        \
      PDAL_STATUS_(PDAL_NO_LEARN_CLIENTS, "No learning clients registered"),  \
      PDAL_STATUS_(PDAL_IDLE_UPDATE_IN_PROGRESS,                              \
                   "Idle time update state already in progress"),             \
      PDAL_STATUS_(PDAL_DEVICE_LOCKED, "Device locked"),                      \
      PDAL_STATUS_(PDAL_INTERNAL_ERROR, "Internal error"),                    \
      PDAL_STATUS_(PDAL_TABLE_NOT_FOUND, "Table not found"),                  \
      PDAL_STATUS_(PDAL_IN_USE, "In use"),                                    \
      PDAL_STATUS_(PDAL_NOT_IMPLEMENTED, "Object not implemented")

#define PDAL_STATUS_(x, y) x
enum pdal_status_enum { PDAL_STATUS_VALUES, PDAL_STS_MAX };
#undef PDAL_STATUS_

const char* pdal_err_str(pdal_status_t sts);

#endif  // _PDAL_STATUS_H_
