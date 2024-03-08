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

#include "pdal_status.h"

static const char* pdal_err_strings[PDAL_STS_MAX + 1] = {
#define PDAL_STATUS_(x, y) y
    PDAL_STATUS_VALUES, "Unknown error"
#undef PDAL_STATUS_
};

const char* pdal_err_str(pdal_status_t sts) {
  if (PDAL_STS_MAX <= sts || 0 > sts) {
    return pdal_err_strings[PDAL_STS_MAX];
  } else {
    return pdal_err_strings[sts];
  }
}
