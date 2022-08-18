/*
 * Copyright (c) 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
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

#include "switch_utils.h"

/* zlog lib initialization */
int krnlmon_zlog_init(const char *arg1) {
  const char *cfg_file_name = arg1;

  if (dzlog_init(cfg_file_name, "KRNLMON") != 0) {
    printf("Failed to initialize dzlog with conf file %s\n",
           cfg_file_name);
    return -1;
  }

  return 0;
}

void krnlmon_zlog_close(void) {
  zlog_fini();
}
