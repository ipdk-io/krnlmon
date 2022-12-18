// Copyright 2022 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#ifndef KRNLMON_MAIN_H_
#define KRNLMON_MAIN_H_

#include "absl/synchronization/notification.h"

int krnlmon_init_main_thread(absl::Notification* ready);
int krnlmon_init_shutdown_thread(absl::Notification* done);

#endif  // KRNLMON_MAIN_H_
