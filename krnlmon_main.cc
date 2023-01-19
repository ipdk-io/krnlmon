// Copyright 2022 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include "krnlmon_main.h"

#include <pthread.h>
#include <stdio.h>

#include "absl/synchronization/notification.h"
#include "switchlink/switchlink_main.h"

static pthread_t main_tid;
static pthread_t stop_tid;

extern "C" {
// Ensure that the functions passed to pthread_create() have C interfaces.
static void *krnlmon_main_wrapper(void *arg);
static void *krnlmon_stop_wrapper(void *arg);
}

static void *krnlmon_main_wrapper(void *arg) {
  // Wait for stratum server to signal that it is ready.
  auto ready_sync = static_cast<absl::Notification*>(arg);
  ready_sync->WaitForNotification();

  // Start switchlink.
  switchlink_main();
  return nullptr;
}

static void *krnlmon_stop_wrapper(void *arg) {
  // Wait for stratum server to signal that it is done.
  auto done_sync = static_cast<absl::Notification*>(arg);
  done_sync->WaitForNotification();

  // Stop switchlink.
  switchlink_stop();
  return nullptr;
}

int krnlmon_create_main_thread(absl::Notification* ready_sync) {
  int rc = pthread_create(&main_tid, NULL, &krnlmon_main_wrapper, ready_sync);
  if (rc) {
     printf("Switchlink thread creation failed, error: %d", rc);
     return -1;
  }
  pthread_setname_np(main_tid, "switchlink_main");
  return 0;
}

int krnlmon_create_shutdown_thread(absl::Notification* done_sync) {
  int rc = pthread_create(&stop_tid, NULL, &krnlmon_stop_wrapper, done_sync);
  if (rc) {
     printf("Switchlink thread stop failed, error: %d", rc);
     return -1;
  }
  pthread_setname_np(stop_tid, "switchlink_stop");
  return 0;
}
