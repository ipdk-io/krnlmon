// Copyright 2022 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include "krnlmon_main.h"

#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>

extern void *switchlink_main(void *);
extern void *switchlink_stop(void *);

static pthread_t krnlmon_start_tid;
static pthread_t krnlmon_stop_tid;

int krnlmon_init(void) {
     int rc = pthread_create(&krnlmon_start_tid, NULL, switchlink_main, NULL);
     if (rc) {
        printf("Switchlink thread creation failed, error: %d", rc);
        return -1;
     }
     pthread_setname_np(krnlmon_start_tid, "switchlink_main");

  return 0;
}

int krnlmon_shutdown(void)
{
     int rc = pthread_create(&krnlmon_stop_tid, NULL, switchlink_stop, NULL);
     if (rc) {
        printf("Switchlink thread stop failed, error: %d", rc);
        return -1;
     }
     pthread_setname_np(krnlmon_stop_tid, "switchlink_stop");
}
