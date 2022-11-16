// Copyright 2022 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "krnlmon_main.h"

extern void *switchlink_main(void *);

static pthread_t krnlmon_tid;	

int krnlmon_init(void) {
     int rc = pthread_create(&krnlmon_tid, NULL, switchlink_main, NULL);
     if (rc) {
        printf("Switchlink thread creation failed, error: %d", rc);
        return -1;
     }
     pthread_setname_np(krnlmon_tid, "krnlmon_main");
     printf("krnlmon thread with ID %lu spawned", krnlmon_tid);

  return 0;
}

void krnlmon_shutdown(void)
{
    pthread_cancel(krnlmon_tid);
}
