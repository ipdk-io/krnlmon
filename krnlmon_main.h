// Copyright 2022 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#ifndef KRNLMON_MAIN_H_
#define KRNLMON_MAIN_H_

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif	
int krnlmon_init(void);
void krnlmon_shutdown(void);
#ifdef __cplusplus
}
#endif

#endif  // KRNLMON_MAIN_H_
