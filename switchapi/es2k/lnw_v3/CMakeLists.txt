# CMake build file for switchapi/es2k/lnw_v3
#
# Copyright 2022-2024 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

target_sources(switchapi_o PRIVATE
  switch_pd_p4_name_routing.h
  switch_pd_routing.c
  switch_pd_lag.c
  switch_pd_lag.h
)
