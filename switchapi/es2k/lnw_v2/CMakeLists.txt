# CMake build file for krnlmon/switchapi/es2k/lnw_v2
#
# Copyright 2022-2023 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

add_library(switchapi_lnwv2_target_o OBJECT
  switch_pd_p4_name_routing.h
  switch_pd_routing.c
  switch_pd_routing.h
  switch_pd_lag.c
  switch_pd_lag.h
)

target_include_directories(switchapi_lnwv2_target_o PRIVATE
  ${SDE_INSTALL_DIR}/include
  ${SDE_INSTALL_DIR}/include/ipu_types
  ${SDE_INSTALL_DIR}/include/target-utils/third-party
  ${SDE_INSTALL_DIR}/include/target-utils/third-party/tommyds
  ${SDE_INSTALL_DIR}/include/target-sys
)

target_link_libraries(switchapi_lnwv2_target_o PRIVATE
  sde::tdi
  sde::tdi_json_parser
)
