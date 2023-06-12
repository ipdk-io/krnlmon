# CMake build file for krnlmon/switchapi/dpdk
#
# Copyright 2022-2023 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

add_library(switchapi_target_o OBJECT
  switch_config.c
  switch_device.c
  switch_fdb.c
  switch_handle.c
  switch_id.c
  switch_l3.c
  switch_neighbor.c
  switch_nhop.c
  switch_pd_fdb.c
  switch_pd_p4_name_mapping.h
  switch_pd_routing.c
  switch_pd_routing.h
  switch_pd_tunnel.c
  switch_pd_utils.c
  switch_pd_utils.h
  switch_rif.c
  switch_rmac.c
  switch_table.c
  switch_tunnel.c
  switch_vrf.c
  switchapi_utils.c
)

target_include_directories(switchapi_target_o PRIVATE
  ${SDE_INSTALL_DIR}/include
  ${SDE_INSTALL_DIR}/include/bf_types
  ${SDE_INSTALL_DIR}/include/target-utils # id
  ${SDE_INSTALL_DIR}/include/target-utils/third-party
  ${SDE_INSTALL_DIR}/include/target-utils/third-party/tommyds
  ${SDE_INSTALL_DIR}/include/target-sys
)

find_library(TDI tdi)
find_library(TDI_JSON_PARSER tdi_json_parser)

target_link_libraries(switchapi_target_o PRIVATE
  ${TDI} ${TDI_JSON_PARSER})
