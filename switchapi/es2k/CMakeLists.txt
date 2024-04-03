# CMake build file for krnlmon/switchapi/es2k
#
# Copyright 2022-2024 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

target_sources(switchapi_o PRIVATE
  switch_config.c
  switch_device.c
  switch_fdb.c
  switch_handle.c
  switch_id.c
  switch_l3.c
  switch_lag.c
  switch_neighbor.c
  switch_nhop.c
  switch_pd_fdb.c
  switch_pd_p4_name_mapping.h
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

if(LNW_V2)
  add_subdirectory(lnw_v2)
elseif(LNW_V3)
  add_subdirectory(lnw_v3)
endif()

target_include_directories(switchapi_o PRIVATE
  ${SDE_INSTALL_DIR}/include
  ${SDE_INSTALL_DIR}/include/bf_types
  ${SDE_INSTALL_DIR}/include/target-utils # id
  ${SDE_INSTALL_DIR}/include/target-utils/third-party
  ${SDE_INSTALL_DIR}/include/target-utils/third-party/tommyds
  ${SDE_INSTALL_DIR}/include/target-sys
)

target_link_libraries(switchapi_o PRIVATE
  sde::tdi
  sde::tdi_json_parser
)
