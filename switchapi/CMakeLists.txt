# CMake build file for krnlmon/switchapi
#
# Copyright 2022 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

cmake_minimum_required(VERSION 3.5)

add_library(switchapi_o OBJECT
    switch_base_types.h
    switch_internal.h
    switch_interface.h
    switch_types_int.h
    switch_port_int.h
    switch_status.h
    switch_id.h
    switch_id.c
    switch_table.h
    switch_table.c
    switch_config_int.h
    switch_config.h
    switch_config.c
    switch_device_int.h
    switch_device.h
    switch_device.c
    switch_handle_int.h
    switch_handle.h
    switch_handle.c
    switchapi_utils.c
    switch_port.h
    switch_port.c
    switch_pd_port.c
    switch_tunnel.h
    switch_tunnel.c
    switch_pd_tunnel.c
    switch_rif.c
    switch_rif.h
    switch_rif_int.h
    switch_rmac.c
    switch_rmac_int.h
    switch_rmac.h
    switch_neighbor.c
    switch_neighbor.h
    switch_neighbor_int.h
    switch_nhop.c
    switch_nhop_int.h
    switch_nhop.h
    switch_pd_routing.c
    switch_pd_routing.h
    switch_fdb.h
    switch_fdb.c
    switch_pd_fdb.c
    switch_l3.c
    switch_l3.h
    switch_l3_int.h
    switch_vrf.c
    switch_vrf.h
    switch_pd_utils.c
    switch_pd_utils.h
    switch_pd_p4_name_mapping.h
)

target_include_directories(switchapi_o PRIVATE
    ${SDE_INSTALL_DIR}/include
    ${SDE_INSTALL_DIR}/include/bf_types
    ${SDE_INSTALL_DIR}/include/target-utils # id
    ${SDE_INSTALL_DIR}/include/target-utils/third-party
    ${SDE_INSTALL_DIR}/include/target-utils/third-party/tommyds
    ${SDE_INSTALL_DIR}/include/target-sys
)

find_library(TDI tdi)
find_library(TDI_JSON_PARSER tdi_json_parser)

target_link_libraries(switchapi_o PRIVATE
    ${TDI} ${TDI_JSON_PARSER})
