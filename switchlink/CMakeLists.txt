# CMake build file for krnlmon/switchlink
#
# Copyright 2022 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

cmake_minimum_required(VERSION 3.5)

add_library(switchlink_o OBJECT
   switchlink_address.c
   switchlink_db.c
   switchlink_db.h
   switchlink_db_int.h
   switchlink.h
   switchlink_int.h
   switchlink_link.c
   switchlink_link.h
   switchlink_main.c
   switchlink_neigh.c
   switchlink_neigh.h
   switchlink_route.c
   switchlink_route.h
   switchlink_sai.c
   switchlink_sai.h
   switchlink_handle.h
   switchlink_handle_link.c
   switchlink_handle_tunnel.c
   switchlink_handle_neigh.c
   switchlink_handle_route.c
   switchlink_handle_nexthop.c
   switchlink_utils.c
   switchlink_utils.h
   switchlink_handle_ecmp.c
)

target_compile_options(switchlink_o PRIVATE -DHAVE_NLA_BITFIELD32)

target_include_directories(switchlink_o PRIVATE
    /usr/include/libnl3
    ${SDE_INSTALL_PREFIX}/include/target-utils/third-party  # judy
    ${SDE_INSTALL_PREFIX}/include/target-utils/third-party/tommyds
    ${SDE_INSTALL_PREFIX}/include/target-utils/third-party/xxHash
    ${SDE_INSTALL_PREFIX}/include/target-sys
    ${SAI_SOURCE_DIR}/inc
)
