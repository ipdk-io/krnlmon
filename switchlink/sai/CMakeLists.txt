# CMake build file for krnlmon/switchlink
#
# Copyright 2022 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

cmake_minimum_required(VERSION 3.5)

add_library(switchlink_sai_o OBJECT
   switchlink_handle_link.c
   switchlink_handle_tunnel.c
   switchlink_handle_neigh.c
   switchlink_handle_route.c
   switchlink_handle_nexthop.c
   switchlink_handle_ecmp.c
   switchlink_init_sai.c
   switchlink_init_sai.h
)

target_include_directories(switchlink_sai_o PRIVATE
    ${SDE_INSTALL_PREFIX}/include/target-utils/third-party  # judy
    ${SDE_INSTALL_PREFIX}/include/target-utils/third-party/tommyds
    ${SDE_INSTALL_PREFIX}/include/target-utils/third-party/xxHash
    ${SDE_INSTALL_PREFIX}/include/target-sys
    ${SAI_SOURCE_DIR}/inc
)


