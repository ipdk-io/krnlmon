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
    switchlink_mdb.c
    switchlink_neigh.c
    switchlink_neigh.h
    switchlink_netconf.c
    switchlink_packet.c
    switchlink_packet.h
    switchlink_route.c
    switchlink_route.h
    switchlink_sai.c
    switchlink_sai.h
)

target_compile_options(switchlink_o PRIVATE -DHAVE_NLA_BITFIELD32)

target_include_directories(switchlink_o PRIVATE
    /usr/include/libnl3
    ${SDE_INSTALL_PREFIX}/include  # judy
    ${SDE_INSTALL_PREFIX}/include/target-utils/third-party/tommyds
    ${SDE_INSTALL_PREFIX}/include/target-utils/third-party/xxHash
    ${SAI_SOURCE_DIR}/inc
    ${OVS_INSTALL_PREFIX}/include
    ${OVS_SOURCE_DIR}
)
