# CMake build file for krnlmon/switchlink
#
# Copyright 2022 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

cmake_minimum_required(VERSION 3.5)

include(FindPkgConfig)

# Find netlink libraries
pkg_check_modules(libnl3 REQUIRED IMPORTED_TARGET libnl-3.0 libnl-route-3.0)

add_subdirectory(sai)

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
   switchlink_handle.h
   switchlink_utils.c
   switchlink_utils.h
   $<TARGET_OBJECTS:switchlink_sai_o>
)

target_compile_options(switchlink_o PRIVATE -DHAVE_NLA_BITFIELD32)

target_link_libraries(switchlink_o PkgConfig::libnl3)

target_include_directories(switchlink_o PRIVATE
    ${SDE_INSTALL_DIR}/include/target-utils/third-party  # judy
    ${SDE_INSTALL_DIR}/include/target-utils/third-party/tommyds
    ${SDE_INSTALL_DIR}/include/target-utils/third-party/xxHash
    ${SDE_INSTALL_DIR}/include/target-sys
    ${SAI_SOURCE_DIR}/inc
)
