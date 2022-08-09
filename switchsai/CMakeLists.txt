# CMake build file for krnlmon/switchsai
#
# Copyright 2022 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

cmake_minimum_required(VERSION 3.5)

add_library(switchsai_o OBJECT
   sai.c
   saiinternal.h
   saiport.c
   saifdb.c
   saineighbor.c
   sainexthop.c
   sairoute.c
   sairouterinterface.c
   saitunnel.c
   saiutils.c
   saivirtualrouter.c
   sainexthopgroup.c
)

target_include_directories(switchsai_o PRIVATE
    ${SAI_SOURCE_DIR}/inc
    ${SDE_INSTALL_PREFIX}/include
    ${SDE_INSTALL_PREFIX}/include/target-utils # id
    ${SDE_INSTALL_PREFIX}/include/target-utils/third-party
    ${SDE_INSTALL_PREFIX}/include/target-utils/third-party/tommyds
    ${SDE_INSTALL_PREFIX}/include/target-sys # bf_sal
    ${OVS_INSTALL_PREFIX}/include
)
