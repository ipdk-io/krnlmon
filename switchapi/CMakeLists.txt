# CMake build file for krnlmon/switchapi
#
# Copyright 2022 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

cmake_minimum_required(VERSION 3.5)

project(switchapi)

add_library(switchapi_o OBJECT
    switch_base_types.h
    switch_port.h
    switch_port.c
    switch_pd_port.c
    switch_handle.h
    switch_internal.h
    switch_id.h
    switch_interface.h
    switch_port_int.h
    switch_status.h
    switch_tunnel.h
)

target_include_directories(switchapi_o PRIVATE
    ${OVS_INSTALL_PREFIX}/include
    ${SDE_INSTALL_PREFIX}/include
    ${SDE_INSTALL_PREFIX}/include/target-utils/third-party
    ${SDE_INSTALL_PREFIX}/include/target-utils/third-party/tommyds
    ${SDE_INSTALL_PREFIX}/include/target-sys
)
