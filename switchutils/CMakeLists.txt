# CMake build file for krnlmon/switchapi
#
# Copyright 2022 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

cmake_minimum_required(VERSION 3.5)

add_library(switchutils_o OBJECT
    switch_utils.h
    switch_log.h
)

target_include_directories(switchutils_o PRIVATE
    ${SDE_INSTALL_DIR}/include/target-sys # zlog
)
