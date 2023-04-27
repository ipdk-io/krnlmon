# Switchlink unit tests
#
# Copyright 2023 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

########################
# switchlink_link_test #
########################

add_executable(switchlink_link_test
    switchlink_link_test.cc
    switchlink_link.c
    switchlink_link.h
)

target_link_libraries(switchlink_link_test PUBLIC
    GTest::gtest
    GTest::gtest_main
    PkgConfig::libnl3
    target_sys
)

target_include_directories(switchlink_link_test PRIVATE
    ${SDE_INSTALL_DIR}/include/target-sys
)

target_link_directories(switchlink_link_test PUBLIC ${DRIVER_SDK_DIRS})

add_test(switchlink_link_test switchlink_link_test)

