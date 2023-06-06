# Switchlink unit tests
#
# Copyright 2023 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

option(TEST_COVERAGE OFF "Measure unit test code coverage")

####################
# set_test_options #
####################

function(set_test_options _TGT)
    target_link_libraries(${_TGT} PUBLIC
        GTest::gtest
        GTest::gtest_main
        PkgConfig::libnl3
        target_sys
    )

    target_link_directories(${_TGT} PUBLIC ${DRIVER_SDK_DIRS})

    target_include_directories(${_TGT} PRIVATE
        ${SDE_INSTALL_DIR}/include/target-sys
    )

    if(TEST_COVERAGE)
        target_compile_options(${_TGT} PRIVATE -fprofile-arcs -ftest-coverage)
        target_link_libraries(${_TGT} PUBLIC gcov)
    endif()
endfunction()

########################
# switchlink_link_test #
########################

add_executable(switchlink_link_test
    switchlink_link_test.cc
    switchlink_link.c
    switchlink_link.h
)

set_test_options(switchlink_link_test)

add_test(NAME switchlink_link_test COMMAND switchlink_link_test)

###########################
# switchlink_address_test #
###########################

add_executable(switchlink_address_test
    switchlink_address_test.cc
    switchlink_address.c
)

set_test_options(switchlink_address_test)

add_test(NAME switchlink_address_test COMMAND switchlink_address_test)

############################
# switchlink_neighbor_test #
############################

add_executable(switchlink_neighbor_test
    switchlink_neigh_test.cc
    switchlink_neigh.c
    switchlink_neigh.h
)

set_test_options(switchlink_neighbor_test)

add_test(NAME switchlink_neighbor_test COMMAND switchlink_neighbor_test)

