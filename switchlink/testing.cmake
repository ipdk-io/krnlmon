# Switchlink unit tests
#
# Copyright 2023 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

option(TEST_COVERAGE OFF "Measure unit test code coverage")

##########################
# define_switchlink_test #
##########################

function(define_switchlink_test test_name)
    target_link_libraries(${test_name} PUBLIC
        GTest::gtest
        GTest::gtest_main
        PkgConfig::nl3
        target_sys
    )

    target_link_directories(${test_name} PUBLIC ${DRIVER_SDK_DIRS})

    target_include_directories(${test_name} PRIVATE
        ${SDE_INSTALL_DIR}/include/target-sys
    )

    if(TEST_COVERAGE)
        target_compile_options(${test_name} PRIVATE
            -fprofile-arcs
            -ftest-coverage
        )
        target_link_libraries(${test_name} PUBLIC gcov)
    endif()

    add_test(NAME ${test_name} COMMAND ${test_name})
endfunction()

########################
# switchlink_link_test #
########################

add_executable(switchlink_link_test
    switchlink_link_test.cc
    switchlink_globals.c
    switchlink_link.c
    switchlink_link.h
)

define_switchlink_test(switchlink_link_test)

###########################
# switchlink_address_test #
###########################

add_executable(switchlink_address_test
    switchlink_address_test.cc
    switchlink_address.c
    switchlink_globals.c
)

define_switchlink_test(switchlink_address_test)

############################
# switchlink_neighbor_test #
############################

add_executable(switchlink_neighbor_test
    switchlink_neigh_test.cc
    switchlink_globals.c
    switchlink_neigh.c
    switchlink_neigh.h
)

define_switchlink_test(switchlink_neighbor_test)

#########################
# switchlink_route_test #
#########################

add_executable(switchlink_route_test
    switchlink_route_test.cc
    switchlink_route.c
    switchlink_route.h
)

define_switchlink_test(switchlink_route_test)

################
# krnlmon-test #
################

if(TEST_COVERAGE)
    set(test_options -T test -T coverage)
endif()

# On-demand target to build and run the krnlmon tests with a
# minimum of configuration.
add_custom_target(krnlmon-test
  COMMAND
    ctest ${test_options}
  DEPENDS
    switchlink_link_test
    switchlink_address_test
    switchlink_neighbor_test
    switchlink_route_test
  WORKING_DIRECTORY
    ${CMAKE_BINARY_DIR}
)

unset(test_options)

set_target_properties(krnlmon-test PROPERTIES EXCLUDE_FROM_ALL TRUE)

####################
# krnlmon-coverage #
####################

add_custom_target(krnlmon-coverage
    lcov --capture --directory ${CMAKE_BINARY_DIR}
    --output-file krnlmon.info
  COMMAND
    genhtml krnlmon.info --output-directory coverage
  WORKING_DIRECTORY
    ${CMAKE_BINARY_DIR}/Testing
)

set_target_properties(krnlmon-coverage PROPERTIES EXCLUDE_FROM_ALL TRUE)
