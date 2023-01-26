# CMake build file for Kernel Monitor
#
# Copyright 2022 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#

# TODO: Make Kernel Monitor a package.
cmake_minimum_required(VERSION 3.5)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_compile_options(-Werror)

include_directories(.)

add_subdirectory(switchapi)
add_subdirectory(switchlink)
add_subdirectory(switchsai)
add_subdirectory(switchutils)

add_library(krnlmon SHARED
    $<TARGET_OBJECTS:switchapi_o>
    $<TARGET_OBJECTS:switchlink_o>
    $<TARGET_OBJECTS:switchsai_o>
    $<TARGET_OBJECTS:switchutils_o>
    $<TARGET_OBJECTS:switchlink_sai_o>
    krnlmon_main.cc
    krnlmon_main.h
)

target_link_libraries(krnlmon nl-route-3 nl-3)

configure_file(libkrnlmon.sym.in
               ${CMAKE_CURRENT_BINARY_DIR}/libkrnlmon.sym @ONLY)

set_target_properties(krnlmon PROPERTIES
    LINK_OPTIONS -Wl,--version-script=libkrnlmon.sym
    LINK_DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/libkrnlmon.sym
)

# Version number for .pc file.
set(VERSION 1.0)

# TODO: Look into using configure_package_config_file()
configure_file(libkrnlmon.pc.in
               ${CMAKE_CURRENT_BINARY_DIR}/libkrnlmon.pc @ONLY)

install(TARGETS krnlmon LIBRARY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libkrnlmon.pc
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/pkgconfig)
