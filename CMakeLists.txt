# CMake build file for Kernel Monitor
#
# Copyright 2022-2024 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#

# Version 3.15 is the baseline for P4 Control Plane.
cmake_minimum_required(VERSION 3.15)

project(krnlmon VERSION 2.0 LANGUAGES C CXX)

include(CMakePrintHelpers)
include(FindPkgConfig)
include(cmake/iwyu.cmake)

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  include(cmake/standalone.cmake)
endif()

if(SAI_SOURCE_DIR STREQUAL "")
  message(FATAL_ERROR "SAI_SOURCE_DIR not defined!")
endif()

set(SAI_INCLUDE_DIR ${SAI_SOURCE_DIR}/inc)
if(NOT EXISTS ${SAI_INCLUDE_DIR}/sai.h)
  message(FATAL_ERROR "sai.h not found")
endif()

# Find netlink libraries
pkg_check_modules(nl3 REQUIRED IMPORTED_TARGET libnl-3.0)
pkg_check_modules(nl3-route REQUIRED IMPORTED_TARGET libnl-route-3.0)
include_directories(${nl3_INCLUDE_DIRS})

if(ES2K_TARGET)
  string(STRIP "${LNW_VERSION}" LNW_VERSION)
  string(TOUPPER "${LNW_VERSION}" LNW_VERSION)

  if(LNW_VERSION STREQUAL "V2" OR LNW_VERSION STREQUAL "2")
    set(LNW_VERSION "V2" CACHE STRING "" FORCE)
  elseif(LNW_VERSION STREQUAL "V3" OR LNW_VERSION STREQUAL "3")
    set(LNW_VERSION "V3" CACHE STRING "" FORCE)
  elseif(LNW_VERSION STREQUAL "")
    set(LNW_VERSION "V3" CACHE STRING "" FORCE)
  else()
    message(FATAL_ERROR "Invalid LNW_VERSION: '${LNW_VERSION}'")
  endif()

  set(lnw_flag "LNW_${LNW_VERSION}")
  add_compile_options("-D${lnw_flag}")
  set(${lnw_flag} TRUE)
  unset(lnw_flag)
endif()

add_compile_options(-Werror)

include_directories(.)

if(BUILD_TESTING)
  include(cmake/testing.cmake)
endif()

add_subdirectory(switchapi)
add_subdirectory(switchlink)
add_subdirectory(switchsai)
add_subdirectory(switchsde)
add_subdirectory(switchutils)

##############
# libkrnlmon #
##############

add_library(krnlmon SHARED
  $<TARGET_OBJECTS:switchapi_o>
  $<TARGET_OBJECTS:switchlink_o>
  $<TARGET_OBJECTS:switchlink_sai_o>
  $<TARGET_OBJECTS:switchsai_o>
  $<TARGET_OBJECTS:switchsde_o>
  $<TARGET_OBJECTS:switchutils_o>
  krnlmon_main.cc
  krnlmon_main.h
)

# Required for Ninja.
set_target_properties(switchutils_o PROPERTIES LINKER_LANGUAGE "C")

target_link_libraries(krnlmon PkgConfig::nl3 PkgConfig::nl3-route)
target_link_libraries(krnlmon absl::synchronization)

#################
# libkrnlmon.pc #
#################

# TODO: Look into using configure_package_config_file()
configure_file(libkrnlmon.pc.in
               ${CMAKE_CURRENT_BINARY_DIR}/libkrnlmon.pc @ONLY)

install(TARGETS krnlmon LIBRARY)

install(
  FILES
    ${CMAKE_CURRENT_BINARY_DIR}/libkrnlmon.pc
  DESTINATION
    ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

#################
# dummy_krnlmon #
#################

add_executable(dummy_krnlmon EXCLUDE_FROM_ALL
  dummy_main.cc
)

target_link_libraries(dummy_krnlmon PUBLIC krnlmon)

if(DPDK_TARGET)
  add_dpdk_target_libraries(dummy_krnlmon)
elseif(ES2K_TARGET)
  add_es2k_target_libraries(dummy_krnlmon)
endif()
