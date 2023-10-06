# standalone.cmake
#
# Copyright 2022-2023 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#
# Initialization for standalone krnlmon build.
#

include(CTest)
include(GNUInstallDirs)

message(STATUS "Standalone krnlmon build")

#-----------------------------------------------------------------------
# Build type
#-----------------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING
      "Choose the build type" FORCE)

  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
    "Debug;MinSizeRel;Release;RelWithDebInfo")
endif()

#-----------------------------------------------------------------------
# Path definitions
#-----------------------------------------------------------------------
set(DEPEND_INSTALL_DIR "$ENV{DEPEND_INSTALL}" CACHE PATH
    "Dependencies install directory")

set(SDE_INSTALL_DIR "$ENV{SDE_INSTALL}" CACHE PATH
    "SDE install directory")

if(SDE_INSTALL_DIR STREQUAL "")
  message(FATAL_ERROR "SDE_INSTALL_DIR (SDE_INSTALL) not defined!")
elseif(DEPEND_INSTALL_DIR STREQUAL "")
  message(FATAL_ERROR "DEPEND_INSTALL_DIR (DEPEND_INSTALL) not defined!")
endif()

#-----------------------------------------------------------------------
# Target selection
#-----------------------------------------------------------------------
include(SelectTdiTarget)
add_compile_options(-D${TARGETFLAG})

#-----------------------------------------------------------------------
# P4 Driver
#-----------------------------------------------------------------------
if(DPDK_TARGET)
  find_package(DpdkDriver)
elseif(ES2K_TARGET)
  find_package(Es2kDriver)
elseif(TOFINO_TARGET)
  message(FATAL_ERROR "Tofino target not supported")
endif()

#-----------------------------------------------------------------------
# Search paths
#-----------------------------------------------------------------------
if(CMAKE_CROSSCOMPILING)
  list(APPEND CMAKE_FIND_ROOT_PATH ${DEPEND_INSTALL_DIR})
else()
  list(APPEND CMAKE_PREFIX_PATH ${DEPEND_INSTALL_DIR})
endif()

#-----------------------------------------------------------------------
# Abseil
#-----------------------------------------------------------------------
find_package(absl CONFIG REQUIRED PATHS)
mark_as_advanced(absl_DIR)

message(STATUS "Found Abseil version ${absl_VERSION}")

if(absl_VERSION VERSION_GREATER_EQUAL "20230125")
  add_compile_definitions(ABSL_LEGACY_THREAD_ANNOTATIONS)
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
