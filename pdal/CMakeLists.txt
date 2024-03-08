# CMake build file for krnlmon/pdal
#
# Copyright 2024 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#

add_library(pdal_o OBJECT
  pdal.h
  pdal_status.c
  pdal_status.h
)

if(ES2K_TARGET)
  target_sources(pdal_o PRIVATE pdal_es2k.c)
else()
  target_sources(pdal_o PRIVATE pdal_legacy.c)
endif()

target_include_directories(pdal_o PUBLIC ${SDE_INSTALL_DIR}/include)
