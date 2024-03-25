# CMake build file for krnlmon/switchsde
#
# Copyright 2024 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

###############
# switchsde_o #
###############

add_library(switchsde_o OBJECT
  ${SDE_PORT_INTF}
  sde_port_intf.h
  sde_status.c
  sde_status.h
  sde_types.h
)

if(DPDK_TARGET)
  target_sources(switchsde_o PRIVATE sde_legacy_port_intf.c)
elseif(ES2K_TARGET)
  target_sources(switchsde_o PRIVATE sde_es2k_port_intf.c)
endif()

target_include_directories(switchsde_o PUBLIC ${SDE_INSTALL_DIR}/include)
