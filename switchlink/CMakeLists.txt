# CMake build file for krnlmon/switchlink
#
# Copyright 2022-2023 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

include(FindGTest)
mark_as_advanced(GTest_DIR)

add_subdirectory(sai)

add_library(switchlink_o OBJECT
    switchlink_address.c
    switchlink_db.c
    switchlink_db.h
    switchlink_db_int.h
    switchlink.h
    switchlink_globals.c
    switchlink_handlers.h
    switchlink_int.h
    switchlink_link.c
    switchlink_link.h
    switchlink_main.c
    switchlink_main.h
    switchlink_neigh.c
    switchlink_neigh.h
    switchlink_route.c
    switchlink_route.h
    switchlink_utils.c
    switchlink_utils.h
    $<TARGET_OBJECTS:switchlink_sai_o>
)

target_compile_options(switchlink_o PRIVATE -DHAVE_NLA_BITFIELD32)

if(WITH_OVSP4RT)
    target_compile_definitions(switchlink_o PRIVATE OVSP4RT_SUPPORT)
endif()

target_link_libraries(switchlink_o PkgConfig::nl3)

target_include_directories(switchlink_o PRIVATE
    ${SDE_INSTALL_DIR}/include/target-utils/third-party  # judy
    ${SDE_INSTALL_DIR}/include/target-utils/third-party/tommyds
    ${SDE_INSTALL_DIR}/include/target-utils/third-party/xxHash
    ${SDE_INSTALL_DIR}/include/target-sys
    ${SAI_INCLUDE_DIR}
)

if(BUILD_TESTING)
    include(testing.cmake)
endif()
