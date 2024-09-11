# CMake build configuration for DPDK target

#-----------------------------------------------------------------------
# Set build variables for DPDK
#-----------------------------------------------------------------------
set(DEPEND_INSTALL_DIR "$ENV{DEPEND_INSTALL}" CACHE PATH
    "config: Dependencies install directory")

set(SDE_INSTALL_DIR "$ENV{SDE_INSTALL}" CACHE PATH
    "config: SDE install directory")

set(CMAKE_INSTALL_PREFIX "${CMAKE_SOURCE_DIR}/install" CACHE PATH "")

set(TDI_TARGET "dpdk" CACHE STRING "config: TDI target type")

unset(_path)
