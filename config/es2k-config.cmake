# CMake build configuration for ES2K target

#-----------------------------------------------------------------------
# Set build variables for ES2K
#-----------------------------------------------------------------------
set(DEPEND_INSTALL_DIR "/opt/deps" CACHE PATH
    "config: Dependencies install directory")

get_filename_component(_path "/opt/p4sde/es2k" REALPATH)
set(SDE_INSTALL_DIR "${_path}" CACHE PATH "config: SDE install directory")

set(CMAKE_INSTALL_PREFIX "${CMAKE_SOURCE_DIR}/install" CACHE PATH "")

set(TDI_TARGET "es2k" CACHE STRING "config: TDI target type")

unset(_path)
