# cmake -B build <other options> -DIWYU=ON
# cmake --build build >& iwyu.log

option(IWYU "Run include-what-you-use" OFF)

if(IWYU)
  find_program(IWYU_PATH NAMES include-what-you-use iwyu)
  if(NOT IWYU_PATH)
    message(FATAL_ERROR "Could not find include-what-you-use")
  endif()
  mark_as_advanced(IWYU_PATH)
  set(CMAKE_CXX_INCLUDE_WHAT_YOU_USE ${IWYU_PATH})
  set(CMAKE_C_INCLUDE_WHAT_YOU_USE ${IWYU_PATH})
  message("IWYU enabled")
endif()
