cmake_minimum_required (VERSION 3.5)
project (sase2019)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

enable_testing()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -Wno-unused-function")
find_package(PkgConfig REQUIRED)

if(ENABLE_AFL AND ENABLE_SCAN_BUILD)
    message(FATAL_ERROR "ENABLE_AFL and ENABLE_SCAN_BUILD may not be enabled at the same time")
endif()

if(ENABLE_AFL)
    set(CMAKE_C_COMPILER /usr/bin/afl-gcc)
    set(CMAKE_CXX_COMPILER /usr/bin/afl-g++)
elseif(ENABLE_SCAN_BUILD)
    set(CMAKE_C_COMPILER /usr/lib/clang/ccc-analyzer)
    set(CMAKE_CXX_COMPILER /usr/lib/clang/c++-analyzer)
endif()

add_subdirectory(libtwelf)
add_subdirectory(libfaultinject)
add_subdirectory(tests)
