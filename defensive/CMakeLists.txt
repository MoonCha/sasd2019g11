cmake_minimum_required (VERSION 3.5)
project (sase2019)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

enable_testing()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -Wno-unused-function")
find_package(PkgConfig REQUIRED)

add_subdirectory(libtwelf)
add_subdirectory(libfaultinject)
add_subdirectory(tests)
