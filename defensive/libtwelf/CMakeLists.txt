#
# DO NOT MODIFY THIS FILE
#

set(ASAN_OPTIONS -fno-omit-frame-pointer -fsanitize=address,undefined)

FILE (GLOB LIBTWELF_SOURCES *.c)

ADD_LIBRARY(libtwelf SHARED ${LIBTWELF_SOURCES})
SET_TARGET_PROPERTIES(libtwelf PROPERTIES PREFIX "")
TARGET_INCLUDE_DIRECTORIES(libtwelf PUBLIC api/)
TARGET_LINK_OPTIONS(libtwelf PUBLIC -rdynamic
    -Wl,--wrap=malloc
    -Wl,--wrap=calloc
    -Wl,--wrap=realloc
    -Wl,--wrap=strdup
    -Wl,--wrap=open
    -Wl,--wrap=fopen
    -Wl,--wrap=close
    -Wl,--wrap=fclose
    -Wl,--wrap=fstat
    -Wl,--wrap=fseek
    -Wl,--wrap=ftell
    -Wl,--wrap=fread
    -Wl,--wrap=fwrite
    -Wl,--wrap=read
    -Wl,--wrap=write
    -Wl,--wrap=mmap)


ADD_LIBRARY(libtwelf_asan SHARED ${LIBTWELF_SOURCES})
SET_TARGET_PROPERTIES(libtwelf_asan PROPERTIES PREFIX "")
TARGET_INCLUDE_DIRECTORIES(libtwelf_asan PUBLIC api/)
TARGET_COMPILE_OPTIONS(libtwelf_asan PUBLIC ${ASAN_OPTIONS})
TARGET_LINK_OPTIONS(libtwelf_asan PUBLIC ${ASAN_OPTIONS})
TARGET_LINK_OPTIONS(libtwelf_asan PUBLIC -rdynamic
    -Wl,--wrap=malloc
    -Wl,--wrap=calloc
    -Wl,--wrap=realloc
    -Wl,--wrap=strdup
    -Wl,--wrap=open
    -Wl,--wrap=fopen
    -Wl,--wrap=close
    -Wl,--wrap=fclose
    -Wl,--wrap=fstat
    -Wl,--wrap=fseek
    -Wl,--wrap=ftell
    -Wl,--wrap=fread
    -Wl,--wrap=fwrite
    -Wl,--wrap=read
    -Wl,--wrap=write
    -Wl,--wrap=mmap)

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
set (CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fprofile-arcs")
set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-arcs -lgcov")

#
# DO NOT MODIFY THIS FILE
#
