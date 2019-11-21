#
# DO NOT MODIFY THIS FILE
#

set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address,undefined")
set (CMAKE_SHARED_LINKER_FLAGS_DEBUG "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address,undefined")

ADD_LIBRARY(libfaultinject SHARED alloc_wrapper.c)

SET_TARGET_PROPERTIES(libfaultinject PROPERTIES PREFIX "")
TARGET_INCLUDE_DIRECTORIES(libfaultinject PUBLIC .)
TARGET_LINK_OPTIONS(libfaultinject PUBLIC -rdynamic -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc -Wl,--wrap=strdup)

#
# DO NOT MODIFY THIS FILE
#
