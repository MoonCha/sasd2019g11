#
# DO NOT MODIFY THIS FILE
#

ADD_LIBRARY(libfaultinject SHARED alloc_wrapper.c)

SET_TARGET_PROPERTIES(libfaultinject PROPERTIES PREFIX "")
TARGET_INCLUDE_DIRECTORIES(libfaultinject PUBLIC .)
TARGET_LINK_OPTIONS(libfaultinject PUBLIC -rdynamic
    -Wl,--wrap=malloc
    -Wl,--wrap=calloc
    -Wl,--wrap=realloc
    -Wl,--wrap=strdup
    -Wl,--wrap=open
    -Wl,--wrap=fopen
    -Wl,--wrap=close
    -Wl,--wrap=fclose
    -Wl,--wrap=fstat
    -Wl,--wrap=mmap)

#
# DO NOT MODIFY THIS FILE
#
