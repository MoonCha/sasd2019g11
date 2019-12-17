///
/// DO NOT MODIFY THIS FILE
///

#ifndef ALLOC_WRAPPER_H
#define ALLOC_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <stdlib.h>
#include <stdio.h>

/**
 * Control whether future heap allocations will artificially fail.
 * This affects malloc, calloc, realloc, strdup and mmap.
 * If @a n == 0, nothing will be done. Otherwise, the nth allocation
 * will fail, returning @a NULL.
 * 
 * @param n The counter at which allocation will fail
 */
void set_alloc_failcounter(size_t n);

/**
 * Control whether future file operations will artificially fail.
 * This affects open, fopen, close, fclose and fstat.
 * If @a n == 0, nothing will be done. Otherwise, the nth usage
 * will fail, returning @a NULL.
 * 
 * @param n The counter at which allocation will fail
 */
void set_io_failcounter(size_t n);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif // ALLOC_WRAPPER_H

///
/// DO NOT MODIFY THIS FILE
///
