///
/// DO NOT MODIFY THIS FILE
///

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include <stdarg.h>

extern void *__real_malloc(size_t size);
extern void *__real_realloc(void *ptr, size_t size);
extern void *__real_calloc(size_t nmemb, size_t size);
extern char *__real_strdup(const char *s);
extern void *__real_mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off);

extern int __real_open(const char *path, int oflag, ...);
extern FILE *__real_fopen(const char *pathname, const char *mode);
extern int __real_close(int fildes);
extern int __real_fclose(FILE *stream);
extern int __real_fstat(int fildes, struct stat *buf);
extern int __real_fseek(FILE *stream, long offset, int whence);
extern int __real_ftell(FILE *stream);
extern size_t __real_fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
extern size_t __real_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
extern ssize_t __real_read(int fd, void *buf, size_t count);
extern ssize_t __real_write(int fd, const void *buf, size_t count);

size_t alloc_failcounter = 0;
size_t io_failcounter = 0;

void set_alloc_failcounter(size_t counter) {
  alloc_failcounter = counter;
}

void set_io_failcounter(size_t counter) {
  io_failcounter = counter;
}

int check_alloc_failcounter() {
  int ret = alloc_failcounter == 1;
  if (alloc_failcounter > 0) {
    alloc_failcounter--;
  }
  return ret;
}

int check_io_failcounter() {
  int ret = io_failcounter == 1;
  if (io_failcounter > 0) {
    io_failcounter--;
  }
  return ret;
}

void *__wrap_malloc(size_t size)
{
  if (check_alloc_failcounter()) {
    errno = ENOMEM;
    return NULL;
  }
  return __real_malloc(size);
}

void *__wrap_realloc(void *ptr, size_t size)
{
  if (size != 0 && check_alloc_failcounter()) {
    errno = ENOMEM;
    return NULL;
  }
  return __real_realloc(ptr, size);
}

void *__wrap_calloc(size_t nmemb, size_t size)
{
  if (check_alloc_failcounter()) {
    errno = ENOMEM;
    return NULL;
  }
  return __real_calloc(nmemb, size);
}

char *__wrap_strdup(const char *s)
{
  if (check_alloc_failcounter()) {
    errno = ENOMEM;
    return NULL;
  }
  return __real_strdup(s);
}

void *__wrap_mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off)
{
  if (check_alloc_failcounter()) {
    errno = ENOMEM;
    return MAP_FAILED;
  }
  return __real_mmap(addr, len, prot, flags, fildes, off);
}

int __wrap_open(const char *path, int oflag, ...)
{
  va_list argp;
  va_start(argp, oflag);
  mode_t mode = va_arg(argp, mode_t);
  va_end(argp);

  char *string = strrchr(path, '.');
  if( string != NULL && strcmp(string, ".gcda") == 0)
    return __real_open(path, oflag, mode);

  if (check_io_failcounter()) {
    errno = ENOENT;
    return -1;
  }
  return __real_open(path, oflag, mode);
}

FILE *__wrap_fopen(const char *pathname, const char *mode)
{
  char *string = strrchr(pathname, '.');
  if( string != NULL && strcmp(string, ".gcda") == 0)
    return __wrap_fopen(pathname, mode);

  if (check_io_failcounter()) {
    errno = ENOENT;
    return NULL;
  }
  return __real_fopen(pathname, mode);
}

int __wrap_close(int fildes)
{
  if (check_io_failcounter()) {
    __real_close(fildes);
    errno = EIO;
    return -1;
  }
  return __real_close(fildes);
}

int __wrap_fclose(FILE *stream)
{
  if (check_io_failcounter()) {
    __real_fclose(stream);
    errno = EIO;
    return -1;
  }
  return __real_fclose(stream);
}

int __wrap_fstat(int fildes, struct stat *buf)
{
  if (check_io_failcounter()) {
    errno = EIO;
    return -1;
  }
  return __real_fstat(fildes, buf);
}

int __wrap_fseek(FILE *stream, long offset, int whence)
{
  if (check_io_failcounter()) {
    errno = EIO;
    return -1;
  }
  return __real_fseek(stream, offset, whence);
}

int __wrap_ftell(FILE *stream)
{
  if (check_io_failcounter()) {
    errno = EIO;
    return -1;
  }
  return __real_ftell(stream);
}

int __wrap_fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
  if (check_io_failcounter()) {
    errno = EIO;
    return 0;
  }
  return __real_fread(ptr, size, nmemb, stream);
}

int __wrap_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
  if (check_io_failcounter()) {
    return 0;
  }
  return __real_fwrite(ptr, size, nmemb, stream);
}

ssize_t __wrap_read(int fd, void *buf, size_t count)
{
  if (check_io_failcounter()) {
    errno = EIO;
    return -1;
  }
  return __real_read(fd, buf, count);
}

ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
  if (check_io_failcounter()) {
    errno = EIO;
    return -1;
  }
  return __real_write(fd, buf, count);
}


///
/// DO NOT MODIFY THIS FILE
///
