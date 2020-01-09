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
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

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


#define FILE_MAX 4096

// because the gcov coverage testing tool also performs file io, we need to make
// sure to not inject faults when gcov performs file operations. To keep track
// of which files are used by gcov we use this bitfield.
static uint8_t whitelisted_fd_bitfield[(FILE_MAX + 7) / 8];

static void whitelist_fd(int fd)
{
  assert(fd > 0 && fd < FILE_MAX);
  whitelisted_fd_bitfield[fd / 8] |= 1 << (fd % 8);
}
static void blacklist_fd(int fd)
{
  assert(fd > 0 && fd < FILE_MAX);
  whitelisted_fd_bitfield[fd / 8] &= ~(1 << (fd % 8));
}
static bool is_whitelisted_fd(int fd)
{
  assert(fd > 0 && fd < FILE_MAX);
  return whitelisted_fd_bitfield[fd / 8] & (1 << (fd % 8));
}


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
  if (fildes >= FILE_MAX || fildes < 0) {
    errno = EBADF;
    return MAP_FAILED;
  }

  if (!is_whitelisted_fd(fildes) && check_alloc_failcounter()) {
    errno = ENOMEM;
    return MAP_FAILED;
  }
  return __real_mmap(addr, len, prot, flags, fildes, off);
}

static int limited_open(const char *path, int oflag, mode_t mode, bool add_to_whitelist)
{
  int fd = __real_open(path, oflag, mode);
  if (fd < 0)
    return -1;
  if (fd >= FILE_MAX)
  {
    __real_close(fd);
    errno = EMFILE;
    return -1;
  }

  if (add_to_whitelist)
    whitelist_fd(fd);

  return fd;
}

int __wrap_open(const char *path, int oflag, ...)
{
  va_list argp;
  va_start(argp, oflag);
  mode_t mode = va_arg(argp, mode_t);
  va_end(argp);

  char *string = strrchr(path, '.');
  if (string != NULL && strcmp(string, ".gcda") == 0)
    return limited_open(path, oflag, mode, true);

  if (check_io_failcounter()) {
    errno = ENOENT;
    return -1;
  }
  return limited_open(path, oflag, mode, false);
}

static FILE *limited_fopen(const char *pathname, const char *mode, bool add_to_whitelist)
{
  FILE *res = __real_fopen(pathname, mode);
  if (!res)
    return NULL;
  int fd = fileno(res);
  if (fd >= FILE_MAX)
  {
    fclose(res);
    errno = EMFILE;
    return NULL;
  }

  if (add_to_whitelist)
    whitelist_fd(fd);

  return res;
}

FILE *__wrap_fopen(const char *pathname, const char *mode)
{
  char *string = strrchr(pathname, '.');
  if( string != NULL && strcmp(string, ".gcda") == 0)
  {
    return limited_fopen(pathname, mode, true);
  }

  if (check_io_failcounter()) {
    errno = ENOENT;
    return NULL;
  }
  return limited_fopen(pathname, mode, false);
}

int __wrap_close(int fildes)
{
  if (fildes < 0 || fildes >= FILE_MAX)
    return __real_close(fildes);

  if (!is_whitelisted_fd(fildes) && check_io_failcounter()) {
    __real_close(fildes);
    errno = EIO;
    return -1;
  }
  return __real_close(fildes);
}

int __wrap_fclose(FILE *stream)
{
  int fd = fileno(stream);
  if (fd >= FILE_MAX || fd < 0) {
    errno = EBADF;
    return -1;
  }

  if (!is_whitelisted_fd(fd) && check_io_failcounter()) {
    __real_fclose(stream);
    errno = EIO;
    return -1;
  }
  blacklist_fd(fd);
  return __real_fclose(stream);
}

int __wrap_fstat(int fildes, struct stat *buf)
{
  if (fildes >= FILE_MAX || fildes < 0) {
    errno = EBADF;
    return -1;
  }

  if (!is_whitelisted_fd(fildes) && check_io_failcounter()) {
    errno = EIO;
    return -1;
  }
  return __real_fstat(fildes, buf);
}

int __wrap_fseek(FILE *stream, long offset, int whence)
{
  int fd = fileno(stream);
  if (fd >= FILE_MAX || fd < 0) {
    errno = EBADF;
    return -1;
  }

  if (!is_whitelisted_fd(fd) && check_io_failcounter()) {
    errno = EIO;
    return -1;
  }
  return __real_fseek(stream, offset, whence);
}

long __wrap_ftell(FILE *stream)
{
  int fd = fileno(stream);
  if (fd >= FILE_MAX || fd < 0) {
    errno = EBADF;
    return -1;
  }

  if (!is_whitelisted_fd(fd) && check_io_failcounter()) {
    errno = EIO;
    return -1;
  }
  return __real_ftell(stream);
}

ssize_t __wrap_fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
  int fd = fileno(stream);
  if (fd >= FILE_MAX || fd < 0) {
    errno = EBADF;
    return -1;
  }

  if (!is_whitelisted_fd(fd) && check_io_failcounter()) {
    return 0;
  }
  return __real_fread(ptr, size, nmemb, stream);
}

ssize_t __wrap_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
  int fd = fileno(stream);
  if (fd >= FILE_MAX || fd < 0) {
    errno = EBADF;
    return -1;
  }

  if (!is_whitelisted_fd(fd) && check_io_failcounter()) {
    return 0;
  }
  return __real_fwrite(ptr, size, nmemb, stream);
}

ssize_t __wrap_read(int fd, void *buf, size_t count)
{
  if (fd >= FILE_MAX || fd < 0) {
    errno = EBADF;
    return -1;
  }
  if (!is_whitelisted_fd(fd) && check_io_failcounter()) {
    errno = EIO;
    return -1;
  }
  return __real_read(fd, buf, count);
}

ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
  if (fd >= FILE_MAX || fd < 0) {
    errno = EBADF;
    return -1;
  }
  if (!is_whitelisted_fd(fd) && check_io_failcounter()) {
    errno = EIO;
    return -1;
  }
  return __real_write(fd, buf, count);
}


///
/// DO NOT MODIFY THIS FILE
///
