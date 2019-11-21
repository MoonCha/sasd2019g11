///
/// DO NOT MODIFY THIS FILE
///

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

extern void *__real_malloc(size_t size);
extern void *__real_realloc(void *ptr, size_t size);
extern void *__real_calloc(size_t nmemb, size_t size);
extern char *__real_strdup(const char *s);

size_t failcounter = 0;

void set_alloc_failcounter(size_t counter) {
  failcounter = counter;
}

int check_failcounter() {
  int ret = failcounter == 1;
  if (failcounter > 0) {
    failcounter--;
  }
  return ret;
}

void *__wrap_malloc(size_t size)
{
  if (check_failcounter()) {
    errno = ENOMEM;
    return NULL;
  }
  return __real_malloc(size);
}

void *__wrap_realloc(void *ptr, size_t size)
{
  if (size != 0 && check_failcounter()) {
    errno = ENOMEM;
    return NULL;
  }
  return __real_realloc(ptr, size);
}

void *__wrap_calloc(size_t nmemb, size_t size)
{
  if (check_failcounter()) {
    errno = ENOMEM;
    return NULL;
  }
  return __real_calloc(nmemb, size);
}

char *__wrap_strdup(const char *s)
{
  if (check_failcounter()) {
    errno = ENOMEM;
    return NULL;
  }
  return __real_strdup(s);
}

///
/// DO NOT MODIFY THIS FILE
///
