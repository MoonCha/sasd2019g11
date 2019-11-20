#include "util.h"
#include "ansi.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

static int stdout_isatty = -1;

__attribute__ ((__format__ (__printf__, 3, 0)))
static void log_print(const char *color, const char *topic, const char *fmt, va_list args)
{
  if (stdout_isatty == -1)
    stdout_isatty = isatty(STDOUT_FILENO);

  const char *reset = FORE_DEFAULT;
  if (!stdout_isatty)
  {
    color = "";
    reset = "";
  }

  char buf[256];
  memset(buf, 0, sizeof(buf));
  vsnprintf(buf, sizeof(buf), fmt, args);
  printf("libtwelf: %s[%-8s] %s%s\n", color, topic, buf, reset);
  fflush(stdout);
}

__attribute__((__visibility__(("internal"))))
void log_debug(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  log_print(FORE_WHITE, "DEBUG", fmt, args);
  va_end(args);
}
__attribute__((__visibility__(("internal"))))
void log_info(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  log_print(FORE_WHITE, "INFO", fmt, args);
  va_end(args);
}
__attribute__((__visibility__(("internal"))))
void log_warn(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  log_print(FORE_YELLOW, "WARN", fmt, args);
  va_end(args);
}
__attribute__((__visibility__(("internal"))))
void log_error(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  log_print(FORE_RED, "ERROR", fmt, args);
  va_end(args);
}
