#pragma once

__attribute__ ((__format__ (__printf__, 1, 2)))
void log_debug(const char *fmt, ...);

__attribute__ ((__format__ (__printf__, 1, 2)))
void log_info(const char *fmt, ...);

__attribute__ ((__format__ (__printf__, 1, 2)))
void log_warn(const char *fmt, ...);

__attribute__ ((__format__ (__printf__, 1, 2)))
void log_error(const char *fmt, ...);
