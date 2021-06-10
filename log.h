/** \file log.h
 * General logging functions.
 *
 * \copyright Copyright (c) 2021 Donovan Baarda <abo@minkirri.apana.org.au>
 *
 * \licence Licensed under the GPLv3 License. See LICENSE file for details. */
#ifndef LIGHTLDAPD_LOG_H
#define LIGHTLDAPD_LOG_H

#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <stdbool.h>

/** Logging function type. */
typedef void log_func_t(int level, const char *msg, ...)
    __attribute__((__format__(printf, 2, 3)));

/** Logging prefix function type. */
typedef char *log_prefix_t(int level, const char *file, const unsigned line, const char *func);

extern log_func_t *log_func;    /**< Logging function to use. */
extern log_prefix_t *log_prefix;        /**< Logging prefix function to use. */
extern int log_level;           /**< The level to log upto. */

/** Initialize logging.
 *
 * Initializes logging and sets the log_func and log_level to use. Note by
 * default logging is configured to log all levels to stderr.
 *
 * \param *name - the service name string to log with.
 *
 * \param daemon - Log in "daemon" mode to syslog instead of stderr.
 *
 * \param level - The level to log upto. */
void log_init(const char *name, bool daemon, int level);

/** Logging function to stderr using warnx(). */
void errlog(int level, const char *msg, ...)
    __attribute__((__format__(printf, 2, 3)));

/** Logging prefix function without color. */
char *log_prefix_plain(int level, const char *file, const unsigned line, const char *func);

/** Logging prefix function with color. */
char *log_prefix_color(int level, const char *file, const unsigned line, const char *func);

#define _prefix(l) log_prefix(l, __FILE__, __LINE__, __FUNCTION__)
#define _log(l, f, ...) log_func(l, "%s"f, _prefix(l), ##__VA_ARGS__)

#define lerr(e, f, ...) do { _log(LOG_ERR, f": %s", ##__VA_ARGS__, strerror(errno)); exit(e); } while (0)
#define lerrx(e, f, ...) do { _log(LOG_ERR, f, ##__VA_ARGS__); exit(e); } while (0)
#define lwarn(f, ...) _log(LOG_WARNING, f": %s", ##__VA_ARGS__, strerror(errno))
#define lwarnx(f, ...) _log(LOG_WARNING, f, ##__VA_ARGS__)
#define lnote(f, ...) _log(LOG_NOTICE, f, ##__VA_ARGS__)
#define linfo(f, ...) _log(LOG_INFO, f, ##__VA_ARGS__)

#ifdef DEBUG
#define ldebug(f, ...) _log(LOG_DEBUG, f, ##__VA_ARGS__)
#else
#define ldebug(f, ...)
#endif

#endif                          /* LIGHTLDAPD_LOG_H */
