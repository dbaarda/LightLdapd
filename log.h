/** \file log.h
 * General logging functions.
 *
 * \copyright Copyright (c) 2021 Donovan Baarda <abo@minkirri.apana.org.au>
 *
 * \licence Licensed under the GPLv3 License. See LICENSE file for details. */
#ifndef LIGHTLDAPD_LOG_H
#define LIGHTLDAPD_LOG_H

#include <err.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <stdbool.h>

/** Function type for logging. */
typedef void log_func_t(int level, const char *msg, ...)
    __attribute__((__format__(printf, 2, 3)));

/** Function to use for logging. */
extern log_func_t *log_func;

/** The level to log upto. */
extern int log_level;

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

/** Logging to stderr with colors using warnx(). */
void errlog(int level, const char *msg, ...)
    __attribute__((__format__(printf, 2, 3)));

#define _log(l, f, ...) log_func(l, "%s:%u %s: "f, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#define lerr(e, f, ...) do { _log(LOG_ERR, "Error: "f": %s", ##__VA_ARGS__, strerror(errno)); exit(e); } while (0)
#define lerrx(e, f, ...) do { _log(LOG_ERR, "Error: "f, ##__VA_ARGS__); exit(e); } while (0)
#define lwarn(f, ...) _log(LOG_WARNING, "Warning: "f": %s", ##__VA_ARGS__, strerror(errno))
#define lwarnx(f, ...) _log(LOG_WARNING, "Warning: "f, ##__VA_ARGS__)
#define lnote(f, ...) _log(LOG_NOTICE, "Note: "f, ##__VA_ARGS__)
#define linfo(f, ...) _log(LOG_INFO, "Info: "f, ##__VA_ARGS__)

#ifdef DEBUG
#define ldebug(f, ...) _log("Debug: "f, ##__VA_ARGS__)
#else
#define ldebug(f, ...)
#endif

#endif                          /* LIGHTLDAPD_LOG_H */
