/** \file log.h
 * General logging functions.
 *
 * \copyright Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 *
 * \licence Licensed under the GPLv3 License. See LICENSE file for details. */
#ifndef LIGHTLDAPD_LOG_H
#define LIGHTLDAPD_LOG_H

#include <err.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>

#ifdef DEBUG
/* Use err for debug logging. */
#define linit(n)
#define lerr(e, f, ...) err(e, "\33[31mError:\33[39m "f, ##__VA_ARGS__)
#define lerrx(e, f, ...) errx(e, "\33[31mError:\33[39m "f, ##__VA_ARGS__)
#define lwarn(f, ...) warn("\33[31mWarning:\33[39m "f, ##__VA_ARGS__)
#define lwarnx(f, ...) warnx("\33[31mWarning:\33[39m "f, ##__VA_ARGS__)
#define lnote(f, ...) warnx("\33[91mNotice:\33[39m "f, ##__VA_ARGS__)
#define linfo(f, ...) warnx("\33[32mInfo:\33[39m "f, ##__VA_ARGS__)
#define ldebug(f, ...) warnx("\33[34mDebug:\33[39m "f, ##__VA_ARGS__)
#else
/* Use syslog for normal logging. */
#define linit(n) openlog(n, LOG_PID | LOG_PERROR | LOG_NDELAY, LOG_DAEMON)
#define lerr(e, f, ...) do { syslog(LOG_ERR, "Error: "f": %s", ##__VA_ARGS__, strerror(errno)); exit(e); } while (0)
#define lerrx(e, f, ...) do { syslog(LOG_ERR, "Error: "f, ##__VA_ARGS__); exit(e); } while (0)
#define lwarn(f, ...) syslog(LOG_WARNING, "Warning: "f": %s", ##__VA_ARGS__, strerror(errno))
#define lwarnx(f, ...) syslog(LOG_WARNING, "Warning: "f, ##__VA_ARGS__)
#define lnote(f, ...) syslog(LOG_NOTICE, "Notice: "f, ##__VA_ARGS__)
#define linfo(f, ...) syslog(LOG_INFO, "Info: "f, ##__VA_ARGS__)
#define ldebug(f, ...)
#endif

#endif                          /* LIGHTLDAPD_LOG_H */
