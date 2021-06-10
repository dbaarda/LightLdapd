/*=
 * Copyright (c) 2021 Donovan Baarda <abo@minkirri.apana.org.au>
 *
 * Licensed under the GPLv3 License. See LICENSE file for details.
 */
#include "log.h"
#include <err.h>
#include <stdarg.h>
#include <stdio.h>

log_func_t *log_func = errlog;
log_prefix_t *log_prefix = log_prefix_color;
int log_level = LOG_DEBUG;
char prefix[256];               /* log_prefix result buffer. */

const char *levelname[8] = {
    "EMERGENCY!",               /* LOG_EMERG */
    "ALERT",                    /* LOG_ALERT */
    "CRITICAL",                 /* LOG_CRIT */
    "error",                    /* LOG_ERR */
    "warning",                  /* LOG_WARNING */
    "note",                     /* LOG_NOTICE */
    "info",                     /* LOG_INFO */
    "debug"                     /* LOG_DEBUG */
};

const char *levelcolor[8] = {
    "\33[01;91m",               /* LOG_EMERG - bold bright red */
    "\33[01;91m",               /* LOG_ALERT - bold bright red */
    "\33[01;91m",               /* LOG_CRIT - bold bright red */
    "\33[01;31m",               /* LOG_ERR - bold red */
    "\33[01;35m",               /* LOG_WARNING - bold magenta */
    "\33[01;33m",               /* LOG_NOTICE - bold yellow */
    "\33[01;36m",               /* LOG_INFO - bold cyan */
    "\33[01;32m",               /* LOG_DEBUG - bold green */
};

#define LOCUS_C "\33[01m"       /* location info - bold */
#define RESET_C "\33[0m"        /* reset colors */

void log_init(const char *name, bool daemon, int level)
{
    if (daemon) {
        openlog(name, LOG_PID | LOG_NDELAY, LOG_DAEMON);
        setlogmask(LOG_UPTO(level));
        log_func = syslog;
        log_prefix = log_prefix_plain;
    } else {
        log_func = errlog;
        log_prefix = log_prefix_color;
    }
    log_level = level;
}

void errlog(int level, const char *msg, ...)
{
    va_list args;

    va_start(args, msg);
    if (level <= log_level)
        vwarnx(msg, args);
    va_end(args);
}

char *log_prefix_plain(int level, const char *file, const unsigned line, const char *func)
{
    snprintf(prefix, sizeof(prefix), "%s:%u %s: %s: ", file, line, func, levelname[level]);
    return prefix;
}

char *log_prefix_color(int level, const char *file, const unsigned line, const char *func)
{
    snprintf(prefix, sizeof(prefix), LOCUS_C "%s:%u %s: %s%s: " RESET_C, file, line, func, levelcolor[level],
             levelname[level]);
    return prefix;
}
