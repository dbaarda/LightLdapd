/*=
 * Copyright (c) 2021 Donovan Baarda <abo@minkirri.apana.org.au>
 *
 * Licensed under the GPLv3 License. See LICENSE file for details.
 */
#include "log.h"
#include <stdarg.h>

log_func_t *log_func = errlog;
int log_level = LOG_DEBUG;

void log_init(const char *name, bool daemon, int level)
{
    if (daemon) {
        openlog(name, LOG_PID | LOG_NDELAY, LOG_DAEMON);
        setlogmask(LOG_UPTO(level));
        log_func = syslog;
    } else {
        log_func = errlog;
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
