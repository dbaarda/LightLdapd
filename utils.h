/** \file utils.h
 * General utility functions.
 *
 * \copyright Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 *
 * \licence Licensed under the GPLv3 License. See LICENSE file for details. */
#ifndef LIGHTLDAPD_UTILS_H
#define LIGHTLDAPD_UTILS_H

#include "log.h"
#include <assert.h>
#include <err.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <sys/types.h>

#define fail(msg) do { lwarn(msg); return; } while (0);
#define fail1(msg, ret) do { lwarn(msg); return ret; } while (0);
#define XNEW(type, n) ({void *_p=malloc(n*sizeof(type)); if (!_p) lerr(EX_OSERR, "malloc"); _p;})
#define XNEW0(type, n) ({void *_p=calloc(n,sizeof(type)); if (!_p) lerr(EX_OSERR, "calloc"); _p;})
#define XRENEW(ptr, type, n) ({void *_p=realloc(ptr, n*sizeof(type)); if (!_p) lerr(EX_OSERR, "realloc"); _p;})
#define XSTRDUP(s) ({char *_s=strdup(s); if (!_s) lerr(EX_OSERR, "strdup"); _s;})
#define XSTRNDUP(s, n) ({char *_s=strndup(s,n); if (!_s) lerr(EX_OSERR, "strndup"); _s;})

/** Get a uid from a user name. */
#define name2uid(n) ({struct passwd *_p=getpwnam(n); if (!_p) lerrx(EX_OSERR, "User not found: %s", n); _p->pw_uid;})

/* Test if a string ends with another string. */
static inline bool strends(const char *s, const char *e)
{
    int sl = strlen(s);
    int el = strlen(e);

    return el <= sl && strcmp(s + sl - el, e) == 0;
}

#endif                          /* LIGHTLDAPD_UTILS_H */
