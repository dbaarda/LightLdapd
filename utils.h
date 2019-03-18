/*=
 * Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 *
 * Licensed under the MIT License. See LICENSE file for details.
 */
#ifndef LIGHTLDAPD_UTILS_H
#define LIGHTLDAPD_UTILS_H

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <sysexits.h>

#define fail(msg) do { perror(msg); return; } while (0);
#define fail1(msg, ret) do { perror(msg); return ret; } while (0);
#define XNEW(type, n) ({void *_p=malloc(n*sizeof(type)); if (!_p) err(EX_OSERR, "malloc"); _p;})
#define XNEW0(type, n) ({void *_p=calloc(n,sizeof(type)); if (!_p) err(EX_OSERR, "calloc"); _p;})
#define XRENEW(ptr, type, n) ({void *_p=realloc(ptr, n*sizeof(type)); if (!_p) err(EX_OSERR, "realloc"); _p;})
#define XSTRDUP(s) ({char *_s=strdup(s); if (!_s) err(EX_OSERR, "strdup"); _s;})
#define XSTRNDUP(s, n) ({char *_s=strndup(s,n); if (!_s) err(EX_OSERR, "strndup"); _s;})

#endif                          /* LIGHTLDAPD_UTILS_H */
