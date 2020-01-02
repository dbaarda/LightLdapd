/*=
 * Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 *
 * Licensed under the GPLv3 License. See LICENSE file for details.
 */
#include "ranges.h"
#include <assert.h>
#include <inttypes.h>
#include <string.h>

int ldap_range_init(ldap_range *r, const char *s)
{
    assert(r);
    assert(s);
    char *e;

    if (*s == '-')
        /* The first number is negative. */
        return 0;
    r->beg = strtoimax(s, &e, 10);
    if (*e == '-') {
        /* There is second number after a '-'. */
        s = e + 1;
        if (*s == '-')
            /* The second number is negative. */
            return 0;
        r->end = strtoimax(s, &e, 10);
    } else if (*e == '\0') {
        /* There was no '-' separator. */
        r->end = r->beg;
    }
    if (s == e || *e)
        /* Parsing failed before the end. */
        return 0;
    return 1;
}

int ldap_ranges_init(ldap_ranges *r, const char *s)
{
    char b[16 * RANGES_SIZE];
    char *p, *e;

    r->count = 0;
    p = strncpy(b, s, sizeof(b));
    for (e = strsep(&p, ","); e; e = strsep(&p, ",")) {
        if (r->count == RANGES_SIZE)
            return 0;
        if (!ldap_range_init(&r->range[r->count++], e))
            return 0;
    }
    return r->count;
}
