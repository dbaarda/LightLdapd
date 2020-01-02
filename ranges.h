/* \file range.h

   Utilities for storing and matching against uid/gid ranges.

   Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>

   Licensed under the GPLv3 License. See LICENSE file for details. */
#ifndef RANGE_H
#define RANGE_H
#include <stdbool.h>
#include <sys/types.h>

#define RANGES_SIZE 32

/** The simple range class. */
typedef struct {
    uid_t beg;                  /**< The first value of the range. */
    uid_t end;                  /**< The last value of the range. */
} ldap_range;
int ldap_range_init(ldap_range *r, const char *s);
static inline bool ldap_range_ismatch(const ldap_range *r, const uid_t id);

/** The sequence of ranges class. */
typedef struct {
    int count;                  /**< The first value of the range. */
    ldap_range range[RANGES_SIZE];      /**< The ranges. */
} ldap_ranges;
int ldap_ranges_init(ldap_ranges *r, const char *s);
static inline bool ldap_ranges_ismatch(const ldap_ranges *r, const uid_t id);

static inline bool ldap_range_ismatch(const ldap_range *r, const uid_t id)
{
    return r->beg <= id && id <= r->end;
}

static inline bool ldap_ranges_ismatch(const ldap_ranges *r, const uid_t id)
{
    for (int i = 0; i < r->count; i++)
        if (ldap_range_ismatch(&r->range[i], id))
            return true;
    return false;
}

#endif                          /* RANGE_H */
