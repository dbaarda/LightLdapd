/*=
 * Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 *
 * Licensed under the MIT License. See LICENSE file for details.
 */

/** \file dlist.h
 * A simple circular doubly linked list.
 *
 * This is used by defining ENTRY to the name of your dlist entry type and
 * including this header file. The dlist is just a pointer to the head ENTRY of
 * the circular dlist, and will be NULL iif the list is empty. Each entry must
 * be a struct with *next and *prev ENTRY pointers.
 *
 * \param ENTRY - the entry type.
 *
 * Example: \code
 *   typedef struct myentry_s myentry;
 *   struct myentry_s {
 *     myentry *next, *prev;
 *     ...
 *   };
 *
 *   #define ENTRY myentry
 *   #include "dlist.h"
 *
 *   myentry *l = NULL, e;
 *   myentry_add(&l, e);
 *   for (e = l; e != NULL; e = myentry_next(&l, e))
 *     ...;
 * \endcode */

#ifndef ENTRY
#error ENTRY needs to be defined
#endif
#define _JOIN2(x, y) x##y
#define _JOIN(x, y) _JOIN2(x, y)
#define ENTRY_add _JOIN(ENTRY, _add)
#define ENTRY_rem _JOIN(ENTRY, _rem)
#define ENTRY_next _JOIN(ENTRY, _next)
#define ENTRY_prev _JOIN(ENTRY, _prev)

/** Add an entry to a circular dlist. */
static inline void ENTRY_add(ENTRY **l, ENTRY *e)
{
    if (*l) {
        e->next = (*l);
        e->prev = (*l)->prev;
        (*l)->prev = (*l)->prev->next = e;
    } else
        /* Adding element to empty dlist as new head. */
        *l = e->next = e->prev = e;
}

/** Remove an entry from a circular dlist. */
static inline void ENTRY_rem(ENTRY **l, ENTRY *e)
{
    if (*l == e)
        /* Removing head, move head to next element. */
        *l = e->next;
    if (*l == e) {
        /* Still removing head, removing last element. */
        *l = NULL;
    } else {
        e->prev->next = e->next;
        e->next->prev = e->prev;
    }
}

/** Get the next element after e or NULL if it's the last. */
static inline ENTRY *ENTRY_next(ENTRY **l, ENTRY *e)
{
    return e->next == *l ? NULL : e->next;
}

/** Get the prev element before e or NULL if it's the first. */
static inline ENTRY *ENTRY_prev(ENTRY **l, ENTRY *e)
{
    return e == *l ? NULL : e->prev;
}

#undef ENTRY
#undef ENTRY_add
#undef ENTRY_rem
#undef ENTRY_next
#undef ENTRY_prev
