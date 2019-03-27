/* Force DEBUG on so that tests can use assert(). */
#undef NDEBUG
#include <stddef.h>
#include <assert.h>

/* Define the dlist entry type. */
typedef struct entry entry;
struct entry {
    entry *next, *prev;
    int i;
};

/* Instantiate the dlist. */
#define ENTRY entry
#include "dlist.h"

int main(int argc, char **argv)
{
    entry *l = NULL, *e;
    entry e1, e2, e3;
    int i = 0, v[3];
    e1.i = 1;
    e2.i = 2;
    e3.i = 3;

    entry_add(&l, &e1);
    assert(l == &e1);
    assert(l->next == l);
    assert(l->prev == l);

    entry_add(&l, &e2);
    assert(l == &e1);
    assert(l->next == &e2);
    assert(l->prev == &e2);

    entry_add(&l, &e3);
    assert(l == &e1);
    assert(l->next == &e2);
    assert(l->prev == &e3);

    entry_rem(&l, l);
    assert(l == &e2);
    assert(l->next == &e3);
    assert(l->prev == &e3);
    assert(entry_next(&l, l) == &e3);
    assert(entry_prev(&l, l) == NULL);
    assert(entry_next(&l, &e3) == NULL);
    assert(entry_prev(&l, &e3) == &e2);

    for (e = l; e != NULL; e = entry_next(&l, e))
        v[i++] = e->i;
    assert(v[0] == 2);
    assert(v[1] == 3);

    entry_rem(&l, &e3);
    assert(l == &e2);
    entry_rem(&l, l);
    assert(l == NULL);
}
