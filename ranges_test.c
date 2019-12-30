/* Force DEBUG on so that tests can use assert(). */
#undef NDEBUG
#include <stddef.h>
#include <assert.h>
#include "ranges.h"

int main(void)
{
    ldap_range r;
    ldap_ranges rs;

    assert(ldap_range_init(&r, "12a-13") == 0);
    assert(ldap_range_init(&r, "12-13a") == 0);
    assert(ldap_range_init(&r, "a12-13") == 0);
    assert(ldap_range_init(&r, "12-a13") == 0);
    assert(ldap_range_init(&r, "12--13") == 0);
    assert(ldap_range_init(&r, "12-") == 0);
    assert(ldap_range_init(&r, "-13") == 0);
    assert(ldap_range_init(&r, "-") == 0);
    assert(ldap_range_init(&r, "") == 0);
    assert(ldap_range_init(&r, "3-7") == 1);
    assert(r.beg == 3);
    assert(r.end == 7);
    assert(!ldap_range_ismatch(&r, 2));
    assert(ldap_range_ismatch(&r, 3));
    assert(ldap_range_ismatch(&r, 4));
    assert(ldap_range_ismatch(&r, 7));
    assert(!ldap_range_ismatch(&r, 8));
    assert(ldap_range_init(&r, "3") == 1);
    assert(r.beg == 3);
    assert(r.end == 3);
    assert(!ldap_range_ismatch(&r, 2));
    assert(ldap_range_ismatch(&r, 3));
    assert(!ldap_range_ismatch(&r, 4));

    assert(ldap_ranges_init(&rs, ",1000-4000") == 0);
    assert(ldap_ranges_init(&rs, "100,1000-4000,") == 0);
    assert(ldap_ranges_init(&rs, "100,,1000-4000") == 0);
    assert(ldap_ranges_init(&rs, ",") == 0);
    assert(ldap_ranges_init(&rs, "") == 0);
    assert(ldap_ranges_init(&rs, "100,1000-4000") == 2);
    assert(rs.count == 2);
    assert(rs.range[0].beg == 100);
    assert(rs.range[0].end == 100);
    assert(rs.range[1].beg == 1000);
    assert(rs.range[1].end == 4000);

    assert(!ldap_ranges_ismatch(&rs, 99));
    assert(ldap_ranges_ismatch(&rs, 100));
    assert(!ldap_ranges_ismatch(&rs, 101));
    assert(!ldap_ranges_ismatch(&rs, 999));
    assert(ldap_ranges_ismatch(&rs, 1000));
    assert(ldap_ranges_ismatch(&rs, 4000));
    assert(!ldap_ranges_ismatch(&rs, 5000));
}
