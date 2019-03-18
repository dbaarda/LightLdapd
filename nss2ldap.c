/*=
 * Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 *
 * Licensed under the MIT License. See LICENSE file for details.
 */

#include "nss2ldap.h"
#include "utils.h"

/* Allocate a PartialAttribute and set it's type. */
static PartialAttribute_t *PartialAttribute_new(const char *type)
{
    assert(type);
    PartialAttribute_t *a = XNEW0(PartialAttribute_t, 1);

    LDAPString_set(&a->type, type);
    return a;
}

/* Add a string value to a PartialAttribute. */
static LDAPString_t *PartialAttribute_add(PartialAttribute_t *attr, const char *value)
{
    assert(attr);
    assert(value);
    LDAPString_t *s = LDAPString_new(value);
    assert(s);

    asn_set_add(&attr->vals, s);
    return s;
}

/* Add a formated value to a PartialAttribute. */
static LDAPString_t *PartialAttribute_addf(PartialAttribute_t *attr, char *format, ...)
{
    assert(attr);
    assert(format);
    char v[STRING_MAX];
    va_list args;

    va_start(args, format);
    vsnprintf(v, sizeof(v), format, args);
    return PartialAttribute_add(attr, v);
}

/* Add a PartialAttribute to a SearchResultEntry. */
static PartialAttribute_t *SearchResultEntry_add(SearchResultEntry_t *res, const char *type)
{
    assert(res);
    assert(type);
    PartialAttribute_t *a = PartialAttribute_new(type);
    assert(a);

    asn_sequence_add(&res->attributes, a);
    return a;
}

/* Get a PartialAttribute from a SearchResultEntry. */
static const PartialAttribute_t *SearchResultEntry_get(const SearchResultEntry_t *res, const char *type)
{
    assert(res);
    assert(type);

    for (int i = 0; i < res->attributes.list.count; i++) {
        const PartialAttribute_t *attr = res->attributes.list.array[i];
        if (strcmp((const char *)attr->type.buf, type))
            return attr;
    }
    return NULL;
}

/* Get the cn from the first field of a gecos entry. */
char *gecos2cn(const char *gecos, char *cn)
{
    assert(gecos);
    assert(cn);
    size_t len = strcspn(gecos, ",");

    memcpy(cn, gecos, len);
    cn[len] = '\0';
    return cn;
}

char *name2dn(const char *basedn, const char *name, char *dn)
{
    assert(basedn);
    assert(name);
    assert(dn);
    snprintf(dn, STRING_MAX, "uid=%s,%s", name, basedn);
    return dn;
}

char *dn2name(const char *basedn, const char *dn, char *name)
{
    assert(basedn);
    assert(dn);
    assert(name);
    /* uid=$name$,$basedn$ */
    const char *pos = dn + 4;
    const char *end = strchr(dn, ',');
    size_t len = end - pos;

    if (!end || strncmp(dn, "uid=", 4) || strcmp(end + 1, basedn))
        return NULL;
    memcpy(name, pos, len);
    name[len] = '\0';
    return name;
}

void passwd2ldap(SearchResultEntry_t *res, const char *basedn, passwd_t *pw)
{
    assert(res);
    assert(basedn);
    assert(pw);
    PartialAttribute_t *attribute;
    char buf[STRING_MAX];

    LDAPString_set(&res->objectName, name2dn(basedn, pw->pw_name, buf));
    attribute = SearchResultEntry_add(res, "objectClass");
    PartialAttribute_add(attribute, "top");
    PartialAttribute_add(attribute, "account");
    PartialAttribute_add(attribute, "posixAccount");
    attribute = SearchResultEntry_add(res, "uid");
    PartialAttribute_add(attribute, pw->pw_name);
    attribute = SearchResultEntry_add(res, "cn");
    PartialAttribute_add(attribute, gecos2cn(pw->pw_gecos, buf));
    attribute = SearchResultEntry_add(res, "userPassword");
    PartialAttribute_addf(attribute, "{crypt}%s", pw->pw_passwd);
    attribute = SearchResultEntry_add(res, "uidNumber");
    PartialAttribute_addf(attribute, "%i", pw->pw_uid);
    attribute = SearchResultEntry_add(res, "gidNumber");
    PartialAttribute_addf(attribute, "%i", pw->pw_gid);
    attribute = SearchResultEntry_add(res, "gecos");
    PartialAttribute_add(attribute, pw->pw_gecos);
    attribute = SearchResultEntry_add(res, "homeDirectory");
    PartialAttribute_add(attribute, pw->pw_dir);
    attribute = SearchResultEntry_add(res, "loginShell");
    PartialAttribute_add(attribute, pw->pw_shell);
}

int getpwnam2ldap(SearchResultEntry_t *res, const char *basedn, const char *name)
{
    assert(res);
    assert(basedn);
    assert(name);
    passwd_t *pw = getpwnam(name);

    if (!pw)
        return -1;
    passwd2ldap(res, basedn, pw);
    return 0;
}

bool Filter_ok(const Filter_t *filter)
{
    assert(filter);

    switch (filter->present) {
    case Filter_PR_and:
        for (int i = 0; i < filter->choice.And.list.count; i++)
            if (!Filter_ok(filter->choice.And.list.array[i]))
                return false;
        return true;
    case Filter_PR_or:
        for (int i = 0; i < filter->choice.Or.list.count; i++)
            if (!Filter_ok(filter->choice.Or.list.array[i]))
                return false;
        return true;
    case Filter_PR_not:
        return Filter_ok(filter->choice.Not);
    case Filter_PR_equalityMatch:
        return true;
    case Filter_PR_present:
    case Filter_PR_substrings:
    case Filter_PR_greaterOrEqual:
    case Filter_PR_lessOrEqual:
    case Filter_PR_approxMatch:
    case Filter_PR_extensibleMatch:
    default:
        return false;
    }
}

/* Check if an AttributeValueAssertion is equal to a SearchResultEntry */
bool AttributeValueAssertion_equal(const AttributeValueAssertion_t *equal, const SearchResultEntry_t *res)
{
    assert(equal);
    assert(res);
    const char *name = (const char *)equal->attributeDesc.buf;
    const char *value = (const char *)equal->assertionValue.buf;
    const PartialAttribute_t *attr = SearchResultEntry_get(res, name);

    if (attr)
        for (int i = 0; i < attr->vals.list.count; i++)
            if (strcmp((const char *)attr->vals.list.array[i]->buf, value))
                return true;
    return false;
}

bool Filter_matches(const Filter_t *filter, const SearchResultEntry_t *res)
{
    assert(filter);
    assert(res);

    switch (filter->present) {
    case Filter_PR_and:
        for (int i = 0; i < filter->choice.And.list.count; i++)
            if (!Filter_matches(filter->choice.And.list.array[i], res))
                return false;
        return true;
    case Filter_PR_or:
        for (int i = 0; i < filter->choice.Or.list.count; i++)
            if (Filter_matches(filter->choice.Or.list.array[i], res))
                return true;
        return false;
    case Filter_PR_not:
        return !Filter_matches(filter->choice.Not, res);
    case Filter_PR_equalityMatch:
        return AttributeValueAssertion_equal(&filter->choice.equalityMatch, res);
    case Filter_PR_present:
    case Filter_PR_substrings:
    case Filter_PR_greaterOrEqual:
    case Filter_PR_lessOrEqual:
    case Filter_PR_approxMatch:
    case Filter_PR_extensibleMatch:
    default:
        return false;
    }
}
