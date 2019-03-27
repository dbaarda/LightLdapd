/*=
 * Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 *
 * Licensed under the MIT License. See LICENSE file for details.
 */

#include "nss2ldap.h"
#include "pam.h"
#include <grp.h>
#include <pwd.h>
#include <shadow.h>

/** The type for passwd, group, and spwd entries. */
typedef struct passwd passwd_t;
typedef struct group group_t;
typedef struct spwd spwd_t;

/* LDAPString methods. */
#define LDAPString_new(s) OCTET_STRING_new_fromBuf(&asn_DEF_LDAPString, (s), -1)
#define LDAPString_set(str, s) OCTET_STRING_fromString((str), (s));

/* PartialAttribute methods. */
static PartialAttribute_t *PartialAttribute_new(const char *type);
static LDAPString_t *PartialAttribute_add(PartialAttribute_t *attr, const char *value);
static LDAPString_t *PartialAttribute_addf(PartialAttribute_t *attr, char *format, ...);

/* SearchResultEntry methods. */
static PartialAttribute_t *SearchResultEntry_add(SearchResultEntry_t *res, const char *type);
static const PartialAttribute_t *SearchResultEntry_get(const SearchResultEntry_t *res, const char *type);
static void SearchResultEntry_passwd(SearchResultEntry_t *res, const char *basedn, const bool isroot, passwd_t *pw);
static void SearchResultEntry_group(SearchResultEntry_t *res, const char *basedn, group_t *gr);
static int SearchResultEntry_getpwnam(SearchResultEntry_t *res, const char *basedn, const bool isroot,
                                      const char *name);

/* AttributeValueAssertion methods */
static bool AttributeValueAssertion_equal(const AttributeValueAssertion_t *equal, const SearchResultEntry_t *res);

/* Filter methods. */
static bool Filter_matches(const Filter_t *filter, const SearchResultEntry_t *res);
static bool Filter_ok(const Filter_t *filter);

/* Initialize an ldap_reponse. */
void ldap_response_init(ldap_response *res)
{
    assert(res);

    res->count = 0;
    res->reply = NULL;
}

/* Destroy an ldap_response. */
void ldap_response_done(ldap_response *res)
{
    assert(res);

    while (res->reply)
        ldap_response_inc(res);
}

/* Add an LDAPMessage to an ldap_response. */
LDAPMessage_t *ldap_response_add(ldap_response *res)
{
    assert(res);
    ldap_reply *reply = XNEW0(ldap_reply, 1);

    res->count++;
    ldap_reply_add(&res->reply, reply);
    return &reply->msg;
}

/* Get the next LDAPMessage_t to send. */
LDAPMessage_t *ldap_response_get(ldap_response *res)
{
    assert(res);

    return res->reply ? &res->reply->msg : NULL;
}

/* Increment the next LDAPMessage_t to send. */
void ldap_response_inc(ldap_response *res)
{
    assert(res);
    ldap_reply *reply = res->reply;
    assert(reply);

    ldap_reply_rem(&res->reply, reply);
    LDAPMessage_done(&reply->msg);
    free(reply);
}

/* Get the ldap_response for a BindRequest message. */
void ldap_response_bind(ldap_response *res, const char *basedn, const bool anonok, const int msgid,
                        const BindRequest_t *req, uid_t *binduid, double *delay)
{
    assert(res);
    assert(basedn);
    assert(req);
    assert(binduid);
    assert(delay);
    LDAPMessage_t *msg = ldap_response_add(res);

    msg->messageID = msgid;
    msg->protocolOp.present = LDAPMessage__protocolOp_PR_bindResponse;
    BindResponse_t *reply = &msg->protocolOp.choice.bindResponse;
    LDAPString_set(&reply->matchedDN, (const char *)req->name.buf);
    if (anonok && req->name.size == 0) {
        /* allow anonymous */
        reply->resultCode = BindResponse__resultCode_success;
        *binduid = -1;
    } else if (req->authentication.present == AuthenticationChoice_PR_simple) {
        /* simple auth */
        char user[PWNAME_MAX];
        char *pw = (char *)req->authentication.choice.simple.buf;
        char status[PAMMSG_LEN] = "";
        if (!dn2name(basedn, (const char *)req->name.buf, user)) {
            reply->resultCode = BindResponse__resultCode_invalidDNSyntax;
        } else if (PAM_SUCCESS != auth_pam(user, pw, status, delay)) {
            reply->resultCode = BindResponse__resultCode_invalidCredentials;
            LDAPString_set(&reply->diagnosticMessage, status);
        } else {                /* Success! */
            reply->resultCode = BindResponse__resultCode_success;
            *binduid = name2uid(user);
        }
    } else {
        /* sasl or anonymous auth */
        reply->resultCode = BindResponse__resultCode_authMethodNotSupported;
    }
}

/* Get the ldap_response for a SearchRequest message. */
void ldap_response_search(ldap_response *res, const char *basedn, const bool isroot, const int msgid,
                          const SearchRequest_t *req)
{
    assert(res);
    assert(basedn);
    assert(req);
    const bool bad_filter = !Filter_ok(&req->filter);
    const char *reqbasedn = (const char *)req->baseObject.buf;
    char passwdbasedn[STRING_MAX] = "ou=people,";
    char groupbasedn[STRING_MAX] = "ou=groups,";
    int limit = req->sizeLimit;

    /* Get the basedn's for passwd and group data. */
    strcat(passwdbasedn, basedn);
    strcat(groupbasedn, basedn);
    /* Adjust limit to RESPONSE_MAX if it is zero or too large. */
    limit = (limit && (limit < RESPONSE_MAX)) ? limit : RESPONSE_MAX;
    LDAPMessage_t *msg = ldap_response_add(res);
    /* Add all the matching entries. */
    if (!bad_filter && strends(passwdbasedn, reqbasedn)) {
        passwd_t *pw;
        while ((pw = getpwent()) && (res->count <= limit)) {
            msg->messageID = msgid;
            msg->protocolOp.present = LDAPMessage__protocolOp_PR_searchResEntry;
            SearchResultEntry_t *entry = &msg->protocolOp.choice.searchResEntry;
            SearchResultEntry_passwd(entry, basedn, isroot, pw);
            if (Filter_matches(&req->filter, entry)) {
                /* The entry matches, keep it and add another. */
                msg = ldap_response_add(res);
            } else {
                /* Empty and wipe the entry message for the next one. */
                LDAPMessage_done(msg);
                memset(msg, 0, sizeof(*msg));
            }
        }
        endpwent();
    }
    if (!bad_filter && strends(groupbasedn, reqbasedn)) {
        group_t *gr;
        while ((gr = getgrent()) && (res->count <= limit)) {
            msg->messageID = msgid;
            msg->protocolOp.present = LDAPMessage__protocolOp_PR_searchResEntry;
            SearchResultEntry_t *entry = &msg->protocolOp.choice.searchResEntry;
            SearchResultEntry_group(entry, basedn, gr);
            if (Filter_matches(&req->filter, entry)) {
                /* The entry matches, keep it and add another. */
                msg = ldap_response_add(res);
            } else {
                /* Empty and wipe the entry message for the next one. */
                LDAPMessage_done(msg);
                memset(msg, 0, sizeof(*msg));
            }
        }
        endgrent();
    }
    /* Otherwise construct a SearchResultDone. */
    msg->messageID = msgid;
    msg->protocolOp.present = LDAPMessage__protocolOp_PR_searchResDone;
    SearchResultDone_t *done = &msg->protocolOp.choice.searchResDone;
    if (bad_filter) {
        done->resultCode = LDAPResult__resultCode_other;
        LDAPString_set(&done->diagnosticMessage, "filter not supported");
    } else {
        done->resultCode = LDAPResult__resultCode_success;
        LDAPString_set(&done->matchedDN, basedn);
    }
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

/* Return a full "uid=<name>,ou=people,..." ldap dn from a name and basedn. */
char *name2dn(const char *basedn, const char *name, char *dn)
{
    assert(basedn);
    assert(name);
    assert(dn);
    snprintf(dn, STRING_MAX, "uid=%s,ou=people,%s", name, basedn);
    return dn;
}

/* Return a full "uid=<name>,ou=groups,..." ldap dn from a name and basedn. */
char *group2dn(const char *basedn, const char *group, char *dn)
{
    assert(basedn);
    assert(group);
    assert(dn);
    snprintf(dn, STRING_MAX, "cn=%s,ou=groups,%s", group, basedn);
    return dn;
}

/* Return the name from a full "uid=<name>,ou=people,..." ldap dn. */
char *dn2name(const char *basedn, const char *dn, char *name)
{
    assert(basedn);
    assert(dn);
    assert(name);
    /* uid=$name$,ou=people,$basedn$ */
    const char *pos = dn + 4;
    const char *end = strchr(dn, ',');
    size_t len = end - pos;

    if (!end || strncmp(dn, "uid=", 4) || strncmp(end, ",ou=people,", 11) || strcmp(end + 11, basedn))
        return NULL;
    memcpy(name, pos, len);
    name[len] = '\0';
    return name;
}

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
        if (!strcmp((const char *)attr->type.buf, type))
            return attr;
    }
    return NULL;
}

/* Set a SearchResultEntry from an nss passwd entry. */
static void SearchResultEntry_passwd(SearchResultEntry_t *res, const char *basedn, const bool isroot, passwd_t *pw)
{
    assert(res);
    assert(basedn);
    assert(pw);
    PartialAttribute_t *attribute;
    char buf[STRING_MAX];
    spwd_t *sp = isroot ? getspnam(pw->pw_name) : NULL;

    LDAPString_set(&res->objectName, name2dn(basedn, pw->pw_name, buf));
    attribute = SearchResultEntry_add(res, "objectClass");
    PartialAttribute_add(attribute, "top");
    PartialAttribute_add(attribute, "account");
    PartialAttribute_add(attribute, "posixAccount");
    if (sp)
        PartialAttribute_add(attribute, "shadowAccount");
    attribute = SearchResultEntry_add(res, "uid");
    PartialAttribute_add(attribute, pw->pw_name);
    attribute = SearchResultEntry_add(res, "cn");
    PartialAttribute_add(attribute, gecos2cn(pw->pw_gecos, buf));
    attribute = SearchResultEntry_add(res, "userPassword");
    if (sp)
        PartialAttribute_addf(attribute, "{crypt}%s", sp->sp_pwdp);
    else
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
    if (sp) {
        attribute = SearchResultEntry_add(res, "shadowLastChange");
        PartialAttribute_addf(attribute, "%i", sp->sp_lstchg);
        attribute = SearchResultEntry_add(res, "shadowMin");
        PartialAttribute_addf(attribute, "%i", sp->sp_min);
        attribute = SearchResultEntry_add(res, "shadowMax");
        PartialAttribute_addf(attribute, "%i", sp->sp_max);
        attribute = SearchResultEntry_add(res, "shadowWarning");
        PartialAttribute_addf(attribute, "%i", sp->sp_warn);
        attribute = SearchResultEntry_add(res, "shadowInactive");
        PartialAttribute_addf(attribute, "%i", sp->sp_inact);
        attribute = SearchResultEntry_add(res, "shadowExpire");
        PartialAttribute_addf(attribute, "%i", sp->sp_expire);
        attribute = SearchResultEntry_add(res, "shadowFlag");
        PartialAttribute_addf(attribute, "%i", sp->sp_flag);
    }
}

/* Set a SearchResultEntry from an nss group entry. */
static void SearchResultEntry_group(SearchResultEntry_t *res, const char *basedn, group_t *gr)
{
    assert(res);
    assert(basedn);
    assert(gr);
    PartialAttribute_t *attribute;
    char buf[STRING_MAX];

    LDAPString_set(&res->objectName, group2dn(basedn, gr->gr_name, buf));
    attribute = SearchResultEntry_add(res, "objectClass");
    PartialAttribute_add(attribute, "top");
    PartialAttribute_add(attribute, "posixGroup");
    attribute = SearchResultEntry_add(res, "cn");
    PartialAttribute_add(attribute, gr->gr_name);
    attribute = SearchResultEntry_add(res, "userPassword");
    PartialAttribute_addf(attribute, "{crypt}%s", gr->gr_passwd);
    attribute = SearchResultEntry_add(res, "gidNumber");
    PartialAttribute_addf(attribute, "%i", gr->gr_gid);
    attribute = SearchResultEntry_add(res, "memberUid");
    for (char **m = gr->gr_mem; *m; m++)
        PartialAttribute_add(attribute, *m);
}

/* Set a SearchResultEntry from an nss user's name. */
static int SearchResultEntry_getpwnam(SearchResultEntry_t *res, const char *basedn, const bool isroot,
                                      const char *name)
{
    assert(res);
    assert(basedn);
    assert(name);
    passwd_t *pw = getpwnam(name);

    if (!pw)
        return -1;
    SearchResultEntry_passwd(res, basedn, isroot, pw);
    return 0;
}

/* Check if an AttributeValueAssertion is equal to a SearchResultEntry */
static bool AttributeValueAssertion_equal(const AttributeValueAssertion_t *equal, const SearchResultEntry_t *res)
{
    assert(equal);
    assert(res);
    const char *name = (const char *)equal->attributeDesc.buf;
    const char *value = (const char *)equal->assertionValue.buf;
    const PartialAttribute_t *attr = SearchResultEntry_get(res, name);

    if (attr)
        for (int i = 0; i < attr->vals.list.count; i++)
            if (!strcmp((const char *)attr->vals.list.array[i]->buf, value))
                return true;
    return false;
}

/* Check if a Filter is fully supported. */
static bool Filter_ok(const Filter_t *filter)
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
    case Filter_PR_present:
        return true;
    case Filter_PR_substrings:
    case Filter_PR_greaterOrEqual:
    case Filter_PR_lessOrEqual:
    case Filter_PR_approxMatch:
    case Filter_PR_extensibleMatch:
    default:
        return false;
    }
}

/* Check if a Filter matches a SearchResultEntry. */
static bool Filter_matches(const Filter_t *filter, const SearchResultEntry_t *res)
{
    assert(filter);
    assert(res);
    assert(Filter_ok(filter));

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
        return SearchResultEntry_get(res, (const char *)filter->choice.present.buf) != NULL;
    case Filter_PR_substrings:
    case Filter_PR_greaterOrEqual:
    case Filter_PR_lessOrEqual:
    case Filter_PR_approxMatch:
    case Filter_PR_extensibleMatch:
    default:
        return false;
    }
}
