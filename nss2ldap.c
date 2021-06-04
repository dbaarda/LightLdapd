/*=
 * Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 *
 * Licensed under the GPLv3 License. See LICENSE file for details.
 */

#include "nss2ldap.h"
#include "pam.h"
#include "ranges.h"
#include <grp.h>
#include <pwd.h>
#include <shadow.h>

/** The type for passwd, group, and spwd entries. */
typedef struct passwd passwd_t;
typedef struct group group_t;
typedef struct spwd spwd_t;

/* Search Scope class. */
#define SCOPE_PASSWD 1          /**< Mask bit to search passwd data. */
#define SCOPE_GROUP 2           /**< Mask bit to search group data. */
typedef struct {
    int mask;                   /**< Bitmask for data sources to search. */
    const char *uid;            /**< Specific passwd uid to search. */
    const char *uidNumber;      /**< Specific passwd uidNumber to search. */
    const char *cn;             /**< Specific group cn to search. */
    const char *gidNumber;      /**< Specific group uidNumber to search. */
    const ldap_ranges *uids;    /**< The ranges of uids exported. */
    const ldap_ranges *gids;    /**< The ranges of gids exported. */
} scope_t;
static void scope_init(scope_t *s, const ldap_ranges *uids, const ldap_ranges *gids);
static scope_t *scope_and(scope_t *s, scope_t *o);
static scope_t *scope_or(scope_t *s, scope_t *o);
static scope_t *scope_not(scope_t *s);
static passwd_t *scope_passwd_iter(scope_t *s);
static passwd_t *scope_passwd_next(scope_t *s);
static void scope_passwd_done(scope_t *s);
static group_t *scope_group_iter(scope_t *s);
static group_t *scope_group_next(scope_t *s);
static void scope_group_done(scope_t *s);

/* Functions for dn's and cn's. */
static char *gecos2cn(const char *gecos, char *cn);
static char *name2dn(const char *basedn, const char *name, char *dn);
static char *group2dn(const char *basedn, const char *group, char *dn);
static char *dn2name(const char *basedn, const char *dn, char *name);

/* PartialAttribute methods. */
static PartialAttribute_t *PartialAttribute_new(const char *type);
static LDAPString_t *PartialAttribute_add(PartialAttribute_t *attr, const char *value);
static LDAPString_t *PartialAttribute_addf(PartialAttribute_t *attr, char *format, ...);
static void PartialAttribute_clear(PartialAttribute_t *attr);

/* SearchResultEntry methods. */
#define SearchResultEntry_done(res) ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_SearchResultEntry, res)
#define SearchResultEntry_init(res) memset(res, 0, sizeof(*res))
static PartialAttribute_t *SearchResultEntry_add(SearchResultEntry_t *res, const char *type);
static const PartialAttribute_t *SearchResultEntry_get(const SearchResultEntry_t *res, const char *type);
static void SearchResultEntry_passwd(SearchResultEntry_t *res, const char *basedn, const bool isroot, passwd_t *pw);
static void SearchResultEntry_group(SearchResultEntry_t *res, const char *basedn, group_t *gr);

/* SearchRequest methods. */
static bool SearchRequest_select(const SearchRequest_t *req, SearchResultEntry_t *res);
static scope_t *SearchRequest_scope(const SearchRequest_t *req, const ldap_server *server, scope_t *scope);

/* AttributeSelection methods. */
static bool AttributeSelection_contains(const AttributeSelection_t *sel, const char *type);

/* AttributeDescription methods. */
static bool AttributeDescription_present(const AttributeDescription_t *present, const SearchResultEntry_t *res);

/* AttributeValueAssertion methods */
static bool AttributeValueAssertion_equal(const AttributeValueAssertion_t *equal, const SearchResultEntry_t *res);
static scope_t *AttributeValueAssertion_equal_scope(const AttributeValueAssertion_t *equal, scope_t *scope);

/* Filter methods. */
static bool Filter_matches(const Filter_t *filter, const SearchResultEntry_t *res);
static bool Filter_ok(const Filter_t *filter);
static scope_t *Filter_scope(const Filter_t *filter, scope_t *scope);

/* Get the ldap_replies for a BindRequest ldap_request using pam. */
void ldap_request_bind_pam(ldap_request *request)
{
    assert(request);
    assert(request->message->protocolOp.present == LDAPMessage__protocolOp_PR_bindRequest);
    ldap_connection *connection = request->connection;
    ldap_server *server = connection->server;
    LDAPMessage_t *msg = &ldap_reply_new(request)->message;
    const BindRequest_t *req = &request->message->protocolOp.choice.bindRequest;
    BindResponse_t *resp = &msg->protocolOp.choice.bindResponse;

    msg->protocolOp.present = LDAPMessage__protocolOp_PR_bindResponse;
    LDAPString_set(&resp->matchedDN, (const char *)req->name.buf);
    if (req->name.size == 0) {
        /* anonymous bind */
        resp->resultCode = BindResponse__resultCode_success;
        connection->binduid = (uid_t)(-1);
    } else if (req->authentication.present == AuthenticationChoice_PR_simple) {
        /* simple auth */
        char user[PWNAME_MAX];
        char *pw = (char *)req->authentication.choice.simple.buf;
        char status[PAMMSG_LEN] = "";
        if (server->ssl && !connection->ssl) {
            resp->resultCode = BindResponse__resultCode_confidentialityRequired;
        } else if (!dn2name(server->basedn, (const char *)req->name.buf, user)) {
            resp->resultCode = BindResponse__resultCode_invalidDNSyntax;
        } else if (PAM_SUCCESS != auth_user(user, pw, status, &connection->delay)) {
            resp->resultCode = BindResponse__resultCode_invalidCredentials;
            LDAPString_set(&resp->diagnosticMessage, status);
        } else {                /* Success! */
            resp->resultCode = BindResponse__resultCode_success;
            connection->binduid = name2uid(user);
        }
    } else {
        /* sasl auth */
        resp->resultCode = BindResponse__resultCode_authMethodNotSupported;
    }
}

/* Get the ldap_replies for a SearchRequest ldap_request using nss. */
void ldap_request_search_nss(ldap_request *request)
{
    assert(request);
    assert(request->message->protocolOp.present == LDAPMessage__protocolOp_PR_searchRequest);
    ldap_connection *connection = request->connection;
    ldap_server *server = connection->server;
    const SearchRequest_t *req = &request->message->protocolOp.choice.searchRequest;
    int limit = req->sizeLimit;
    const char *basedn = server->basedn;
    const bool filterok = Filter_ok(&req->filter);
    const bool isroot = server->rootuid == connection->binduid;
    const bool isauth = server->anonok || connection->binduid != (uid_t)(-1);

    /* Adjust limit to RESPONSE_MAX if it is zero or too large. */
    limit = (limit && (limit < RESPONSE_MAX)) ? limit : RESPONSE_MAX;
    LDAPMessage_t *msg = &ldap_reply_new(request)->message;
    /* Add all the matching entries. */
    if (filterok && isauth) {
        scope_t scope;
        SearchRequest_scope(req, server, &scope);
        for (passwd_t *pw = scope_passwd_iter(&scope); pw && (request->count <= limit); pw = scope_passwd_next(&scope)) {
            msg->protocolOp.present = LDAPMessage__protocolOp_PR_searchResEntry;
            SearchResultEntry_t *entry = &msg->protocolOp.choice.searchResEntry;
            SearchResultEntry_passwd(entry, basedn, isroot, pw);
            /* If the entry matches, keep it and add another. */
            if (SearchRequest_select(req, entry))
                msg = &ldap_reply_new(request)->message;
        }
        scope_passwd_done(&scope);
        for (group_t *gr = scope_group_iter(&scope); gr && (request->count <= limit); gr = scope_group_next(&scope)) {
            msg->protocolOp.present = LDAPMessage__protocolOp_PR_searchResEntry;
            SearchResultEntry_t *entry = &msg->protocolOp.choice.searchResEntry;
            SearchResultEntry_group(entry, basedn, gr);
            /* If the entry matches, keep it and add another. */
            if (SearchRequest_select(req, entry))
                msg = &ldap_reply_new(request)->message;
        }
        scope_group_done(&scope);
    }
    /* Otherwise construct a SearchResultDone. */
    msg->protocolOp.present = LDAPMessage__protocolOp_PR_searchResDone;
    SearchResultDone_t *done = &msg->protocolOp.choice.searchResDone;
    if (!isauth) {
        done->resultCode = LDAPResult__resultCode_insufficientAccessRights;
        LDAPString_set(&done->diagnosticMessage, "anonymous search not permitted");
    } else if (!filterok) {
        done->resultCode = LDAPResult__resultCode_other;
        LDAPString_set(&done->diagnosticMessage, "filter not supported");
    } else {
        done->resultCode = LDAPResult__resultCode_success;
        LDAPString_set(&done->matchedDN, basedn);
    }
}

/* Initialize a search scope to include everything. */
static void scope_init(scope_t *s, const ldap_ranges *uids, const ldap_ranges *gids)
{
    s->mask = -1;
    s->uid = s->uidNumber = s->cn = s->gidNumber = NULL;
    s->uids = uids;
    s->gids = gids;
}

/* Logical 'and' of two search scopes. */
static scope_t *scope_and(scope_t *s, scope_t *o)
{
    s->mask &= o->mask;
    /* If we exclude passwd, clear specifics. */
    if (!(s->mask & SCOPE_PASSWD))
        s->uidNumber = s->uid = NULL;
    else if (!s->uid && !s->uidNumber) {
        /* If we include passwd and don't have specifics, use the others. */
        s->uidNumber = o->uidNumber;
        s->uid = o->uid;
    }
    /* If we exclude group, clear specifics. */
    if (!(s->mask & SCOPE_GROUP))
        s->gidNumber = s->cn = NULL;
    else if (!s->cn && !s->gidNumber) {
        /* If we include group and don't have specifics, use the other's. */
        s->gidNumber = o->gidNumber;
        s->cn = o->cn;
    }
    return s;
}

/* Logical 'or' of two search scopes. */
static scope_t *scope_or(scope_t *s, scope_t *o)
{
    /* If we don't include passwd, use the other's specifics. */
    if (!(s->mask & SCOPE_PASSWD)) {
        s->uidNumber = o->uidNumber;
        s->uid = o->uid;
    } else if (o->mask & SCOPE_PASSWD)
        /* If both include passwd, we can't be specific. */
        s->uidNumber = s->uid = NULL;
    /* If we don't include group, use the other's specifics. */
    if (!(s->mask & SCOPE_GROUP)) {
        s->gidNumber = o->gidNumber;
        s->cn = o->cn;
    } else if (o->mask & SCOPE_GROUP)
        /* If both include group, we can't be specific. */
        s->gidNumber = s->cn = NULL;
    s->mask |= o->mask;
    return s;
}

/* Logical 'not' of a search scope. */
static scope_t *scope_not(scope_t *s)
{
    s->mask = ~s->mask;
    /* If we had passwd specifics, we need to include the rest. */
    if (s->uid || s->uidNumber) {
        s->mask |= SCOPE_PASSWD;
        s->uid = s->uidNumber = NULL;
    }
    /* If we had group specifics, we need to include the rest. */
    if (s->cn || s->gidNumber) {
        s->mask |= SCOPE_GROUP;
        s->cn = s->gidNumber = NULL;
    }
    return s;
}

/* Start iterating through the passwd entries included in a scope. */
static passwd_t *scope_passwd_iter(scope_t *s)
{
    if (!(s->mask & SCOPE_PASSWD)) {
        return NULL;
    } else if (s->uidNumber) {
        uid_t uid = atoi(s->uidNumber);
        /* printf("getpwuid(%d)\n", uid); */
        return ldap_ranges_ismatch(s->uids, uid) ? getpwuid(uid) : NULL;
    } else if (s->uid) {
        /* printf("getpwnam(%s)\n", s->uid); */
        passwd_t *p = getpwnam(s->uid);
        return (p && ldap_ranges_ismatch(s->uids, p->pw_uid)) ? p : NULL;
    } else {
        /* printf("getpwent()\n"); */
        return scope_passwd_next(s);
    }
}

/* Iterate to the next passwd entry included in a scope. */
static passwd_t *scope_passwd_next(scope_t *s)
{
    passwd_t *p = NULL;

    if (!s->uid && !s->uidNumber)
        while ((p = getpwent()) && !ldap_ranges_ismatch(s->uids, p->pw_uid)) ;
    return p;
}

/* Stop iterating through passwd entries included in a scope. */
static void scope_passwd_done(scope_t *s)
{
    if (!s->uid && !s->uidNumber)
        endpwent();
}

/* Start iterating through the group entries included in a scope. */
static group_t *scope_group_iter(scope_t *s)
{
    if (!(s->mask & SCOPE_GROUP)) {
        return NULL;
    } else if (s->gidNumber) {
        gid_t gid = atoi(s->gidNumber);
        /* printf("getgrgid(%d)\n", gid); */
        return ldap_ranges_ismatch(s->gids, gid) ? getgrgid(gid) : NULL;
    } else if (s->cn) {
        /* printf("getgrnam(%s)\n", s->cn); */
        group_t *g = getgrnam(s->cn);
        return (g && ldap_ranges_ismatch(s->gids, g->gr_gid)) ? g : NULL;
    } else {
        /* printf("getgrent()\n"); */
        return scope_group_next(s);
    }
}

/* Iterate to the next group entry included in a scope. */
static group_t *scope_group_next(scope_t *s)
{
    group_t *g = NULL;

    if (!s->cn && !s->gidNumber)
        while ((g = getgrent()) && !ldap_ranges_ismatch(s->gids, g->gr_gid)) ;
    return g;
}

/* Stop iterating through group entries included in a scope. */
static void scope_group_done(scope_t *s)
{
    if (!s->cn && !s->gidNumber)
        endgrent();
}

/* Get the cn from the first field of a gecos entry. */
static char *gecos2cn(const char *gecos, char *cn)
{
    assert(gecos);
    assert(cn);
    size_t len = strcspn(gecos, ",");

    memcpy(cn, gecos, len);
    cn[len] = '\0';
    return cn;
}

/* Return a full "uid=<name>,ou=people,..." ldap dn from a name and basedn. */
static char *name2dn(const char *basedn, const char *name, char *dn)
{
    assert(basedn);
    assert(name);
    assert(dn);
    snprintf(dn, STRING_MAX, "uid=%s,ou=people,%s", name, basedn);
    return dn;
}

/* Return a full "uid=<name>,ou=groups,..." ldap dn from a name and basedn. */
static char *group2dn(const char *basedn, const char *group, char *dn)
{
    assert(basedn);
    assert(group);
    assert(dn);
    snprintf(dn, STRING_MAX, "cn=%s,ou=groups,%s", group, basedn);
    return dn;
}

/* Return the name from a full "uid=<name>,ou=people,..." ldap dn. */
static char *dn2name(const char *basedn, const char *dn, char *name)
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

/* Remove all the values from a PartialAttribute. */
static void PartialAttribute_clear(PartialAttribute_t *attr)
{
    assert(attr);

    asn_set_empty(&attr->vals);
}

/* Add a PartialAttribute to a SearchResultEntry. */
static PartialAttribute_t *SearchResultEntry_add(SearchResultEntry_t *res, const char *type)
{
    assert(res);
    assert(type);
    PartialAttribute_t *a = PartialAttribute_new(type);

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

/* Check a SearchRequest matches an entry and prune it to match selections. */
static bool SearchRequest_select(const SearchRequest_t *req, SearchResultEntry_t *res)
{
    assert(req);
    assert(res);

    if (!Filter_matches(&req->filter, res)) {
        /* Empty and wipe the whole entry. */
        SearchResultEntry_done(res);
        SearchResultEntry_init(res);
        return false;
    }
    /* Prune unselected attributes and values. */
    int i = 0;
    while (i < res->attributes.list.count) {
        PartialAttribute_t *attr = res->attributes.list.array[i];
        if (req->typesOnly)
            PartialAttribute_clear(attr);
        if (!AttributeSelection_contains(&req->attributes, (const char *)attr->type.buf))
            asn_sequence_del(&res->attributes.list, i, 1);
        else
            i++;
    }
    return true;
}

/* Get the scope for a SearchRequest. */
static scope_t *SearchRequest_scope(const SearchRequest_t *req, const ldap_server *server, scope_t *scope)
{
    assert(req);
    assert(server);
    assert(scope);
    const char *basedn = server->basedn;
    const char *reqbasedn = (const char *)req->baseObject.buf;
    char passwdbasedn[STRING_MAX] = "ou=people,";
    char groupbasedn[STRING_MAX] = "ou=groups,";
    scope_t fscope;

    /* Get the basedn's for passwd and group data. */
    strcat(passwdbasedn, basedn);
    strcat(groupbasedn, basedn);
    /* Set dnscope to exclude passwd or group depending on reqbasedn. */
    scope_init(scope, server->uids, server->gids);
    if (!strends(passwdbasedn, reqbasedn))
        scope->mask &= ~SCOPE_PASSWD;
    if (!strends(groupbasedn, reqbasedn))
        scope->mask &= ~SCOPE_GROUP;
    return scope_and(scope, Filter_scope(&req->filter, &fscope));
}

/* Check if an AttributeSelection contains an attribute type. */
static bool AttributeSelection_contains(const AttributeSelection_t *sel, const char *type)
{
    assert(sel);
    assert(type);

    for (int i = 0; i < sel->list.count; i++)
        if (!strcmp((const char *)sel->list.array[i]->buf, type))
            return true;
    /* An empty AttributeSelection means select all attributes. */
    return !sel->list.count;
}

/* Check if an AttributeDescription_present matches a SearchResultEntry. */
static bool AttributeDescription_present(const AttributeDescription_t *present, const SearchResultEntry_t *res)
{
    return SearchResultEntry_get(res, (const char *)present->buf) != NULL;
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

/* Get the search scope for an AttributeValueAssertion_equal check. */
static scope_t *AttributeValueAssertion_equal_scope(const AttributeValueAssertion_t *equal, scope_t *scope)
{
    assert(equal);
    assert(scope);
    const char *name = (const char *)equal->attributeDesc.buf;
    const char *value = (const char *)equal->assertionValue.buf;

    scope_init(scope, NULL, NULL);
    if (!strcmp(name, "objectClass")) {
        if (!strcmp(value, "posixAccount") || !strcmp(value, "shadowAccount"))
            scope->mask = SCOPE_PASSWD;
        else if (!strcmp(value, "posixGroup"))
            scope->mask = SCOPE_GROUP;
        else
            scope->mask = 0;
    } else if (!strcmp(name, "uid")) {
        scope->uid = value;
    } else if (!strcmp(name, "uidNumber")) {
        scope->uidNumber = value;
    } else if (!strcmp(name, "cn")) {
        scope->cn = value;
    } else if (!strcmp(name, "gidNumber")) {
        scope->gidNumber = value;
    }
    return scope;
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
        return AttributeDescription_present(&filter->choice.present, res);
    case Filter_PR_substrings:
    case Filter_PR_greaterOrEqual:
    case Filter_PR_lessOrEqual:
    case Filter_PR_approxMatch:
    case Filter_PR_extensibleMatch:
    default:
        return false;
    }
}

static scope_t *Filter_scope(const Filter_t *filter, scope_t *scope)
{
    assert(filter);
    assert(scope);
    scope_t other;

    switch (filter->present) {
    case Filter_PR_and:
        Filter_scope(filter->choice.And.list.array[0], scope);
        for (int i = 1; i < filter->choice.And.list.count; i++)
            scope_and(scope, Filter_scope(filter->choice.And.list.array[i], &other));
        return scope;
    case Filter_PR_or:
        Filter_scope(filter->choice.Or.list.array[0], scope);
        for (int i = 1; i < filter->choice.Or.list.count; i++)
            scope_or(scope, Filter_scope(filter->choice.Or.list.array[i], &other));
        return scope;
    case Filter_PR_not:
        return scope_not(Filter_scope(filter->choice.Not, scope));
    case Filter_PR_equalityMatch:
        return AttributeValueAssertion_equal_scope(&filter->choice.equalityMatch, scope);
    case Filter_PR_present:
    case Filter_PR_substrings:
    case Filter_PR_greaterOrEqual:
    case Filter_PR_lessOrEqual:
    case Filter_PR_approxMatch:
    case Filter_PR_extensibleMatch:
    default:
        scope_init(scope, NULL, NULL);
        return scope;
    }
}
