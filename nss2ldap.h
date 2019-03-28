/*=
 * Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 *
 * Licensed under the MIT License. See LICENSE file for details.
 */
#ifndef LIGHTLDAPD_NSS2LDAP_H
#define LIGHTLDAPD_NSS2LDAP_H
#include "utils.h"
#include "ldap_server.h"

#define PWNAME_MAX 32           /**< The max length of a username string. */
#define STRING_MAX 256          /**< The max length of an LDAPString. */
#define RESPONSE_MAX 100000     /**< The max results in any response. */

/** Destroy and free an LDAPMessage instance. */
#define LDAPMessage_free(msg) ASN_STRUCT_FREE(asn_DEF_LDAPMessage, msg)

/** Destroy an LDAPMessage freeing its contents only. */
#define LDAPMessage_done(msg) ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_LDAPMessage, msg)

#ifdef DEBUG
#define LDAP_DEBUG(msg) asn_fprint(stdout, &asn_DEF_LDAPMessage, msg)
#else
#define LDAP_DEBUG(msg)
#endif

/** Add the ldap_replies for a BindRequest ldap_request using pam.
 *
 * \param request - The ldap_request to add the replies to. */
void ldap_request_bind_pam(ldap_request *request);

/** Add the ldap_replies for a SearchRequest ldap_request using nss.
 *
 * \param request - the ldap_request to add the replies to. */
void ldap_request_search_nss(ldap_request *request);

/** Return a full "uid=<name>,ou=people,..." ldap dn from a name and basedn.
 *
 * \param basedn - the ldap base dn string.
 *
 * \param name - the user name string.
 *
 * \param dn - a char[STRING_MAX] buffer to hold the result.
 *
 * \return a pointer to the ldap dn string result. */
char *name2dn(const char *basedn, const char *name, char *dn);

/** Return the name from a full "uid=<name>,ou=people,..." ldap dn.
 *
 * This checks that the dn provided is in the valid form with the right basedn
 * and returns NULL if it is invalid.
 *
 * \param basedn - the ldap basedn string expected.
 *
 * \param dn - the full ldap dn string.
 *
 * \param name - a char[PWNAME_MAX] buffer to hold the result.
 *
 * \return a pointer to the name result or NULL if dn was invalid. */
char *dn2name(const char *basedn, const char *dn, char *name);

#endif                          /* LIGHTLDAPD_NSS2LDAP_H */
