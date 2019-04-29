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

/** Initialize an LDAPMessage and set its msgid. */
#define LDAPMessage_init(msg, msgid) do { memset(msg, 0, sizeof(*msg)); msg->messageID = msgid; } while(0);

/* LDAPString methods. */
#define LDAPString_new(s) OCTET_STRING_new_fromBuf(&asn_DEF_LDAPString, (s), -1)
#define LDAPString_set(str, s) OCTET_STRING_fromString((str), (s));

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

#endif                          /* LIGHTLDAPD_NSS2LDAP_H */
