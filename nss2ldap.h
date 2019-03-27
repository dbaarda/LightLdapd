/*=
 * Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 *
 * Licensed under the MIT License. See LICENSE file for details.
 */
#ifndef LIGHTLDAPD_NSS2LDAP_H
#define LIGHTLDAPD_NSS2LDAP_H
#include "utils.h"
#include "asn1/LDAPMessage.h"

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

/** An ldap reply message circular dlist entry. */
typedef struct ldap_reply ldap_reply;
struct ldap_reply {
    ldap_reply *next, *prev;
    LDAPMessage_t msg;
};
#define ENTRY ldap_reply
#include "dlist.h"

/** A collection of LDAPMessages that make up an ldap response. */
typedef struct {
    int count;                  /**< The count of messages in the response. */
    ldap_reply *reply;          /**< The circular dlist of replies. */
} ldap_response;

/** Initialize an ldap_reponse.
 *
 * \param *res - the ldap_response to initialize. */
void ldap_response_init(ldap_response *res);

/** Destroy an ldap_response.
 *
 * \param *res - the ldap_response to destroy. */
void ldap_response_done(ldap_response *res);

/** Add an LDAPMessage_t to an ldap_response.
 *
 * \param *res - the ldap_response to add to.
 *
 * \return the LDAPMessage_t added. */
LDAPMessage_t *ldap_response_add(ldap_response *res);

/** Get the next LDAPMessage_t to send.
 *
 * \param *res - the ldap_response to get it from.
 *
 * \return the next LDAPMessage_t to send, or NULL if finished. */
LDAPMessage_t *ldap_response_get(ldap_response *res);

/** Increment the next LDAPMessage_t to send.
 *
 * \param *res - the ldap_response to increment. */
void ldap_response_inc(ldap_response *res);

/** Get the ldap_response for a BindRequest message.
 *
 * \param res - The ldap_response to add the replies to.
 *
 * \param basedn - The basedn to use.
 *
 * \param anonok - If the anonymous auth is permitted.
 *
 * \param msgid - The messageID of the request.
 *
 * \param req - The BindRequest to respond to.
 *
 * \param binduid - The returned uid bound to.
 *
 * \param delay - The returned delay time for a failed bind. */
void ldap_response_bind(ldap_response *res, const char *basedn, const bool anonok, const int msgid,
                        const BindRequest_t *req, uid_t *binduid, double *delay);

/** Get the ldap_response for a SearchRequest message.
 *
 * \param res - the ldap_response to add the replies to.
 *
 * \param basedn - The basedn to use.
 *
 * \param isroot - If the request has 'root' access.
 *
 * \param msgid - the messageID of the request.
 *
 * \param req - The SearchRequest to respond to. */
void ldap_response_search(ldap_response *res, const char *basedn, const bool isroot, const int msgid,
                          const SearchRequest_t *req);

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
