/*=
 * Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 *
 * Licensed under the MIT License. See LICENSE file for details.
 */
#ifndef LIGHTLDAPD_NSS2LDAP_H
#define LIGHTLDAPD_NSS2LDAP_H
#include <sys/types.h>
#include <pwd.h>
#include <stdbool.h>
#include "asn1/LDAPMessage.h"

#define PWNAME_MAX 32           /**< The max length of a username string. */
#define STRING_MAX 256          /**< The max length of an LDAPString. */
#define RESPONSE_MAX 100000     /**< The max results in any response. */

/** Destroy and free an LDAPMessage instance. */
#define ldapmessage_free(msg) ASN_STRUCT_FREE(asn_DEF_LDAPMessage, msg)

/** Destroy an LDAPMessage freeing its contents only. */
#define ldapmessage_empty(msg) ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_LDAPMessage, msg)

#ifdef DEBUG
#define LDAP_DEBUG(msg) asn_fprint(stdout, &asn_DEF_LDAPMessage, msg)
#else
#define LDAP_DEBUG(msg)
#endif

/** Allocate and initialize an LDAPString instance. */
#define LDAPString_new(s) OCTET_STRING_new_fromBuf(&asn_DEF_LDAPString, (s), -1)

/** Set an LDAPString instance from a string. */
#define LDAPString_set(str, s) OCTET_STRING_fromString((str), (s));

/** The type for passwd entries. */
typedef struct passwd passwd_t;

/** A collection of LDAPMessages that make up an ldap response. */
typedef struct {
    int count;                  /**< The number of LDAPMessages in the
                                 * response. */
    int next;                   /**< The index of the next message to send. */
    int size;                   /**< The allocated size of **replies. */
    LDAPMessage_t **msgs;       /**< Array of LDAPMessages in the reply. */
} ldap_response;

/** Initialize an ldap_reponse.
 *
 * \param *res - the ldap_response to initialize.
 *
 * \param size - the initial size to allocate. */
void ldap_response_init(ldap_response *res, int size);

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

/** Get the ldap_response for a SearchRequest message.
 *
 * \param res - the ldap_response to add the replies to.
 *
 * \param basedn - The basedn to use.
 *
 * \param msgid - the messageID of the request.
 *
 * \param req - The SearchRequest to respond to. */
void ldap_response_search(ldap_response *res, const char *basedn, const int msgid, const SearchRequest_t *req);

/** Return a full "uid=<name>,<basedn>" ldap dn from a name and basedn.
 *
 * \param basedn - the ldap base dn string.
 *
 * \param name - the user name string.
 *
 * \param dn - a char[STRING_MAX] buffer to hold the result.
 *
 * \return a pointer to the ldap dn string result. */
char *name2dn(const char *basedn, const char *name, char *dn);

/** Return the name from a full "uid=<name>,<basedn>" ldap dn.
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

/** Set a SearchResultEntry from an nss passwd entry.
 *
 * \param res - the SearchResultEntry to set.
 *
 * \pram basedn - the basedn to use.
 *
 * \param pw - the nss passwd entry. */
void passwd2ldap(SearchResultEntry_t *res, const char *basedn, passwd_t *pw);

/** Set a SearchResultEntry from an nss user's name.
 *
 * \param res - the SearchResultEntry to set.
 *
 * \param basedn - the ldap basedn to use.
 *
 * \param name - the nss user name to use.
 *
 * \return 0 if successful, -1 if there was no such user. */
int getpwnam2ldap(SearchResultEntry_t *res, const char *basedn, const char *name);

/** Check if a Filter is fully supported.
 *
 * \param filter - The the Filter to check.
 *
 * \return true if the filter is supported, otherwise false. */
bool Filter_ok(const Filter_t *filter);

/** Check if a Filter matches a SearchResultEntry.
 *
 * \param filter - The Filter to use.
 *
 * \param res - the SearchResultEntry to test.
 *
 * \return true if res matches filter, otherwise false. */
bool Filter_matches(const Filter_t *filter, const SearchResultEntry_t *res);

#endif                          /* LIGHTLDAPD_NSS2LDAP_H */
