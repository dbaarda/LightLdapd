/** \file nss2ldap.h
 * LDAP request handers using NSS and PAM.
 *
 * \copyright Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 *
 * \licence Licensed under the GPLv3 License. See LICENSE file for details. */
#ifndef LIGHTLDAPD_NSS2LDAP_H
#define LIGHTLDAPD_NSS2LDAP_H
#include "ldap_server.h"

#define PWNAME_MAX 32           /**< The max length of a username string. */
#define STRING_MAX 256          /**< The max length of an LDAPString. */
#define RESPONSE_MAX 100000     /**< The max results in any response. */

/** Add the ldap_replies for a BindRequest ldap_request using pam.
 *
 * \param request - The ldap_request to add the replies to. */
void ldap_request_bind_pam(ldap_request *request);

/** Add the ldap_replies for a SearchRequest ldap_request using nss.
 *
 * \param request - the ldap_request to add the replies to. */
void ldap_request_search_nss(ldap_request *request);

#endif                          /* LIGHTLDAPD_NSS2LDAP_H */
