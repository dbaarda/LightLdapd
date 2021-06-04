/** \file pam.h
 * PAM authentication handler.
 *
 * \copyright Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 *
 * \licence Licensed under the GPLv3 License. See LICENSE file for details. */
#ifndef LIGHTLDAPD_PAM_H
#define LIGHTLDAPD_PAM_H
#include <security/pam_appl.h>

#define PAMMSG_LEN 256          /**< The max length of a PAM message string. */

/** Function type to authenticate a user and password.
 *
 * Does an authentication and account check for a user and password. It must
 * always return immediately, returning a PAM result code. If the
 * authentication failed, *msg will have an error string and *delay will have
 * the seconds to delay before responding to the client.
 *
 * \param user - the user name string to authenticate,
 *
 * \param *pw - the password string to authenticate with.
 *
 * \param *msg - a char[PAMMSG_LEN] string for failure messages.
 *
 * \param *delay - the seconds to delay for failed auth attempts.
 *
 * \return a PAM result code from security/pam_appl.h. */
typedef int auth_func_t(const char *user, const char *pw, char *msg, double *delay);

/** Function to use for authenticating a user and password.
 *
 * This can be set to any `auth_*()` function to select the authentication
 * method to use. It defaults to `auth_pam()`. */
extern auth_func_t *auth_user;

/** Authenticate a user and password using PAM. */
int auth_pam(const char *user, const char *pw, char *msg, double *delay);

/** Authenticate a user and password using NSS. */
int auth_nss(const char *user, const char *pw, char *msg, double *delay);

#endif                          /* LIGHTLDAPD_PAM_H */
