/*=
 * Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 *
 * Licensed under the GPLv3 License. See LICENSE file for details.
 */
#ifndef LIGHTLDAPD_PAM_H
#define LIGHTLDAPD_PAM_H
#include <security/pam_appl.h>

#define PAMMSG_LEN 256          /**< The max length of a PAM message string. */

/** PAM authenticate a user and password.
 *
 * This does a PAM authentication and account check for a user and password. It
 * always returns immediately, returning a result code. If the authentication
 * failed, *msg will have an error string and *delay will have the seconds to
 * delay before responding to the client.
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
int auth_pam(const char *user, const char *pw, char *msg, double *delay);
#endif                          /* LIGHTLDAPD_PAM_H */
