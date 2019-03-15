/**
 * Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 *
 * Licensed under the MIT License. See LICENSE file for details.
 */

#include "pam.h"
#include "utils.h"

typedef struct {
	const char *user, *pw;
	double delay;
} auth_pam_data_t;

static int auth_pam_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr);
static void auth_pam_delay(int retval, unsigned usec_delay, void *appdata_ptr);

int auth_pam(const char *user, const char *pw, char *msg, double *delay)
{
	int pam_res = -1;
	auth_pam_data_t data;
	struct pam_conv conv_info;
	pam_handle_t *pamh = NULL;

	data.user = user;
	data.pw = pw;
	data.delay = 0.0;
	conv_info.conv = &auth_pam_conv;
	conv_info.appdata_ptr = (void *)&data;
	/* Start PAM transaction. */
	if (PAM_SUCCESS != (pam_res = pam_start("lightldapd", user, &conv_info, &pamh)))
		snprintf(msg, PAMMSG_LEN, "PAM: Could not start pam service: %s\n", pam_strerror(pamh, pam_res));
	/* Set failure delay handler function. */
	else if (PAM_SUCCESS != (pam_res = pam_set_item(pamh, PAM_FAIL_DELAY, &auth_pam_delay)))
		snprintf(msg, PAMMSG_LEN, "PAM: Could not set failure delay handler: %s\n",
			 pam_strerror(pamh, pam_res));
	/* Try authenticate. */
	else if (PAM_SUCCESS != (pam_res = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK)))
		snprintf(msg, PAMMSG_LEN, "PAM: user %s - not authenticated: %s\n", user, pam_strerror(pamh, pam_res));
	/* Validate account. */
	else if (PAM_SUCCESS != (pam_res = pam_acct_mgmt(pamh, PAM_DISALLOW_NULL_AUTHTOK)))
		snprintf(msg, PAMMSG_LEN, "PAM: user %s - invalid account: %s", user, pam_strerror(pamh, pam_res));
	/* End PAM transaction. */
	pam_end(pamh, pam_res);
	*delay = data.delay;
	return pam_res;
}

static int auth_pam_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
	auth_pam_data_t *data = (auth_pam_data_t *) appdata_ptr;

	if (!resp || !msg || !data)
		return PAM_CONV_ERR;
	*resp = XNEW0(struct pam_response, num_msg);
	for (int i = 0; i < num_msg; i++) {
		/* select response based on requested output style */
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_ON:
			(*resp)[i].resp = XSTRDUP(data->user);
			break;
		case PAM_PROMPT_ECHO_OFF:
			(*resp)[i].resp = XSTRDUP(data->pw);
			break;
		default:
			for (int j = 0; j < i; j++)
				free((*resp)[j].resp);
			free(*resp);
			*resp = NULL;
			return PAM_CONV_ERR;
		}
	}
	return PAM_SUCCESS;
}

static void auth_pam_delay(int retval, unsigned usec_delay, void *appdata_ptr)
{
	auth_pam_data_t *data = (auth_pam_data_t *) appdata_ptr;

	/* Only set the delay if the auth failed. */
	if (PAM_SUCCESS != retval)
		data->delay = usec_delay * 1.0e-6;
}
