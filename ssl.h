/** \file ssl.h
 * SSL server class using mbedtls.
 *
 * \copyright Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 * Based on mbedtls provided examples.
 *
 * \licence Licensed under the GPLv3 License. See LICENSE file for details. */

#include "log.h"
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>

#define mbedtls_fail1(msg, err, ret) do {char _s[256]; mbedtls_strerror(err, _s, 256); lwarnx("%s: %s", msg, _s); return ret; } while (0);
#define mbedtls_fail(msg, err) mbedtls_fail1(msg, err, );

typedef struct {
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_x509_crt cert;
    mbedtls_pk_context pkey;
} mbedtls_ssl_server;
mbedtls_ssl_server *mbedtls_ssl_server_new(const char *crtpath, const char *caspath, const char *keypath);
void mbedtls_ssl_server_free(mbedtls_ssl_server *srv);

mbedtls_ssl_context *mbedtls_ssl_connection_new(mbedtls_ssl_server *srv, mbedtls_net_context *socket);
void mbedtls_ssl_connection_free(mbedtls_ssl_context *ssl);
