/*=
 * Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 * Based on mbedtls provided examples.
 *
 * Licensed under the MIT License. See LICENSE file for details.
 */

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>

#define mbedtls_fail1(msg, err, ret) do {char _s[256]; mbedtls_strerror(err, _s, 256); warnx("%s: %s", msg, _s); return ret; } while (0);
#define mbedtls_fail(msg, err) mbedtls_fail1(msg, err, );

typedef struct {
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_x509_crt cert;
    mbedtls_pk_context pkey;
} mbedtls_ssl_server;
int mbedtls_ssl_server_init(mbedtls_ssl_server *srv, const char *crtpath, const char *caspath, const char *keypath);
void mbedtls_ssl_server_done(mbedtls_ssl_server *srv);

int mbedtls_ssl_connection_init(mbedtls_ssl_context *ssl, mbedtls_ssl_server *srv, mbedtls_net_context *socket);
void mbedtls_ssl_connection_done(mbedtls_ssl_context *ssl);
