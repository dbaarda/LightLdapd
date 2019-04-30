/*=
 * Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 * Based on mbedtls provided examples.
 *
 * Licensed under the MIT License. See LICENSE file for details.
 */

#include "ssl.h"
#include "utils.h"
#include <string.h>
#include <unistd.h>

static const unsigned char *pers = (unsigned char *)"lightldapd";

#define mbedtls_ssl_server_fail(msg, err, ptr) do {\
    mbedtls_ssl_server_free(ptr);\
    mbedtls_fail1(msg, err, NULL);\
} while (0)

mbedtls_ssl_server *mbedtls_ssl_server_new(const char *crtpath, const char *caspath, const char *keypath)
{
    assert(crtpath);
    mbedtls_ssl_server *srv = XNEW0(mbedtls_ssl_server, 1);
    int err;

    mbedtls_ssl_config_init(&srv->conf);
    mbedtls_ctr_drbg_init(&srv->ctr_drbg);
    mbedtls_entropy_init(&srv->entropy);
    mbedtls_x509_crt_init(&srv->cert);
    mbedtls_pk_init(&srv->pkey);
    /* If keypath is NULL, assume crtpath is a bundled key/cert pem file. */
    keypath = keypath ? keypath : crtpath;
    /* Load the server cert, ca chain, and private key. */
    if ((err = mbedtls_x509_crt_parse_file(&srv->cert, crtpath)))
        mbedtls_ssl_server_fail(crtpath, err, srv);
    if (caspath && (err = mbedtls_x509_crt_parse_file(&srv->cert, caspath)))
        mbedtls_ssl_server_fail(caspath, err, srv);
    if ((err = mbedtls_pk_parse_keyfile(&srv->pkey, keypath, NULL)))
        mbedtls_ssl_server_fail(keypath, err, srv);
    /* Seed the random number generator. */
    if ((err = mbedtls_ctr_drbg_seed(&srv->ctr_drbg, mbedtls_entropy_func, &srv->entropy, pers, strlen((char *)pers))))
        mbedtls_ssl_server_fail("mbedtls_ctr_drbg_seed", err, srv);
    /* Set the config defaults. */
    if ((err =
         mbedtls_ssl_config_defaults(&srv->conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT)))
        mbedtls_ssl_server_fail("mbedtls_ssl_config_defaults", err, srv);
    mbedtls_ssl_conf_rng(&srv->conf, mbedtls_ctr_drbg_random, &srv->ctr_drbg);
    mbedtls_ssl_conf_ca_chain(&srv->conf, srv->cert.next, NULL);
    if ((err = mbedtls_ssl_conf_own_cert(&srv->conf, &srv->cert, &srv->pkey)))
        mbedtls_ssl_server_fail("mbedtls_ssl_conf_own_cert", err, srv);
    return srv;
}

void mbedtls_ssl_server_free(mbedtls_ssl_server *srv)
{
    if (srv) {
        mbedtls_ssl_config_free(&srv->conf);
        mbedtls_ctr_drbg_free(&srv->ctr_drbg);
        mbedtls_entropy_free(&srv->entropy);
        mbedtls_x509_crt_free(&srv->cert);
        mbedtls_pk_free(&srv->pkey);
        free(srv);
    }
}

#define mbedtls_ssl_connection_fail(msg, err, ptr) do {\
    mbedtls_ssl_connection_free(ptr);\
    mbedtls_fail1(msg, err, NULL);\
} while (0)

mbedtls_ssl_context *mbedtls_ssl_connection_new(mbedtls_ssl_server *srv, mbedtls_net_context *socket)
{
    assert(srv);
    assert(socket);
    mbedtls_ssl_context *ssl = XNEW0(mbedtls_ssl_context, 1);
    int err;

    mbedtls_ssl_init(ssl);
    if ((err = mbedtls_ssl_setup(ssl, &srv->conf)))
        mbedtls_ssl_connection_fail("mbedtls_ssl_setup", err, ssl);
    mbedtls_ssl_set_bio(ssl, socket, mbedtls_net_send, mbedtls_net_recv, NULL);
    return ssl;
}

void mbedtls_ssl_connection_free(mbedtls_ssl_context *ssl)
{
    if (ssl) {
        mbedtls_ssl_free(ssl);
        free(ssl);
    }
}
