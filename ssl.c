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

int mbedtls_ssl_server_init(mbedtls_ssl_server *srv, const char *crtpath, const char *caspath, const char *keypath)
{
    assert(srv);
    assert(crtpath);
    int ret;

    mbedtls_ssl_config_init(&srv->conf);
    mbedtls_ctr_drbg_init(&srv->ctr_drbg);
    mbedtls_entropy_init(&srv->entropy);
    mbedtls_x509_crt_init(&srv->cert);
    mbedtls_pk_init(&srv->pkey);
    /* If keypath is NULL, assume crtpath is a bundled key/cert pem file. */
    keypath = keypath ? keypath : crtpath;
    /* Load the server cert, ca chain, and private key. */
    if ((ret = mbedtls_x509_crt_parse_file(&srv->cert, crtpath)))
        mbedtls_fail1(crtpath, ret, ret);
    if (caspath && (ret = mbedtls_x509_crt_parse_file(&srv->cert, caspath)))
        mbedtls_fail1(caspath, ret, ret);
    if ((ret = mbedtls_pk_parse_keyfile(&srv->pkey, keypath, NULL)))
        mbedtls_fail1(keypath, ret, ret);
    /* Seed the random number generator. */
    if ((ret = mbedtls_ctr_drbg_seed(&srv->ctr_drbg, mbedtls_entropy_func, &srv->entropy, pers, strlen((char *)pers))))
        mbedtls_fail1("mbedtls_ctr_drbg_seed", ret, ret);
    /* Set the config defaults. */
    if ((ret =
         mbedtls_ssl_config_defaults(&srv->conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT)))
        mbedtls_fail1("mbedtls_ssl_config_defaults", ret, ret);
    mbedtls_ssl_conf_rng(&srv->conf, mbedtls_ctr_drbg_random, &srv->ctr_drbg);
    mbedtls_ssl_conf_ca_chain(&srv->conf, srv->cert.next, NULL);
    if ((ret = mbedtls_ssl_conf_own_cert(&srv->conf, &srv->cert, &srv->pkey)))
        mbedtls_fail1("mbedtls_ssl_conf_own_cert", ret, ret);
    return ret;
}

void mbedtls_ssl_server_done(mbedtls_ssl_server *srv)
{
    assert(srv);

    mbedtls_ssl_config_free(&srv->conf);
    mbedtls_ctr_drbg_free(&srv->ctr_drbg);
    mbedtls_entropy_free(&srv->entropy);
    mbedtls_x509_crt_free(&srv->cert);
    mbedtls_pk_free(&srv->pkey);
}

int mbedtls_ssl_connection_init(mbedtls_ssl_context *ssl, mbedtls_ssl_server *srv, mbedtls_net_context *socket)
{
    assert(ssl);
    assert(srv);
    assert(socket);
    int ret;

    mbedtls_ssl_init(ssl);
    if ((ret = mbedtls_ssl_setup(ssl, &srv->conf)))
        mbedtls_fail1("mbedtls_ssl_setup", ret, ret);
    mbedtls_ssl_set_bio(ssl, socket, mbedtls_net_send, mbedtls_net_recv, NULL);
    return ret;
}

void mbedtls_ssl_connection_done(mbedtls_ssl_context *ssl)
{
    assert(ssl);

    mbedtls_ssl_free(ssl);
}
