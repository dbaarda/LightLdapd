/** \file ldap_server.h
 * An LDAP server and supporting classes.
 *
 * \copyright Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 * Based on entente Copyright (c) 2010, 2011 Sergey Urbanovich
 *
 * \licence Licensed under the GPLv3 License. See LICENSE file for details. */
#ifndef LIGHTLDAPD_LDAP_SERVER_H
#define LIGHTLDAPD_LDAP_SERVER_H

#include "utils.h"
#include "ssl.h"
#include "buffer.h"
#include "ranges.h"
#include "asn1/LDAPMessage.h"
#define EV_COMPAT3 0            /* Use the ev 4.X API. */
#include <ev.h>
#include <arpa/inet.h>

/* Pre-declare types needed for forward referencing. */
typedef struct ldap_request ldap_request;
typedef struct ldap_reply ldap_reply;

/** The ldap_server class. */
typedef struct {
    mbedtls_net_context socket; /**< The mbedtls server socket used. */
    const char *basedn;         /**< The ldap basedn to use. */
    const char *rootuser;       /**< The name of admin "root" user. */
    uid_t rootuid;              /**< The uid of admin "root" user. */
    bool anonok;                /**< If anonymous bind is allowed. */
    const ldap_ranges *uids;    /**< The ranges of uids exported. */
    const ldap_ranges *gids;    /**< The ranges of gids exported. */
    ev_loop *loop;              /**< The libev loop to use. */
    ev_io connection_watcher;   /**< The libev incoming connection watcher. */
    mbedtls_ssl_server *ssl;    /**< The mbedtls ssl server config. */
} ldap_server;
int ldap_server_init(ldap_server *server, ev_loop *loop, const char *basedn, const char *rootuser, const bool anonok,
                     const char *crtpath, const char *caspath, const char *keypath, const ldap_ranges *uids,
                     const ldap_ranges *gids);
void ldap_server_start(ldap_server *server, mbedtls_net_context socket);
void ldap_server_stop(ldap_server *server);

/* Reuse the ber_decode return value enum as the ldap recv/send status. */
typedef enum asn_dec_rval_code_e ldap_status_t;

/** The ldap_connection class. */
typedef struct {
    ldap_server *server;        /**< The server for this connection. */
    mbedtls_net_context socket; /**< The mbedtls client socket used. */
    char client_ip[INET6_ADDRSTRLEN];   /**< The client ip address. */
    uid_t binduid;              /**< The uid the client binded to. */
    ev_io read_watcher;         /**< The libev data read watcher. */
    ev_io write_watcher;        /**< The libev data write watcher. */
    ev_timer delay_watcher;     /**< The libev failed bind delay watcher. */
    LDAPMessage_t *recv_msg;    /**< The incoming message being decoded */
    ldap_request *request;      /**< The circular dlist of requests. */
    ev_tstamp delay;            /**< The delay time to pause for. */
    buffer_t recv_buf;          /**< The buffer for incoming data. */
    buffer_t send_buf;          /**< The buffer for outgoing data. */
    mbedtls_ssl_context *ssl;   /**< The mbedtls ssl context. */
} ldap_connection;
ldap_connection *ldap_connection_new(ldap_server *server, mbedtls_net_context socket, const char *ip);
void ldap_connection_free(ldap_connection *connection);
void ldap_connection_close(ldap_connection *connection);
void ldap_connection_respond(ldap_connection *connection);
ldap_status_t ldap_connection_send(ldap_connection *connection, LDAPMessage_t *msg);
ldap_status_t ldap_connection_recv(ldap_connection *connection, LDAPMessage_t **msg);

/** The ldap_request class. */
struct ldap_request {
    ldap_request *next, *prev;  /**< The circular dlist pointers. */
    ldap_connection *connection;        /**< The connection for this request. */
    LDAPMessage_t *message;     /**< The recieved request message. */
    ldap_reply *reply;          /**< The dlist of replies for this request. */
    int count;                  /**< The count of replies for this request. */
};
ldap_request *ldap_request_new(ldap_connection *connection, LDAPMessage_t *msg);
void ldap_request_free(ldap_request *request);
ldap_request *ldap_request_bind(ldap_connection *connection, LDAPMessage_t *msg);
ldap_request *ldap_request_search(ldap_connection *connection, LDAPMessage_t *msg);
ldap_request *ldap_request_extended(ldap_connection *connection, LDAPMessage_t *msg);
void ldap_request_abandon(ldap_connection *connection, LDAPMessage_t *msg);
ldap_status_t ldap_request_respond(ldap_request *request);
#define ENTRY ldap_request
#include "dlist.h"

/** The ldap_reply class. */
struct ldap_reply {
    ldap_reply *next, *prev;
    ldap_request *request;
    LDAPMessage_t message;
};
ldap_reply *ldap_reply_new(ldap_request *request);
void ldap_reply_free(ldap_reply *reply);
ldap_status_t ldap_reply_respond(ldap_reply *reply);
#define ENTRY ldap_reply
#include "dlist.h"

#endif                          /* LIGHTLDAPD_LDAP_SERVER_H */
