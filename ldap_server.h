/*=
 * Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 * Based on entente Copyright (c) 2010, 2011 Sergey Urbanovich
 *
 * Licensed under the MIT License. See LICENSE file for details.
 */
#ifndef LIGHTLDAPD_LDAP_SERVER_H
#define LIGHTLDAPD_LDAP_SERVER_H

#include "utils.h"
#include "asn1/LDAPMessage.h"
#define EV_COMPAT3 0            /* Use the ev 4.X API. */
#include <ev.h>
#include <mbedtls/net_sockets.h>

#define BUFFER_SIZE 16384
typedef struct {
    char buf[BUFFER_SIZE];
    size_t len;
} buffer_t;
void buffer_init(buffer_t *buffer);
void buffer_appended(buffer_t *buffer, size_t len);
void buffer_consumed(buffer_t *buffer, size_t len);
#define buffer_wpos(buffer) ((buffer)->buf + (buffer)->len)
#define buffer_wlen(buffer) (BUFFER_SIZE - (buffer)->len)
#define buffer_rpos(buffer) ((buffer)->buf)
#define buffer_rlen(buffer) ((buffer)->len)
#define buffer_empty(buffer) (!(buffer)->len)
#define buffer_full(buffer) ((buffer)->len == BUFFER_SIZE)

/* Pre-declare types needed for forward referencing. */
typedef struct ldap_request ldap_request;
typedef struct ldap_reply ldap_reply;

/** The ldap_server class. */
typedef struct {
    char *basedn;               /**< The ldap basedn to use. */
    uid_t rootuid;              /**< The uid of admin "root" user. */
    bool anonok;                /**< If anonymous bind is allowed. */
    ev_loop *loop;              /**< The libev loop to use. */
    ev_io connection_watcher;   /**< The libev incoming connection watcher. */
    const mbedtls_net_context *socket;  /**< The mbedtls socket used. */
} ldap_server;
void ldap_server_init(ldap_server *server, ev_loop *loop, char *basedn, uid_t rootuid, bool anonok);
void ldap_server_start(ldap_server *server, const mbedtls_net_context *socket);
void ldap_server_stop(ldap_server *server);

/* Reuse the ber_decode return value enum as the ldap recv/send status. */
typedef enum asn_dec_rval_code_e ldap_status_t;

/** The ldap_connection class. */
typedef struct {
    ldap_server *server;        /**< The server for this connection. */
    uid_t binduid;              /**< The uid the client binded to. */
    ev_io read_watcher;         /**< The libev data read watcher. */
    ev_io write_watcher;        /**< The libev data write watcher. */
    ev_timer delay_watcher;     /**< The libev failed bind delay watcher. */
    LDAPMessage_t *recv_msg;    /**< The incoming message being decoded */
    ldap_request *request;      /**< The circular dlist of requests. */
    ev_tstamp delay;            /**< The delay time to pause for. */
    buffer_t recv_buf;          /**< The buffer for incoming data. */
    buffer_t send_buf;          /**< The buffer for outgoing data. */
} ldap_connection;
ldap_connection *ldap_connection_new(ldap_server *server, int fd);
void ldap_connection_free(ldap_connection *connection);
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
