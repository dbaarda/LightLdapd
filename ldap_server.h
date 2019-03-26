/*=
 * Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 * Based on entente Copyright (c) 2010, 2011 Sergey Urbanovich
 *
 * Licensed under the MIT License. See LICENSE file for details.
 */

#include "utils.h"
#include "nss2ldap.h"
#define EV_COMPAT3 0            /* Use the ev 4.X API. */
#include <ev.h>

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

typedef struct {
    char *basedn;               /**< The ldap basedn to use. */
    uid_t rootuid;              /**< The uid of admin "root" user. */
    bool anonok;                /**< If anonymous bind is allowed. */
    ev_loop *loop;              /**< The libev loop to use. */
    ev_io connection_watcher;   /**< The libev incoming connection watcher. */
} ldap_server;
void ldap_server_init(ldap_server *server, ev_loop *loop, char *basedn, uid_t rootuid, bool anonok);
int ldap_server_start(ldap_server *server, uint32_t addr, int port);
void ldap_server_stop(ldap_server *server);

/* Reuse the ber_decode return value enum as the ldap recv/send status. */
typedef enum asn_dec_rval_code_e ldap_status_t;

typedef struct {
    ldap_server *server;        /**< The server for this connection. */
    uid_t binduid;              /**< The uid the client binded to. */
    ev_io read_watcher;         /**< The libev data read watcher. */
    ev_io write_watcher;        /**< The libev data write watcher. */
    ev_timer delay_watcher;     /**< The libev failed bind delay watcher. */
    LDAPMessage_t *request;
    ldap_status_t request_status;
    ldap_response response;
    ldap_status_t response_status;
    ev_tstamp delay;            /**< The delay time to pause for. */
    buffer_t recv_buf;          /**< The buffer for incoming data. */
    buffer_t send_buf;          /**< The buffer for outgoing data. */
} ldap_connection;
ldap_connection *ldap_connection_new(ldap_server *server, int fd);
void ldap_connection_free(ldap_connection *connection);
void ldap_connection_respond(ldap_connection *connection);
ldap_status_t ldap_connection_send(ldap_connection *connection, LDAPMessage_t *msg);
ldap_status_t ldap_connection_recv(ldap_connection *connection, LDAPMessage_t **msg);

void ldap_request_init(ldap_connection *connection);
void ldap_request_done(ldap_connection *connection);
ldap_status_t ldap_request_reply(ldap_connection *connection, LDAPMessage_t *req);
