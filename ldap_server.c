/*=
 * Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 * Based on entente Copyright (c) 2010, 2011 Sergey Urbanovich
 *
 * Licensed under the MIT License. See LICENSE file for details.
 */

#include "ldap_server.h"
#include "nss2ldap.h"
#include <unistd.h>

#define LISTENQ 128

void accept_cb(ev_loop *loop, ev_io *watcher, int revents);
void read_cb(ev_loop *loop, ev_io *watcher, int revents);
void write_cb(ev_loop *loop, ev_io *watcher, int revents);
void delay_cb(EV_P_ ev_timer *w, int revents);

void buffer_init(buffer_t *buffer)
{
    buffer->len = 0;
}

void buffer_appended(buffer_t *buffer, size_t len)
{
    assert(len <= buffer_wlen(buffer));

    buffer->len += len;
}

void buffer_consumed(buffer_t *buffer, size_t len)
{
    assert(len <= buffer_rlen(buffer));

    buffer->len -= len;
    /* Shuffle any remaining data to start of buffer. */
    if (buffer->len) {
        memmove(buffer->buf, buffer->buf + len, buffer->len);
    }
}

void ldap_server_init(ldap_server *server, ev_loop *loop, char *basedn, uid_t rootuid, bool anonok)
{
    server->basedn = basedn;
    server->rootuid = rootuid;
    server->anonok = anonok;
    server->loop = loop;
    ev_init(&server->connection_watcher, accept_cb);
    server->connection_watcher.data = server;
    server->socket = NULL;
}

void ldap_server_start(ldap_server *server, const mbedtls_net_context *socket)
{
    assert(!ev_is_active(&server->connection_watcher));
    assert(!server->socket);

    ev_io_set(&server->connection_watcher, socket->fd, EV_READ);
    ev_io_start(server->loop, &server->connection_watcher);
    server->socket = socket;
}

void ldap_server_stop(ldap_server *server)
{
    assert(ev_is_active(&server->connection_watcher));

    ev_io_stop(server->loop, &server->connection_watcher);
    server->socket = NULL;
}

ldap_connection *ldap_connection_new(ldap_server *server, int fd)
{
    ldap_connection *connection = XNEW0(ldap_connection, 1);

    connection->server = server;
    connection->binduid = -1;
    ev_io_init(&connection->read_watcher, read_cb, fd, EV_READ);
    connection->read_watcher.data = connection;
    ev_io_init(&connection->write_watcher, write_cb, fd, EV_WRITE);
    connection->write_watcher.data = connection;
    ev_init(&connection->delay_watcher, delay_cb);
    connection->delay_watcher.data = connection;
    connection->recv_msg = NULL;
    connection->request = NULL;
    connection->delay = 0.0;
    buffer_init(&connection->recv_buf);
    buffer_init(&connection->send_buf);
    ev_io_start(server->loop, &connection->read_watcher);
    return connection;
}

void ldap_connection_free(ldap_connection *connection)
{
    ev_io_stop(connection->server->loop, &connection->read_watcher);
    ev_io_stop(connection->server->loop, &connection->write_watcher);
    ev_timer_stop(connection->server->loop, &connection->delay_watcher);
    close(connection->read_watcher.fd);
    LDAPMessage_free(connection->recv_msg);
    while (connection->request)
        ldap_request_free(connection->request);
    free(connection);
}

void ldap_connection_respond(ldap_connection *connection)
{
    assert(connection);
    ldap_server *server = connection->server;
    LDAPMessage_t **msg = &connection->recv_msg;
    ldap_status_t status;

    /* While we've recieved a message, add a request. */
    while ((status = ldap_connection_recv(connection, msg)) == RC_OK) {
        switch ((*msg)->protocolOp.present) {
            /* For known request types, create a new request. */
        case LDAPMessage__protocolOp_PR_bindRequest:
            ldap_request_bind(connection, *msg);
            break;
        case LDAPMessage__protocolOp_PR_searchRequest:
            ldap_request_search(connection, *msg);
            break;
        case LDAPMessage__protocolOp_PR_abandonRequest:
            ldap_request_abandon(connection, *msg);
            break;
        default:
            /* For unknown or unbindRequest, close the connection. */
            return ldap_connection_free(connection);
        }
        *msg = NULL;
    }
    /* If we got an error recieving messages, close the connection. */
    if (status == RC_FAIL)
        return ldap_connection_free(connection);
    /* While there's a request and we are not blocked, respond to the request. */
    while (connection->request && (status = ldap_request_respond(connection->request)) == RC_OK) ;
    /* If we got an error sending messages, close the connection. */
    if (status == RC_FAIL)
        return ldap_connection_free(connection);
    /* Update the state of all the connection watchers. */
    if (connection->delay && !ev_is_active(&connection->delay_watcher)) {
        ev_timer_set(&connection->delay_watcher, connection->delay, 0.0);
        ev_timer_start(server->loop, &connection->delay_watcher);
    }
    if (connection->delay || buffer_full(&connection->recv_buf))
        ev_io_stop(server->loop, &connection->read_watcher);
    else
        ev_io_start(server->loop, &connection->read_watcher);
    if (buffer_empty(&connection->send_buf))
        ev_io_stop(server->loop, &connection->write_watcher);
    else
        ev_io_start(server->loop, &connection->write_watcher);
}

ldap_status_t ldap_connection_send(ldap_connection *connection, LDAPMessage_t *msg)
{
    buffer_t *buf = &connection->send_buf;
    asn_enc_rval_t rencode;

    /* Send nothing if connection is delayed. */
    if (connection->delay)
        return RC_WMORE;
    rencode = der_encode_to_buffer(&asn_DEF_LDAPMessage, msg, buffer_wpos(buf), buffer_wlen(buf));
    /* If it failed the buffer was full, return RC_WMORE to try again. */
    if (rencode.encoded == -1)
        return RC_WMORE;
    buffer_appended(buf, rencode.encoded);
    LDAP_DEBUG(msg);
    return RC_OK;
}

ldap_status_t ldap_connection_recv(ldap_connection *connection, LDAPMessage_t **msg)
{
    buffer_t *buf = &connection->recv_buf;
    asn_dec_rval_t rdecode;

    /* Recv nothing if connection is delayed. */
    if (connection->delay)
        return RC_WMORE;
    /* from asn1c's FAQ: If you want BER or DER encoding, use der_encode(). */
    rdecode = ber_decode(0, &asn_DEF_LDAPMessage, (void **)msg, buffer_rpos(buf), buffer_rlen(buf));
    buffer_consumed(buf, rdecode.consumed);
    if (rdecode.code == RC_FAIL) {
        fail1("ber_decode", RC_FAIL);
    } else if (rdecode.code == RC_OK) {
        LDAP_DEBUG(*msg);
    }
    return rdecode.code;
}

void accept_cb(ev_loop *loop, ev_io *watcher, int revents)
{
    ldap_server *server = watcher->data;
    int client_sd;

    assert(server->loop == loop);
    assert(&server->connection_watcher == watcher);

    if (EV_ERROR & revents)
        fail("got invalid event");
    if ((client_sd = accept(watcher->fd, NULL, NULL)) < 0)
        fail("accept error");
    ldap_connection_new(server, client_sd);
}

void read_cb(ev_loop *loop, ev_io *watcher, int revents)
{
    ldap_connection *connection = watcher->data;
    buffer_t *buf = &connection->recv_buf;
    ssize_t buf_cnt;

    assert(connection->server->loop == loop);
    assert(&connection->read_watcher == watcher);

    if (EV_ERROR & revents)
        fail("got invalid event");
    buf_cnt = recv(watcher->fd, buffer_wpos(buf), buffer_wlen(buf), 0);
    if (buf_cnt <= 0) {
        ldap_connection_free(connection);
        if (buf_cnt < 0)
            fail("read");
        return;
    }
    buffer_appended(buf, buf_cnt);
    ldap_connection_respond(connection);
}

void write_cb(ev_loop *loop, ev_io *watcher, int revents)
{
    assert(revents == EV_WRITE);
    ldap_connection *connection = watcher->data;
    buffer_t *buf = &connection->send_buf;
    ssize_t buf_cnt;

    assert(connection->server->loop == loop);
    assert(&connection->write_watcher == watcher);

    buf_cnt = send(watcher->fd, buffer_rpos(buf), buffer_rlen(buf), MSG_NOSIGNAL);
    if (buf_cnt < 0) {
        ldap_connection_free(connection);
        fail("send");
    }
    buffer_consumed(buf, buf_cnt);
    ldap_connection_respond(connection);
}

void delay_cb(ev_loop *loop, ev_timer *watcher, int revents)
{
    assert(revents == EV_TIMER);
    ldap_connection *connection = watcher->data;

    assert(connection->server->loop == loop);
    assert(&connection->delay_watcher == watcher);

    connection->delay = 0.0;
    ldap_connection_respond(connection);
}

/* Allocate and initialize a bare ldap_request from a request message. */
ldap_request *ldap_request_new(ldap_connection *connection, LDAPMessage_t *msg)
{
    assert(connection);
    assert(msg);
    ldap_request *request = XNEW0(ldap_request, 1);

    request->connection = connection;
    request->message = msg;
    request->reply = NULL;
    request->count = 0;
    /* Add the request to the connection's circular dlist. */
    ldap_request_add(&connection->request, request);
    return request;
}

/* Destroy and free an ldap_response. */
void ldap_request_free(ldap_request *request)
{
    if (request) {
        /* Remove the request from the connection's circular dlist. */
        ldap_connection *connection = request->connection;
        ldap_request_rem(&connection->request, request);
        LDAPMessage_free(request->message);
        while (request->reply)
            ldap_reply_free(request->reply);
        free(request);
    }
}

/* Allocate and initialize a bind ldap_request from a bind message. */
ldap_request *ldap_request_bind(ldap_connection *connection, LDAPMessage_t *msg)
{
    assert(msg->protocolOp.present == LDAPMessage__protocolOp_PR_bindRequest);
    ldap_request *request = ldap_request_new(connection, msg);

    ldap_request_bind_pam(request);
    return request;
}

/* Allocate and initialize a search ldap_request from a search message. */
ldap_request *ldap_request_search(ldap_connection *connection, LDAPMessage_t *msg)
{
    assert(msg->protocolOp.present == LDAPMessage__protocolOp_PR_searchRequest);
    ldap_request *request = ldap_request_new(connection, msg);

    ldap_request_search_nss(request);
    return request;
}

/* Find and abandon a request from the circular dlist. */
void ldap_request_abandon(ldap_connection *connection, LDAPMessage_t *msg)
{
    assert(connection);
    assert(msg);
    ldap_request *l = connection->request;
    ldap_request *e;
    int msgid = msg->messageID;

    /* Consume the message like we do for other request types. */
    LDAPMessage_free(msg);
    for (e = l; e; e = ldap_request_next(&l, e))
        if (e->message->messageID == msgid)
            return ldap_request_free(e);
}

/* Process a single reply for an ldap_response. */
ldap_status_t ldap_request_respond(ldap_request *request)
{
    assert(request);
    assert(request->reply);
    ldap_status_t status = ldap_reply_respond(request->reply);

    /* If we sent a reply, rotate the connection to the next request. */
    if (status == RC_OK)
        request->connection->request = request->next;
    /* If we have no more replies, we are done. */
    if (!request->reply)
        ldap_request_free(request);
    return status;
}

/* Allocate and initialize a bare ldap_reply for an ldap_request. */
ldap_reply *ldap_reply_new(ldap_request *request)
{
    assert(request);
    ldap_reply *reply = XNEW0(ldap_reply, 1);

    reply->request = request;
    reply->message.messageID = request->message->messageID;
    /* Add the reply to the request's circular dlist. */
    ldap_reply_add(&request->reply, reply);
    request->count++;
    return reply;
}

/* Destroy and free an ldap_response. */
void ldap_reply_free(ldap_reply *reply)
{
    if (reply) {
        /* Remove the reply from the request's circular dlist. */
        ldap_reply_rem(&reply->request->reply, reply);
        LDAPMessage_done(&reply->message);
        free(reply);
    }
}

ldap_status_t ldap_reply_respond(ldap_reply *reply)
{
    assert(reply);
    ldap_status_t status = ldap_connection_send(reply->request->connection, &reply->message);

    /* If the message was sent, we are done. */
    if (status == RC_OK)
        ldap_reply_free(reply);
    return status;
}
