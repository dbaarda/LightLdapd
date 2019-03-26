/*=
 * Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 * Based on entente Copyright (c) 2010, 2011 Sergey Urbanovich
 *
 * Licensed under the MIT License. See LICENSE file for details.
 */

#include "ldap_server.h"
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
}

int ldap_server_start(ldap_server *server, uint32_t addr, int port)
{
    int serv_sd;
    int opt = 1;
    struct sockaddr_in servaddr;

    assert(!ev_is_active(&server->connection_watcher));

    if ((serv_sd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
        fail1("socket", -1);
    if (setsockopt(serv_sd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        fail1("setsockopt", -1);
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(addr);
    servaddr.sin_port = htons(port);
    if (bind(serv_sd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
        fail1("bind", -1);
    if (listen(serv_sd, LISTENQ) < 0)
        fail1("listen", -1);
    ev_io_set(&server->connection_watcher, serv_sd, EV_READ);
    ev_io_start(server->loop, &server->connection_watcher);
    return serv_sd;
}

void ldap_server_stop(ldap_server *server)
{
    assert(ev_is_active(&server->connection_watcher));

    ev_io_stop(server->loop, &server->connection_watcher);
    close(server->connection_watcher.fd);
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
    connection->delay = 0.0;
    buffer_init(&connection->recv_buf);
    buffer_init(&connection->send_buf);
    ldap_request_init(connection);
    ev_io_start(server->loop, &connection->read_watcher);
    return connection;
}

void ldap_connection_free(ldap_connection *connection)
{
    ev_io_stop(connection->server->loop, &connection->read_watcher);
    ev_io_stop(connection->server->loop, &connection->write_watcher);
    ev_timer_stop(connection->server->loop, &connection->delay_watcher);
    close(connection->read_watcher.fd);
    ldap_request_done(connection);
    free(connection);
}

void ldap_connection_respond(ldap_connection *connection)
{
    ldap_server *server = connection->server;
    LDAPMessage_t **req = &connection->recv_msg;
    ldap_response *rsp = &connection->response;
    ldap_status_t status;

    /* Recieve and reply to requests until blocked on recv or reply. */
    while ((rsp->count || (status = ldap_connection_recv(connection, req)) == RC_OK)
           && (status = ldap_request_reply(connection, *req)) == RC_OK) {
        ldap_request_done(connection);
        ldap_request_init(connection);
    }
    if (status == RC_FAIL) {
        ldap_connection_free(connection);
        return;
    }
    if (connection->delay && !ev_is_active(&connection->delay_watcher)) {
        ev_timer_set(&connection->delay_watcher, connection->delay, 0.0);
        ev_timer_start(server->loop, &connection->delay_watcher);
    }
    if (connection->delay || buffer_full(&connection->recv_buf)) {
        ev_io_stop(server->loop, &connection->read_watcher);
    } else {
        ev_io_start(server->loop, &connection->read_watcher);
    }
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

void ldap_request_init(ldap_connection *connection)
{
    connection->recv_msg = NULL;
    ldap_response_init(&connection->response);
}

void ldap_request_done(ldap_connection *connection)
{
    LDAPMessage_free(connection->recv_msg);
    ldap_response_done(&connection->response);
}

ldap_status_t ldap_request_reply(ldap_connection *connection, LDAPMessage_t *req)
{
    assert(connection);
    ldap_server *server = connection->server;
    ldap_response *response = &connection->response;
    ldap_status_t status = RC_WMORE;
    LDAPMessage_t *msg;
    bool isroot = server->rootuid == connection->binduid;

    /* If we have not built the response, build it first. */
    if (!response->count) {
        switch (req->protocolOp.present) {
        case LDAPMessage__protocolOp_PR_bindRequest:
            ldap_response_bind(response, server->basedn, server->anonok, req->messageID,
                               &req->protocolOp.choice.bindRequest, &connection->binduid, &connection->delay);
            break;
        case LDAPMessage__protocolOp_PR_searchRequest:
            ldap_response_search(response, server->basedn, isroot, req->messageID,
                                 &req->protocolOp.choice.searchRequest);
            break;
        case LDAPMessage__protocolOp_PR_abandonRequest:
            /* Ignore abandonRequest; the request has completed already. */
            return RC_OK;
        case LDAPMessage__protocolOp_PR_unbindRequest:
            /* Fail unbindRequest so we close the connection. */
            return RC_FAIL;
        default:
            /* Fail any unknown requests to close the connection. */
            perror("_|_");
            return RC_FAIL;
        }
    }
    /* Send reply messages until blocked. */
    while ((msg = ldap_response_get(response)) && (status = ldap_connection_send(connection, msg)) == RC_OK)
        ldap_response_inc(response);
    return status;
}
