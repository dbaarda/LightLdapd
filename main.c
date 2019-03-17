/*=
 * Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 * Based on entente Copyright (c) 2010, 2011 Sergey Urbanovich
 *
 * Licensed under the MIT License. See LICENSE file for details.
 */

#include "utils.h"
#include <unistd.h>
#include <netinet/in.h>
#define EV_COMPAT3 0            /* Use the ev 4.X API. */
#include <ev.h>
#include "pam.h"
#include "nss2ldap.h"

#define LISTENQ 128

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
    char *basedn;
    int anonymous;
    ev_loop *loop;
    ev_io connection_watcher;
} ldap_server;
void ldap_server_init(ldap_server *server, ev_loop *loop, char *basedn, int anonymous);
int ldap_server_start(ldap_server *server, uint32_t addr, int port);
void ldap_server_stop(ldap_server *server);

/* Reuse the ber_decode return value enum as the ldap recv/send status. */
typedef enum asn_dec_rval_code_e ldap_status_t;

typedef struct {
    ldap_server *server;
    ev_io read_watcher;
    ev_io write_watcher;
    ev_timer delay_watcher;
    LDAPMessage_t *request;
    ldap_status_t request_status;
    LDAPMessage_t *response;
    ldap_status_t response_status;
    int response_stage;
    buffer_t recv_buf;
    buffer_t send_buf;
} ldap_connection;
ldap_connection *ldap_connection_new(ldap_server *server, int fd);
void ldap_connection_free(ldap_connection *connection);
void ldap_connection_respond(ldap_connection *connection);
ldap_status_t ldap_connection_send(ldap_connection *connection, LDAPMessage_t *msg);
ldap_status_t ldap_connection_recv(ldap_connection *connection, LDAPMessage_t **msg);

void accept_cb(ev_loop *loop, ev_io *watcher, int revents);
void read_cb(ev_loop *loop, ev_io *watcher, int revents);
void write_cb(ev_loop *loop, ev_io *watcher, int revents);
void delay_cb(EV_P_ ev_timer *w, int revents);

void ldap_request_init(ldap_connection *connection);
void ldap_request_done(ldap_connection *connection);
ldap_status_t ldap_request_reply(ldap_connection *connection, LDAPMessage_t *req);
ldap_status_t ldap_request_bind(ldap_connection *connection, int msgid, BindRequest_t *req);
ldap_status_t ldap_request_search(ldap_connection *connection, int msgid, SearchRequest_t *req);

char *setting_basedn = "dc=lightldapd";
int setting_port = 389;
int setting_daemon = 0;
int setting_loopback = 0;
int setting_anonymous = 0;
void settings(int argc, char **argv);

int main(int argc, char **argv)
{
    ev_loop *loop = EV_DEFAULT;
    ldap_server server;
    uint32_t server_addr;

    settings(argc, argv);
    server_addr = setting_loopback ? INADDR_LOOPBACK : INADDR_ANY;
    if (setting_daemon && daemon(0, 0))
        fail1("daemon", 1);
    ldap_server_init(&server, loop, setting_basedn, setting_anonymous);
    if (ldap_server_start(&server, server_addr, setting_port) < 0)
        fail1("ldap_server_start", 1);
    ev_run(loop, 0);
    return 0;
}

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

void ldap_server_init(ldap_server *server, ev_loop *loop, char *basedn, int anonymous)
{
    server->basedn = basedn;
    server->anonymous = anonymous;
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
    ev_io_init(&connection->read_watcher, read_cb, fd, EV_READ);
    connection->read_watcher.data = connection;
    ev_io_init(&connection->write_watcher, write_cb, fd, EV_WRITE);
    connection->write_watcher.data = connection;
    ev_init(&connection->delay_watcher, delay_cb);
    connection->delay_watcher.data = connection;
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
    LDAPMessage_t **req = &connection->request;

    /* Recieve and reply to requests until blocked on recv or reply. */
    do {
        if (connection->response_status == RC_OK) {
            ldap_request_done(connection);
            ldap_request_init(connection);
        }
        if (connection->request_status == RC_WMORE)
            connection->request_status = ldap_connection_recv(connection, req);
        if (connection->request_status == RC_OK)
            connection->response_status = ldap_request_reply(connection, *req);
    } while (connection->response_status == RC_OK);
    if (connection->request_status == RC_FAIL) {
        ldap_connection_free(connection);
        return;
    }
    if (buffer_full(&connection->recv_buf)) {
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
    ldap_connection *connection = watcher->data;

    assert(connection->server->loop == loop);
    assert(&connection->delay_watcher == watcher);

    ldap_connection_respond(connection);
}

void ldap_request_init(ldap_connection *connection)
{
    connection->request = NULL;
    connection->request_status = RC_WMORE;
    connection->response = NULL;
    connection->response_status = RC_WMORE;
    connection->response_stage = 0;
}

void ldap_request_done(ldap_connection *connection)
{
    ldapmessage_free(connection->request);
    ldapmessage_free(connection->response);
}

ldap_status_t ldap_request_reply(ldap_connection *connection, LDAPMessage_t *req)
{
    switch (req->protocolOp.present) {
    case LDAPMessage__protocolOp_PR_bindRequest:
        return ldap_request_bind(connection, req->messageID, &req->protocolOp.choice.bindRequest);
    case LDAPMessage__protocolOp_PR_searchRequest:
        return ldap_request_search(connection, req->messageID, &req->protocolOp.choice.searchRequest);
    case LDAPMessage__protocolOp_PR_unbindRequest:
        return RC_FAIL;
    default:
        perror("_|_");
        return RC_FAIL;
    }
}

ldap_status_t ldap_request_bind(ldap_connection *connection, int msgid, BindRequest_t *req)
{
    ldap_server *server = connection->server;
    LDAPMessage_t *res = connection->response;
    ev_tstamp delay = 0.0;

    /* If the delay is active, do nothing and return RC_WMORE to try again. */
    if (ev_is_active(&connection->delay_watcher))
        return RC_WMORE;
    /* If we have already built the response, just try to send it. */
    if (res)
        return ldap_connection_send(connection, res);
    /* Otherwise construct the response first. */
    res = connection->response = XNEW0(LDAPMessage_t, 1);
    res->messageID = msgid;
    res->protocolOp.present = LDAPMessage__protocolOp_PR_bindResponse;
    BindResponse_t *bindResponse = &res->protocolOp.choice.bindResponse;
    LDAPString_set(&bindResponse->matchedDN, (const char *)req->name.buf);
    if (server->anonymous && req->name.size == 0) {
        /* allow anonymous */
        bindResponse->resultCode = BindResponse__resultCode_success;
    } else if (req->authentication.present == AuthenticationChoice_PR_simple) {
        /* simple auth */
        char user[PWNAME_MAX];
        char *pw = (char *)req->authentication.choice.simple.buf;
        char status[PAMMSG_LEN] = "";
        if (!dn2name(server->basedn, (const char *)req->name.buf, user)) {
            bindResponse->resultCode = BindResponse__resultCode_invalidDNSyntax;
        } else if (PAM_SUCCESS != auth_pam(user, pw, status, &delay)) {
            bindResponse->resultCode = BindResponse__resultCode_invalidCredentials;
            LDAPString_set(&bindResponse->diagnosticMessage, status);
        } else {                /* Success! */
            bindResponse->resultCode = BindResponse__resultCode_success;
        }
    } else {
        /* sasl or anonymous auth */
        bindResponse->resultCode = BindResponse__resultCode_authMethodNotSupported;
    }
    /* If delay was set, pause response by starting delay watcher. */
    if (delay > 0.0) {
        ev_timer_set(&connection->delay_watcher, delay, 0.0);
        ev_timer_start(server->loop, &connection->delay_watcher);
        return RC_WMORE;
    }
    return ldap_connection_send(connection, res);
}

ldap_status_t ldap_request_search(ldap_connection *connection, int msgid, SearchRequest_t *req)
{
    ldap_server *server = connection->server;
    LDAPMessage_t *res = connection->response;
    ldap_status_t status = RC_WMORE;
    /* Check that it's a valid search request. */
    AttributeValueAssertion_t *attr = &req->filter.choice.equalityMatch;
    const int bad_dn = strcmp((const char *)req->baseObject.buf, server->basedn)
        && strcmp((const char *)req->baseObject.buf, "");
    const int bad_filter = req->filter.present != Filter_PR_equalityMatch
        || strcmp((const char *)attr->attributeDesc.buf, "uid");
    const char *user = (char *)attr->assertionValue.buf;

    if (connection->response_stage == 0) {
        /* Allocate the response. */
        res = connection->response = XNEW0(LDAPMessage_t, 1);
        status = RC_OK;
    }
    do {
        /* If we need to, create a new response. */
        if (status == RC_OK) {
            /* Empty and wipe the response message. */
            ldapmessage_empty(res);
            memset(res, 0, sizeof(*res));
            res->messageID = msgid;
            res->protocolOp.present = LDAPMessage__protocolOp_PR_searchResEntry;
            SearchResultEntry_t *searchResEntry = &res->protocolOp.choice.searchResEntry;
            if (connection->response_stage == 0 && !bad_dn && !bad_filter
                && getpwnam2ldap(searchResEntry, server->basedn, user) != -1) {
                /* If the request is good and we found an entry, send it. */
                connection->response_stage = 1;
            } else {
                /* Otherwise construct a SearchResultDone. */
                res->protocolOp.present = LDAPMessage__protocolOp_PR_searchResDone;
                SearchResultDone_t *searchResDone = &res->protocolOp.choice.searchResDone;
                if (bad_dn) {
                    searchResDone->resultCode = LDAPResult__resultCode_other;
                    LDAPString_set(&searchResDone->diagnosticMessage, "baseobject is invalid");
                } else if (bad_filter) {
                    searchResDone->resultCode = LDAPResult__resultCode_other;
                    LDAPString_set(&searchResDone->diagnosticMessage, "filter not supported");
                } else {
                    searchResDone->resultCode = LDAPResult__resultCode_success;
                    LDAPString_set(&searchResDone->matchedDN, server->basedn);
                }
                connection->response_stage = 2;
            }
        }
        status = ldap_connection_send(connection, res);
    } while (status == RC_OK && connection->response_stage < 2);
    return status;
}

void settings(int argc, char **argv)
{
    int c;

    while ((c = getopt(argc, argv, "ab:dlp:")) != -1) {
        switch (c) {
        case 'a':
            setting_anonymous = 1;
            break;
        case 'b':
            setting_basedn = optarg;
            break;
        case 'd':
            setting_daemon = 1;
            break;
        case 'l':
            setting_loopback = 1;
            break;
        case 'p':
            setting_port = atoi(optarg);
            break;
        default:
            fprintf(stderr, "Usage: %s [-a] [-b dc=lightldapd] [-l] [-p 389] [-d]\n", argv[0]);
            exit(1);
        }
    }
}
