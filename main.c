/*=
 * Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 * Based on entente Copyright (c) 2010, 2011 Sergey Urbanovich
 *
 * Licensed under the GPLv3 License. See LICENSE file for details.
 */

#include "utils.h"
#include "ldap_server.h"
#include "ranges.h"
#include "pam.h"
#include <unistd.h>
#include <syslog.h>

char *setting_port = "389";
bool setting_loopback = 0;
bool setting_authnss = 0;
bool setting_daemon = 0;
uid_t setting_setuid = 0;
char *setting_chroot = NULL;
char *setting_basedn = "dc=lightldapd";
char *setting_rootuser = "root";
bool setting_anonok = 0;
char *setting_crtpath = NULL;
char *setting_caspath = NULL;
char *setting_keypath = NULL;
char *setting_uids = "1000-29999";
char *setting_gids = "100,1000-29999";
void settings(int argc, char **argv);

int main(int argc, char **argv)
{
    ev_loop *loop = EV_DEFAULT;
    mbedtls_net_context socket;
    ldap_server server;
    char *server_addr;
    ldap_ranges uids, gids;

    settings(argc, argv);
    server_addr = setting_loopback ? "127.0.0.1" : NULL;
    if (!ldap_ranges_init(&uids, setting_uids))
        errx(EX_USAGE, "Invalid -U value: \"%s\"", setting_uids);
    if (!ldap_ranges_init(&gids, setting_gids))
        errx(EX_USAGE, "Invalid -G value: \"%s\"", setting_gids);
    if (setting_daemon && daemon(0, 0))
        fail1("daemon", 1);
    openlog("lightldapd", LOG_PID | LOG_CONS | LOG_PERROR | LOG_NDELAY, LOG_DAEMON);
    syslog(LOG_NOTICE, "lightldapd starting");
    if (mbedtls_net_bind(&socket, server_addr, setting_port, MBEDTLS_NET_PROTO_TCP))
        fail1("mbdedtls_net_bind", 1);
    if (ldap_server_init
        (&server, loop, setting_basedn, setting_rootuser, setting_anonok, setting_crtpath, setting_caspath,
         setting_keypath, &uids, &gids))
        fail1("ldap_server_init", 1);
    if (setting_chroot && (chroot(setting_chroot) || chdir("/")))
        fail1("chroot", 1);
    if (setting_setuid && setuid(setting_setuid))
        fail1("setuid", 1);
    if (setting_authnss)
        auth_user = auth_nss;
    ldap_server_start(&server, socket);
    ev_run(loop, 0);
    syslog(LOG_NOTICE, "lightldapd stopping");
    return 0;
}

void settings(int argc, char **argv)
{
    int c;

    while ((c = getopt(argc, argv, "ab:dlp:r:u:A:C:G:K:NR:U:")) != -1) {
        switch (c) {
        case 'a':
            setting_anonok = true;
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
            setting_port = optarg;
            break;
        case 'r':
            setting_rootuser = optarg;
            break;
        case 'u':
            setting_setuid = name2uid(optarg);
            break;
        case 'A':
            setting_caspath = optarg;
            break;
        case 'C':
            setting_crtpath = optarg;
            break;
        case 'G':
            setting_gids = optarg;
            break;
        case 'K':
            setting_keypath = optarg;
            break;
        case 'N':
            setting_authnss = 1;
            break;
        case 'R':
            setting_chroot = optarg;
            break;
        case 'U':
            setting_uids = optarg;
            break;
        default:
            fprintf(stderr,
                    "Usage: %s [-a] [-b dc=lightldapd] [-r rootuser] [-l] [-p 389] [-d] \\\n"
                    "  [-u runuser] [-R chroot] [-C crtfile] [-A ca-file] [-K keyfile] \\\n"
                    "  [-U 1000-29999,...] [-G 100,1000-29999,...] [-N]", argv[0]);
            exit(1);
        }
    }
}
