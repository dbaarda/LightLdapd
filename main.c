/*=
 * Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 * Based on entente Copyright (c) 2010, 2011 Sergey Urbanovich
 *
 * Licensed under the MIT License. See LICENSE file for details.
 */

#include "utils.h"
#include "ldap_server.h"
#include <unistd.h>

char *setting_basedn = "dc=lightldapd";
int setting_port = 389;
int setting_daemon = 0;
int setting_loopback = 0;
uid_t setting_rootuid = 0;
uid_t setting_setuid = 0;
bool setting_anonymous = 0;
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
    ldap_server_init(&server, loop, setting_basedn, setting_rootuid, setting_anonymous);
    if (ldap_server_start(&server, server_addr, setting_port) < 0)
        fail1("ldap_server_start", 1);
    if (setting_setuid && setuid(setting_setuid))
        fail1("setuid", 1);
    ev_run(loop, 0);
    return 0;
}

void settings(int argc, char **argv)
{
    int c;

    while ((c = getopt(argc, argv, "ab:dlp:r:u:")) != -1) {
        switch (c) {
        case 'a':
            setting_anonymous = true;
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
        case 'r':
            setting_rootuid = name2uid(optarg);
            break;
        case 'u':
            setting_setuid = name2uid(optarg);
            break;
        default:
            fprintf(stderr, "Usage: %s [-a] [-b dc=lightldapd] [-l] [-p 389] [-d] [-r root] [-u user]\n", argv[0]);
            exit(1);
        }
    }
}
