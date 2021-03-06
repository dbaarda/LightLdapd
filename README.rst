=================
LightLdapd README
=================

LightLdapd is a small and easy to manage LDAP server for small
home/classroom/school sized networks that can include thin clients. It
is designed to provide network wide users/groups/etc support to
supplement the excellent network dns/dhcp/tftp support provided by
dnsmasq.

It uses local PAM and NSS for authentication to export the local
passwd/group/shadow/etc system databases. This means it requires no special
separate ldap database to manage, and users/groups/etc can be managed normally
on the LightLdapd server machine. No special database setup or ldap management
tools are required, it just exports all the local users/groups/etc. Client
machines can then use libpam_ldapd and libnss_ldapd to have all the same
users/groups/etc as are on the machine where LightLdapd is running.

It can also run inside a minimal chroot environment, giving more isolation
from the host system, and explorting a completely different set of
users/groups possibly using a completely different PAM/NSS setup from inside
the chroot.

The code is small, clean and efficient C, leveraging of existing libraries as
much as possible. It uses libev for an efficient event loop. It uses asn1c to
auto-generate the LDAP message parsing/generating from the ASN.1 spec. It uses
libpam or crypt for authentication. It uses mbedtls for TLS support. It is
small and efficient enough to run on a router or NAS.

LightLdapd was forked from the excellent entente by Sergey Urbanovich
with his blessing. The choice to fork was made in order to leave
entente as simple as possible and avoid adding features needed for
LightLdapd. Improvements have and will be fed back into entente when
they don't increase its size.

Status
======

LightLdapd is now functional enough to be used for clients using
pam_ldap authentication and/or nss_ldap access to passwd, group, and
shadow data. It now has TLS support so it should be safe to use on
untrusted networks.

The TLS support is relatively new but complete. If TLS is enabled it will
require it be started for bind operations. This should prevent clients from
accidentally using it insecurely on an untrusted network.

It does not yet have any logging, which can make it hard to figure out
what is wrong when something is not working.

See the github issue tracker for the most up to date status on what
is/isn't working.

Contents
========

.. This should be a brief description of the contents of the
   distribution. It should include a list of important features in a
   table like this;

==================== ======================================================
Name                 Description
==================== ======================================================
`<README.rst>`_      This file.
`<DESIGN.rst>`_      Details of the design.
`<DEVELOPMENT.rst>`_ Instructions for developers.
`<LICENSE>`_         Copyright and Licencing details.
`<NEWS.rst>`_        Summary of fixes and changes for each release.
`<TODO.rst>`_        List of outstanding tasks and future plans.
`<ldap.asn1>`_       The asn1 ldap protocol specification.
`*.[ch]`             The project source code.
`<chroot/>`_         Minimal chroot for testing.
==================== ======================================================

.. It wouldn't hurt to have a few paragraphs here suggesting were to
   look in the distribution for bits and pieces.


Install
=======

Dependencies
------------

* `asn1c <https://github.com/vlm/asn1c>`_ - `apt-get install asn1c`
* `libev <http://software.schmorp.de/pkg/libev.html>`_ - `apt-get install libev-dev`
* `libpam <http://www.kernel.org/pub/linux/libs/pam/>`_ - `apt-get install libpam-dev`
* `mbedtls <https://tls.mbed.org/>`_ - `apt-get install libmbedtls-dev`

Build
-----

To compile and install::

    make
    make install

Or (for building debian package)::

    make debian

Usage
=====

.. Simple Instructions for usage after installing. May include a
   reference to man pages or documentation in doc/, or USAGE

::

    lightldapd [options]

Or::

    /etc/init.d/lightldapd start
    # config file: /etc/default/lightldapd

Options
-------

-a  Allow anonymous access.
-b basedn  Set the basedn for the ldap server (default: "dc=lightldapd").
-r rootuser  Bind user for 'root' access to shadow data (default: "root").
-l  Bind to the loopback interface only.
-p port  Set local port number (default: 389).
-d  Run as a daemon.
-u runuser  Optional user to run as after dropping root privileges.
-R chroot  Optional path to chroot() into.
-C crtpath  Optional path to an ssl cert to use for TLS.
-A ca-path  Optional path to a ca-chain to use for TLS.
-K keypath  Optional path to a private key to use for TLS.
-U uids  Optional comma-separated list of uids or uid-ranges to export
  (default: "1000-29999").
-G gids  Optional comma-separated list of gids or gid-ranges to export
  (default: "100,1000-29999").
-N  Use NSS and crypt for authenticating instead of PAM.
-L loglevel  Optional syslog logging level 1-7, larger means more logging
  (default: 4).

Note lightldapd must run as root to open the default ldap serving
port, but using ``-u runuser`` it will use setuid() to drop root
privileges after starting. However, this also usually means it cannot
access nss shadow data so will not serve shadowAccount data. Clients
using pam_ldap for authentication don't need to access shadow data
anyway, and it is more secure to not export it.

However, if you want clients to use normal pam_unix authentication and
read shadow data using nss_ldap, then the runuser needs to be
privilged enough to read nss shadow data on the server. If the server
is using nss_unix, this is often done by adding the runuser to a
``shadow`` group that has read access to ``/etc/shadow``. You need to
also configure nss_ldap on the client machines to bind as the rootuser
with the ``rootbinddn`` setting so root (and only root)on the clients
can read shadow data.

Using ``-R chroot`` means lightldapd can be run in a chroot isolated from the
host system with a completely different NSS/PAM setup and users. The chroot
must include everything to configure NSS and PAM correctly, including all the
required PAM modules and libraries. The runuser, and cert paths are resolved
and read before switching to the chroot, so must exist on the host system.
Logging with syslog is initialized before switching to the chroot so it will
log to the host system and doesn't need anything configured in the chroot. The
runuser should also exist in the chroot with the same uid, and must have
permissions configured correctly for access to shadow data. The rootuser is
resolved after switching to the chroot, so only needs to exist in the chroot
environment.

Using ``-N`` means authentication is done using NSS and crypt against the the
shadow passwords instead of using PAM. This requires that the runuser have
read access to NSS shadow data. This is particularly useful for running in a
chroot, as it means the chroot doesn't need any pam modules installed, and
only requires a minimal nss setup with resolv.conf and passwd/group/shadow
files.

To enable TLS support you specify a cert file with the ``-C`` option, and
optionally a certificate authority chain file with the ``-A`` argument and/or
a separate private key file with the ``-K`` argument. If you don't use the
``-K`` option, the cert file must be a ``*.pem`` file containing both the cert
and private key. The file contining the private key must be readable by the
user lightldapd is started as, but doesn't have to be readable by the ``-u
runuser`` user. Typically it is set readable only by root. It is important to
configure your clients to use TLS and trust the cert used. If you are using
self-signed certs this typically means giving them a copy of the public cert.

To only expose a subset of your local uids or gids over ldap, use the `-U` and
`-G` options, setting them to a comma-separated list of ids or id-ranges to
include. The defaults are `-U 1000-29999` and `-G 100,1000-29999`. This
ensures that system users and groups are not exported, as clients typically
define their own system users and groups in their own /etc/passwd and
/etc/group configs. Note that authentication for bind is done against the host
(or chroot) system's users and is not limited to the `-U` exported uid ranges.
This means it is possible to bind as a user not exported by the LDAP server.
This means you can make the rootuser a special system user (uid < 1000) while
only exporting normal users (uid >= 1000).

Example usage with lighttpd
---------------------------

lighttpd.conf::

    server.modules += ( "mod_rewrite" )

    auth.backend = "ldap"
    auth.backend.ldap.hostname = "localhost"
    auth.backend.ldap.filter   = "(user=$)"

    auth.require = (
        "/tratata" => (
            "method"  => "basic",
            "realm"   => "lightldapd",
            "require" => "user=kiki|user=ooki"
        ),
    )



Support
=======

.. This should list all the user-level contact points for support,
   including mailing lists, discussion forums, online documentation,
   trackers, etc. It should also include instructions or pointers to
   instructions on procedures and conventions when using them.

Documentation
-------------

http://github.com/dbaarda/LightLdapd
  The project homepage.

http://minkirri.apana.org.au/wiki/LightLdapd
  An early brainstorming wiki before the github project was created.

Discussion
----------

.. Provide links to any IRC channels, mailing lists or online
   discussion forums, giving any necissary subscription information
   etc.

Reporting Problems
------------------

.. This should describe the procedure for users to report bugs,
   providing any useful links.

File any problems/bugs/suggestions/questions on the github issue
tracker.

Development
===========

See `<DEVELOPMENT.rst>`_ for development instructions including debugging.

See `<DESIGN.rst>`_ for general design philosophy and ideas.

----

http://github.com/dbaarda/LightLdapd
$Id: README,v 65b64de6b1e1 2014/01/20 02:32:20 abo $
