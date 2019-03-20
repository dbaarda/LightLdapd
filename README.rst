=================
LightLdapd README
=================

LightLdapd is a small and easy to manage LDAP server for small
home/classroom/school sized networks that can include thin clients. It
is designed to provide network wide users/groups/etc support to
supplement the excellent network dns/dhcp/tftp support provided by
dnsmasq.

It uses local PAM and NSS for authentication and to export the local
passwd/group/shadow/etc system databases. This means it has no special
separate ldap database to manage, and users/groups/etc can be managed
normally on the LightLdapd machine. No database setup or ldap
management tools are required, it just exports all the local
users/groups/etc. Client machines can then use libpam_ldapd and
libnss_ldapd to have all the same users/groups/etc as are on the
machine where LightLdapd is running.

The code is small, clean and efficient C, leveraging of existing
libraries as much as possible. It uses libev for an efficient event
loop. It uses asn1c to auto-generate the LDAP message
parsing/generating from the ASN.1 spec. It uses libpam for
authentication. It is small and efficient enough to run on a router or
NAS.

LightLdapd was forked from the excellent entente by Sergey Urbanovich
with his blessing. The choice to fork was made in order to leave
entente as simple as possible and avoid adding features needed for
LightLdapd. Improvements have and will be fed back into entente when
they don't increase its size.

The rest of this readme is not finished yet.

Contents
========

.. This should be a brief description of the contents of the
   distribution. It should include a list of important features in a
   table like this;

=============== ======================================================
Name       Description
=============== ======================================================
README.rst      This file.
DESIGN.rst      Details of the design.
DEVELOPMENT.rst Instructions for developers.
LICENSE         Copyright and Licencing details.
NEWS.rst        Summary of fixes and changes for each release.
TODO.rst        List of outstanding tasks and future plans.
ldap.asn1       The asn1 ldap protocol specification.
*.[ch]          The project source code.
=============== ======================================================

.. It wouldn't hurt to have a few paragraphs here suggesting were to
   look in the distribution for bits and pieces.


Install
=======

Dependencies
------------

* `asn1c <https://github.com/vlm/asn1c>`_
* `libev <http://software.schmorp.de/pkg/libev.html>`_
* `libpam <http://www.kernel.org/pub/linux/libs/pam/>`_


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
-l  Bind to the loopback interface only.
-p port  Set local port number (default: 389).
-d  Run as a daemon.
-r user  Set the bind user for 'root' access to shadowAccount data.


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

See DEVELOPMENT for development instructions.


----

http://github.com/dbaarda/LightLdapd
$Id: README,v 65b64de6b1e1 2014/01/20 02:32:20 abo $
