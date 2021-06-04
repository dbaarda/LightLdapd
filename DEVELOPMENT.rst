======================
LightLdapd DEVELOPMENT
======================

This document is very preliminary.

See the DESIGN document for more detailed explanations behind some of
these procedures.

Testing
=======

To build lightldapd with debug output turned on use::

  make debug

When running lightldapd for tesing use::

  sudo ./lightldapd -l -a -r abo

When searching with ldapsearch, you should use::

  ldapsearch "uid=abo" -b "dc=lightldapd" -h localhost -v -x \
    -D "uid=abo,ou=people,dc=lightldapd" -W

Where the arguments provided are:

  -b DN  is the base DN to use.
  -h host  is the host to use.
  -v  is for verbose output.
  -x  is to use simple bind.
  -D DN  is the bind DN to use.
  -W  is to prompt for passwd.
  -ZZ  is to require tls.

Without ``-b`` it uses the default from ``/etc/ldap/ldap.conf``.

Without ``-D`` and ``-W`` it does an anonymous bind.

With ``-D ""`` it also does an anonymous bind.

With ``-ZZ`` it will start TLS first.

For testing without root against the minimal chroot use::

  fakechroot -- ./lightldapd -l -p 8389 -a -R chroot -N

And search with ldapsearch like this with the password "pass0001"::

  ldapsearch "cn=*" -b "dc=lightldapd" -h localhost -p 8389 -v -x \
    -D "uid=user0001,ou=people,dc=lightldapd" -W


Using TLS
---------

To use TLS you will need a cert+key and make sure that ldapsearch is
configured to trust it. You can create a self-signed cert using
openssl like this::

  openssl req -new -x509 -nodes -sha256 -days 1000 \
    -out lightldapd.crt -keyout lightldapd.key

Make sure that you set the "Common Name" to the fully qualified
hostname you will use. If you are using the loopback interface this
will be ``localhost.localnet``. Note you also must use this fully
qualified hostname for the ``-h`` argument to ldapsearch.

Next you will need to tell ldapsearch to trust this certificate,
otherwise it will fail mysteriously. This can be done temporarily by
setting an enviroment variable::

  export LDAPTLS_CACERT=lightldapd.crt

You can then run lightldapd with TLS support enabled::

  sudo ./lightldapd -l -a -r abo -C lightldapd.crt -K lightldapd.key

When searching with ldapsearch, you should use::

  ldapsearch "uid=abo" -b "dc=lightldapd" -h localhost.localnet -v -x -ZZ

To make this more permanent so you don't need to keep doing it you can
put the certs into the host's configuration. If you do this you
probably want to generate a cert using your actual hostname and stop
using the loopback interface::

  openssl req -new -x509 -nodes -sha256 -days 1000 \
    -out /etc/ssl/certs/lightldapd.crt \
    -keyout /etc/ssl/private/lightldapd.key
  sudo chown root:root /etc/ssl/certs/lightldapd.crt
  sudo chmod 644 /etc/ssl/certs/lightldapd.crt
  sudo chown root:ssl-cert /etc/ssl/certs/lightldapd.key
  sudo chmod 640 /etc/ssl/certs/lightldapd.key

On the client system, so you nolonger need to set LDAPTLS_CACERT for
ldapsearch to work, you edit ``/etc/ldap/ldap.conf`` to include::

  TLS_CACERT      /etc/ssl/certs/lightldapd.crt

Note your client system will need a copy of the public
``lightldapd.crt`` in the same ``/etc/ssl/certs/lightldapd.crt``
location if it is a different host.

You can then start lightldapd on the server to use these certs::

  sudo ./lightldapd -a -r abo -C /etc/ssl/certs/lightldapd.crt \
    -K /etc/ssl/private/lightldapd.key

If you use a proper certificate signed by a publicly recognised
certificate authority (like letsencrypt), you shouldn't need to copy
``lightldapd.crt`` to clients and change `/etc/ldap/ldap.conf``. Note
that you may also need to start lightldapd with the ``-A <ca-path>``
argument.

Coding Style
============

There is a ``make tidy`` target that will reformat code to comply with
the project's coding style. Always run ``make tidy`` to automatically
reformat your code before committing. This depends on tidyc being on
your path. The tidyc too (an extension/wrapper of GNU indent) can be
found here;

https://github.com/dbaarda/tidyc

The coding style used is ``tidyc -ppi0 -R -C -T '/ev_\w+/' -T
'/ldap_\w+/' *.[ch]`` which is equivalent to ``indent -linux -nut -i4
-ppi0 -l120 -lc80 -fc1 -sob -nhnl`` which is linux style with 4
character indents instead of tabs, a max code line length of 120, and
extra code line reformating. The tidyc tool does some additional
formatting with ``sed`` to workaround some ``indent`` quirks and do
additional comment formatting.

Always use typedef names instead of struct names when possible.

When defining structs prefer typdef with anonymous structs. If the
struct must have a name (for things like forward declaration), make
the struct name the same as the typedef name.

Type names should be named ``ldap_<class>`` for major ldap class
structs, or ``<type>_t`` for minor non-ldap specific types.

All method functions that operate on class structs should have a name
prefixed with the class name and take a pointer to the class type as
the first argument like ``ldap_<class>_<method>(ldap_<class> *<class>,
...)``.

All classes should have an initializer method that sets all the struct
fields like ``void ldap_<class>_init(ldap_<class> *<class>, ...);``

All ev_io watcher variables or struct fields should be named
``<event>_watcher``.

All ev_io callback methods or method pointers in structs should always
be named ``on_<event>()``.

Support for optional extensions like ``gnutls`` should be inside ``#ifdef
HAVE_GNUTLS`` blocks.

Use assert statements at the beginning of methods to verify all state
and data consistency invarients and preconditions like
``assert(&server->connection_watcher == watcher)`` and
``assert(ev_is_active(&server->connection_watcher)``.

Error Handling
==============

Wherever possible handle errors by cleaning up and closing the
connection, leaving the server running. If cleaning everything up is
very hard, it is better to exit the whole server than to leak.

For memory alloc failures, we immediately exit. Use the provided
XNEW, XNEW0, XSTRDUP, etc macros to do this.

----

http://github.com/dbaarda/LightLdapd
$Id: DEVELOPMENT,v 65b64de6b1e1 2014/01/20 02:32:20 abo $
