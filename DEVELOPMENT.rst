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

  ldapsearch "uid=abo" -b "dc=lightldapd" -h localhost -v -x -D "uid=abo,ou=people,dc=lightldapd" -W

Where the arguments provided are:

  -b DN  is the base DN to use.
  -h host  is the host to use.
  -v  is for verbose output.
  -x  is to use simple bind.
  -D DN  is the bind DN to use.
  -W  is to prompt for passwd.

Without ``-b`` it uses the default from ``/etc/ldap/ldap.conf``.

Without ``-D`` and ``-W`` it does an anonymous bind.

With ``-D ""`` it also does an anonymous bind.

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
