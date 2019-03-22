===============
LightLdapd TODO
===============

This is a list of outstanding TODO items in aproximate order of most
important first. Feel free to add things to this list. Please ensure
that user visible things are moved from here to the NEWS file when
they get done.

Items
=====

* Change license from MIT to GPL?

  Would prefer to require contributions to come back rather than spawn private
  forks. I have confirmed with the entente author this is OK.

* #9,#10 Improve design.

  Restructure using ldap_server, ldap_connection, ldap_request
  structs, copying the design of https://github.com/taf2/libebb.

* #8 Add tests.

  Currently there are no tests.

* #12 Add logging.

  Using syslog. Or using glib's logging?

* #4 Add StartTLS support.

  Probably using mbedtls.

* #2 Optimize Search.

  Add Filter_scope() analysis to figure out what the search is
  constrained to instead of scanning everything.

  Add caching of scanned nss data.

* Extend search functionality.

  #1 Add support for substrings, greaterOrEqual, lessOrEqual, approxMatch
  searches.

  #3 Add support for typesOnly and attribute selection.

----

$Id: TODO,v 1.40 2004/10/18 02:30:53 abo Exp $
