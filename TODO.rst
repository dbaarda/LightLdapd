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

* #8 Add tests.

  Currently there are no tests.

* #12 Add logging.

  Using syslog. Or using glib's logging?

* Extend search functionality.

  #1 Add support for substrings, greaterOrEqual, lessOrEqual, approxMatch
  searches.

* Make served users/groups configurable.

  #13 Support serving only some user/group ranges.

* Add support for other schemas.

  Add simple support for custom schemas, ideally enough to support
  windows auth for samba etc.

* Add support for write changes.

  Add enough write support to allow passwd changes from clients.

----

$Id: TODO,v 1.40 2004/10/18 02:30:53 abo Exp $
