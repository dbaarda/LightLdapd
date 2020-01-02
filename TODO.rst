===============
LightLdapd TODO
===============

This is a list of outstanding TODO items in aproximate order of most important
first. Feel free to add things to this list. Please ensure that user visible
things are moved from here to the NEWS file when they get done.

Items
=====

* #8 Add tests.

  Currently there are no tests.

* #12 Add logging.

  Using syslog. Or using glib's logging?

* #1 Extend search functionality.

  Add support for substrings, greaterOrEqual, lessOrEqual, approxMatch
  searches.

* #14 Add support for a RootDSE.

  This gives clients the ability to discover supported functionality. See
  https://ldapwiki.com/wiki/RootDSE for details.

* #7 Make debian package create a lightldap user.

  It should create a lightldapd user and run lightldapd with '-u lightldapd'
  instead of running as root. Maybe also optionally set a password for
  lightldapd, add lightldapd to group shadow, and run it with '-r lightldapd'
  to optionally support exporting shadow.

* #5 Add support for other request types.

  Add enough write support to allow passwd changes from clients.

* #15 Add support for other schemas.

  Add simple support for custom schemas, ideally enough to support windows
  auth for samba etc.


----

$Id: TODO,v 1.40 2004/10/18 02:30:53 abo Exp $
