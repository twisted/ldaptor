Changelog
=========

Release 14.1 (UNRELEASED)
-------------------------

Features
^^^^^^^^

- Make meta data introspectable
- Added `proxybase.py`, an LDAP proxy that is easier to hook into.


Release 14.0 (2014-10-31)
-------------------------

Ldaptor has a new version schema. As a first-party library we now follow Twisted's example.

License
^^^^^^^

- Ldaptor's original author `Tommi Virtanen <https://github.com/tv42>`_ changed the license to the MIT (Expat) license.
- ldaptor.md4 has been replaced by a 3-clause BSD version.

API Changes
^^^^^^^^^^^

- Ldaptor client and server: None
- Everything having to do with webui and Nevow have been *removed*.

Features
^^^^^^^^

- `Travis CI <https://travis-ci.org/twisted/ldaptor/>`_ is now used for continuous integration.
- Test coverage is now measured. We're currently at around 75%.
- tox is used now to test ldaptor on all combinations of pypy, Python 2.6, Python 2.7 and Twisted versions from 10.0 until 14.0.
- A few ordering bugs that were exposed by that and are fixed now.
- ldaptor.protocols.pureldap.LDAPExtendedRequest now has additional tests.
- The new ldaptor.protocols.pureldap.LDAPAbandonRequest adds support for abandoning requests.
- ldaptor.protocols.pureldap.LDAPBindRequest has basic SASL support now.
  Higher-level APIs like ldapclient don't expose it yet though.

Bugfixes
^^^^^^^^

- ldaptor.protocols.ldap.ldapclient's now uses log.msg for it's debug listing instead of the non-Twisted log.debug.
- String literal exceptions have been replaced by real Exceptions.
- "bin/ldaptor-ldap2passwd --help" now does not throws an exception anymore (`debian bug #526522 <https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=526522>`_).
- ldaptor.delta.Modification and ldaptor.protocols.ldap.ldapsyntax.PasswordSetAggregateError that are used for adding contacts now handle unicode arguments properly.
- ldaptor.protocols.pureldap.LDAPExtendedRequest's constructor now handles STARTTLS in accordance to `RFC2251 <http://tools.ietf.org/html/rfc2251>`_ so the constructor of ldaptor.protocols.pureldap.LDAPStartTLSRequest doesn't fail anymore.
- ldaptor.protocols.ldap.ldapserver.BaseLDAPServer now uses the correct exception module in dataReceived.
- ldaptor.protocols.ldap.ldaperrors.LDAPException: "Fix deprecated exception error"
- bin/ldaptor-find-server now imports dns from the correct twisted modules.
- bin/ldaptor-find-server now only prints SRV records.
- ldaptor.protocols.ldap.ldapsyntax.LDAPEntryWithClient now correctly propagates errors on search().
  The test suite has been adapted appropriately.
- ldaptor.protocols.ldap.ldapconnector.LDAPConnector now supports specifying a local address when connecting to a server.
- The new ldaptor.protocols.pureldap.LDAPSearchResultReference now prevents ldaptor from choking on results containing SearchResultReference (usually from Active Directory servers).
  It is currently only a stub and silently ignored.
- hashlib and built-in set() are now used instead of deprecated modules.

Improved Documentation
^^^^^^^^^^^^^^^^^^^^^^

- Added, updated and reworked documentation using Sphinx.
  `Dia <https://wiki.gnome.org/Apps/Dia/>`_ is required for converting diagrams to svg/png, this might change in the future.
- Dia is now invoked correctly for diagram generation in a headless environment.
- The documentation is now hosted on https://ldaptor.readthedocs.org/.

Prehistory
----------

All versions up to and including 0.0.43 didn't have a changelog.
