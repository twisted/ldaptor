Changelog
=========
Ldaptor has a new version schema. As a first-party library we now follow Twisted's example.

Release 14.0
------------

**License**
    * Tommi changed Ldaptor's license to the MIT (Expat) license.
    * Replaced MD4 code with one using BSD 3-clause license.

**API Changes**
    * Ldaptor client and server: None
    * Everything having to do with webui and Nevow have been removed

**Testing**
    * Added Travis-CI.
    * Added test coverage, we're currently at around 75%.
    * Use Tox build matrix to handle pypy, py26, py27 and twisted version from 10.0 until 14.0
    * The above passes all existing unit tests, a few "ordering" bugs were fixed in the process.
    * Added pureldap.LDAPAbandonRequest and extra pureldap.LDAPExtendedRequest test

**Improved Documentation**
    * Added, updated and reworked documentation using Sphinx.
    * Stay tuned to: https://ldaptor.readthedocs.org/
    * Dia is required for convert diagrams to svg/png, this might change in the future.

**Bug fixes**
    * Fix startTLS support, in accordance to RFC2251
    * Fix for debug logging in ldapclient
    * Added support for abandon request
    * Replace string literal exceptions with real Exceptions
    * Fixes the invocation of dia for diagramm generation in a headless environment
    * Fixes #526522 ldaptor-ldap2passwd --help throws exception.
    * Fix unicode problem with add contact
    * Fixes a small bug in the LDAPExtendedRequest constructor was making the LDAPStartTLSRequest constructor fail
    * Added very basic, low-level support for SASL credentials in the pureldap module
    * Fix typo in module name: pureldap -> pureber.
    * Fix deprecated exception error
    * Handle additional records in DNS response
    * Fix dns import
    * Extend test driver send_multiResponse() to return deferred and throw errors
    * Reroute errback to deferred returned by search()
    * Make it possible to specify local address for LDAP client
    * Added stub for SearchResultReference
    * Use hashlib and built-in set() instead of deprecated modules


Prehistory
----------

All versions up to and including 0.0.43 didn't have a changelog.