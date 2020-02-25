Changelog
=========

Release.next
-------------------------

Features
^^^^^^^^

Changes
^^^^^^^

Bugfixes
^^^^^^^^

- SASL Bind without credentials caused list index out of range. Issue #157, Fixed
- return an LDAPSearchResultEntry even if all attributes are filtered. Issue #166, Fixed




Release 19.1 (2019-09-09)
-------------------------

Features
^^^^^^^^

- Basic implementation of ``ldaptor.protocols.pureldap.LDAPSearchResultReference``.
- Explicit ``ldaptor.protocols.ldap.ldaperrors`` classes declaration was made
  to allow syntax highlighting for this module.
- Example of using LDAP server with the database. Employees are store in the database table and retrieved
  on server initialization.

Changes
^^^^^^^

- ``ldaptor.protocols.pureldap.LDAPPasswordModifyRequest`` string representation now contains
  ``userIdentity``, ``oldPasswd`` and ``newPasswd`` attributes. Password attributes are represented as asterisks.
- ``ldaptor.protocols.pureldap.LDAPBindRequest`` string representation is now using asterisks to represent
  ``auth`` attribute.

Bugfixes
^^^^^^^^

- ``DeprecationWarning`` stacklevel was set to mark the caller of the deprecated
  methods of the ``ldaptor._encoder`` classes.
- ``NotImplementedError`` for ``ldaptor.protocols.pureldap.LDAPSearchResultReference`` was fixed.
- Regression bug with ``LDAPException`` instances was fixed (``ldaptor.protocols.ldap.ldapclient``
  exceptions failed to get their string representations).
- StartTLS regression bug was fixed: ``ldaptor.protocols.pureldap.LDAPStartTLSRequest.oid`` and
  ``ldaptor.protocols.pureldap.LDAPStartTLSResponse.oid`` must be of bytes type.
- ``ldaptor.protocols.pureldap`` and ``ldaptor.protocols.pureber`` string representations were fixed:
  `LDAPResult(resultCode=0, matchedDN='uid=user')` instead of `LDAPResult(resultCode=0, matchedDN="b'uid=user'")`.
- ``ldaptor.protocols.pureldap.LDAPMatchingRuleAssertion`` initialization for Python 3 was failed for bytes arguments.
- ``ldaptor.protocols.pureldap.LDAPExtendedResponse`` custom tag parameter was not used.
- ``ldaptor._encoder.to_bytes()`` was fixed under Python 3 to return integers as their numeric
  representation rather than a sequence of null bytes.

Release 19.0 (2019-03-05)
-------------------------

Features
^^^^^^^^

- Ability to logically compare ldaptor.protocols.pureldap.LDAPFilter_and and ldaptor.protocols.pureldap.LDAPFilter_or objects with ==.
- Ability to customize ldaptor.protocols.pureldap.LDAPFilter_* object's encoding of values when using asText.
- New client recipe- adding an entry to the DIT.
- Ability to use paged search control for LDAP clients.
- New client recipie- using the paged search control.

Changes
^^^^^^^

- Using modern classmethod decorator instead of old-style method call.
- Usage of zope.interfaces was updated in preparation for python3 port.
- ``toWire`` method is used to get bytes representation of `ldaptor` classes
  instead of ``__str__`` which is deprecated now.
- Code was updated to pass `python3 -m compileall` in preparation for py3 port.
- Code is linted under python 3  in preparation for py3 port.
- Continuous test are executed only against latest related Twisted and latest
  Twisted trunk branch.
- The local development environment was updated to produce overall and diff
  coverage reports in HTML format.
- `six` package is now a direct dependency in preparation for the Python 3
  port, and has replaced the ldaptor.compat module.
- Remove Python 3.3 from tox as it is EOL.
- Add API documentation for ``LDAPAttributeSet`` and ``startTLS``.
- Quick start and cookbook examples were moved to separate files and
  made agnostic to the Python version.
- dependency on pyCrypto replaced with pure python passlib.
- replace direct dependency on pyOpenSSL with Twisted[tls]

Bugfixes
^^^^^^^^

- DN matching is now case insensitive.
- Proxies now terminate the connection to the proxied server in case a client immediately closes the connection.
- asText() implemented for LDAPFilter_extensibleMatch
- Children of ``ldaptor.inmemory.ReadOnlyInMemoryLDAPEntry`` subclass instances are added as the same class instances.
- Redundant attributes keys sorting was removed from ``ldaptor.entry.BaseLDAPEntry`` methods.

Release 16.0 (2016-06-07)
-------------------------

Features
^^^^^^^^

- Make meta data introspectable
- Added `proxybase.py`, an LDAP proxy that is easier to hook into.
- When parsing LDAPControls, criticality may not exist while controlValue still does
- Requested attributes can also be passed as '*' symbol
- Numerous small bug fixes.
- Additional documentation
- Updated Travis-CI, Tox and other bits for better coverage.

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
