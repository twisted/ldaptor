# -*- python -*-

"""
If you are using moshez's experimental twisted-web Debian package,
try copying this file as

	/etc/twisted-web/local.d/ldaptor.py

editing to suite (the example assumes your LDAP server is running on
localhost, and serves the DN dc=example,dc=com), and browsing

	http://localhost/ldap/

"""

from ldaptor.apps.webui import main

resource = main.getResource()

default.putChild('ldap', resource)
