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
from ldaptor.protocols.ldap import distinguishedname

exampleCom = distinguishedname.DistinguishedName('dc=example,dc=com')

resource = main.getResource(
    identityBaseDN=exampleCom,

    serviceLocationOverride={ exampleCom: ('localhost', None),
                              },

    searchFields=[
    ('Name', '(|(cn=%(input)s)(uid=%(input)s)(mail=%(input)s))'),
    ('Phone', '(telephoneNumber=%(input)s)'),
    ],
    )

default.putChild('ldap', resource)
