#!/usr/bin/python

import os, errno
from distutils.core import setup
from distutils.command.build import build
from distutils.command.clean import clean
from distutils.command.install import install

if __name__=='__main__':
    setup(name="ldaptor",
	  description="Pure-Python library for LDAP",
	  long_description="""

Ldaptor is a pure-Python library that implements

- LDAP client logic.

- separately-accessible LDAP and BER protocol message
generation/parsing.

- ASCII-format LDAP filter generation and parsing.

- LDIF format data generation.

- Samba password changing logic.

Also included is a web-based user interface to search and edit
information in an LDAP directory and a set of LDAP utilities for use
from the command line.

""".strip(),
	  author="Tommi Virtanen",
	  author_email="tv@eagain.net",
	  #url="TODO",
	  license="MIT",

          cmdclass={'build': build,
                    'clean': clean,
                    'install': install,
                    },

	  packages=[
	"ldaptor",
	"ldaptor.protocols",
        "ldaptor.protocols.ldap",
        "ldaptor.protocols.ldap.autofill",
	"ldaptor.samba",
	"ldaptor.test",
	],
	  scripts=[
	"bin/ldaptor-ldap2dhcpconf",
	"bin/ldaptor-ldap2maradns",
	"bin/ldaptor-ldap2dnszones",
	"bin/ldaptor-search",
	"bin/ldaptor-namingcontexts",
	"bin/ldaptor-passwd",
	"bin/ldaptor-ldap2passwd",
	"bin/ldaptor-getfreenumber",
	"bin/ldaptor-ldap2pdns",
	"bin/ldaptor-find-server",
	"bin/ldaptor-rename",
	"bin/ldaptor-fetchschema",
        "bin/ldaptor-ldifdiff",
        "bin/ldaptor-ldifpatch",
        ])
