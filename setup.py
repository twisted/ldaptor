#!/usr/bin/python

import os
from distutils.core import setup, Extension
from distutils import sysconfig

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
	  author_email="tv@debian.org",
	  #url="TODO",
	  license="GNU LGPL",

	  packages=[
	"ldaptor",
	"ldaptor.protocols",
        "ldaptor.protocols.ldap",
	"ldaptor.samba",
	"ldaptor.apps",
	"ldaptor.apps.webui",
	],
	  scripts=[
	"bin/ldaptor-webui",
	"bin/ldaptor-ldap2dhcpconf",
	"bin/ldaptor-ldap2maradns",
	"bin/ldaptor-search",
	"bin/ldaptor-namingcontexts",
	"bin/ldaptor-passwd",
	"bin/ldaptor-ldap2passwd",
	"bin/ldaptor-getfreenumber",
	"bin/ldaptor-ldap2pdns",
	"bin/ldaptor-find-server",
	"bin/ldaptor-rename",
	"bin/ldaptor-fetchschema",
	],
          data_files=[
        (os.path.join(sysconfig.get_python_lib(), 'ldaptor/apps/webui'),
         [
        'ldaptor/apps/webui/add-really.xhtml',
        'ldaptor/apps/webui/add.xhtml',
        'ldaptor/apps/webui/basedn.xhtml',
        'ldaptor/apps/webui/change_password.xhtml',
        'ldaptor/apps/webui/delete-done.xhtml',
        'ldaptor/apps/webui/delete-nodn.xhtml',
        'ldaptor/apps/webui/delete.xhtml',
        'ldaptor/apps/webui/edit-really.xhtml',
        'ldaptor/apps/webui/edit.xhtml',
        'ldaptor/apps/webui/login.xhtml',
        'ldaptor/apps/webui/mass_change_password-really.xhtml',
        'ldaptor/apps/webui/mass_change_password.xhtml',
        'ldaptor/apps/webui/move.xhtml',
        'ldaptor/apps/webui/search.xhtml',

        'ldaptor/apps/webui/ldaptor.css',
        ]),
        ],
	  )
