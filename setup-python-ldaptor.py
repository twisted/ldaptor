#!/usr/bin/env python

#debian-section: python

from distutils.core import setup, Extension

if __name__=='__main__':
    setup(name="python-ldaptor",
	  description="Pure-Python library for LDAP",
	  long_description="""
Ldaptor is a pure-Python library that implements

- LDAP client logic.

- separately-accessible LDAP and BER protocol message
generation/parsing.

- ASCII-format LDAP filter generation and parsing.

- LDIF format data generation.

- Samba password changing logic.


""".strip(),
	  author="Tommi Virtanen",
	  author_email="tv@debian.org",
	  #url="TODO",
	  license="GNU LGPL",

	  packages=[
	"ldaptor",

	"ldaptor.protocols", "ldaptor.protocols.ldap",
	"ldaptor.samba",

	"ldaptor.apps",
	],
	  )
