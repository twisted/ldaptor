#!/usr/bin/env python

from distutils.core import setup, Extension

setup(name="ldaptor-utils",
      description="TODO",
      long_description="""
Ldaptor is TODO
""".strip(),
      author="Tommi Virtanen",
      author_email="tv@debian.org",
      #url="TODO",
      licence="GNU LGPL",
      
      package_dir={"": "lib"},
      packages=[
    ],
      scripts=[
    "bin/ldaptor-ldap2dhcpconf",
    "bin/ldaptor-ldap2maradns",
    "bin/ldaptor-search",
    "bin/ldaptor-namingcontexts",
    "bin/ldaptor-passwd",
    ],
      )
