#!/usr/bin/env python

from distutils.core import setup, Extension

setup(name="python-ldaptor",
      description="Pure-Python library for LDAP",
      long_description="""
TODO
""".strip(),
      author="Tommi Virtanen",
      author_email="tv@debian.org",
      #url="TODO",
      licence="GNU LGPL",
      
      package_dir={"": "lib"},
      packages=[
    "ldaptor",

    "ldaptor.protocols", "ldaptor.protocols.ldap",

    "ldaptor.apps",
    ],
      )
