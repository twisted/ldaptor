#!/usr/bin/env python

from distutils.core import setup, Extension

setup(name="ldaptor-webui",
      description="Web user interface for editing LDAP directories",
      long_description="""
Ldaptor is TODO
""".strip(),
      author="Tommi Virtanen",
      author_email="tv@debian.org",
      #url="TODO",
      licence="GNU LGPL",
      
      package_dir={"": "lib"},
      packages=[
    "ldaptor.apps.webui",
    ],
      scripts=[
    "bin/ldaptor-webui",
    ],
      )
