#!/usr/bin/env python

from distutils.core import setup, Extension

setup(name="ldaptor",
      version="0.0.0.20020526.1",
      description="TODO",
      long_description="""
Ldaptor is TODO
""",
      author="Tommi Virtanen",
      author_email="tv@debian.org",
      #url="TODO",
      licence="GNU LGPL",
      
      package_dir={"": "lib"},
      packages=[
    "ldaptor",

    "ldaptor.protocols", "ldaptor.protocols.ldap",

    "ldaptor.twisted",

    "ldaptor.apps",
    "ldaptor.apps.webui",
    ],
      scripts=["bin/ldaptor-webui"],
      )
