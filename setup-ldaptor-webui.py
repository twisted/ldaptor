#!/usr/bin/env python

from distutils.core import setup, Extension

if __name__=='__main__':
    setup(name="ldaptor-webui",
          description="Web user interface for editing LDAP directories",
          long_description="""

A web-based user interface to search and edit information in an LDAP
directory.

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
