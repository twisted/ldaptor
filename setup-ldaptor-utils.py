#!/usr/bin/env python

#debian-section: admin

from distutils.core import setup, Extension

if __name__=='__main__':
    setup(name="ldaptor-utils",
          description="Command-line LDAP utilities",
          long_description="""

A set of LDAP utilities for use from the command line, including:

ldaptor-search -- Search LDAP directories.

ldaptor-namingcontexts -- Fetch the naming contexts the server
supports.

ldaptor-passwd -- Change passwords.

ldaptor-ldap2passwd -- Generate passwd(5) format data from LDAP
accounts.

ldaptor-getfreenumber -- Do an efficient scan for e.g. next free
uidNumber.

ldaptor-ldap2dhcpconf -- Create dhcp.conf based on LDAP host info.

ldaptor-ldap2maradns -- Create a maradns zone file based on LDAP host
info.

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
        "bin/ldaptor-ldap2passwd",
        "bin/ldaptor-getfreenumber",
        ],
          )
