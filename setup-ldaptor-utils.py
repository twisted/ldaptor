#!/usr/bin/env python

#debian-section: admin
#debian-depends:

from distutils.core import setup, Extension

if __name__=='__main__':
    setup(name="ldaptor-utils",
	  description="Command-line LDAP utilities",
	  long_description="""

A set of LDAP utilities for use from the command line, including:

ldaptor-search -- Search LDAP directories.

ldaptor-namingcontexts -- Fetch the naming contexts the server
supports.

ldaptor-find-server -- Find the server that serves the wanted DN by
looking at DNS SRV records.

ldaptor-passwd -- Change passwords.

ldaptor-rename -- Change object RDN and DNs.

ldaptor-ldap2passwd -- Generate passwd(5) format data from LDAP
accounts.

ldaptor-getfreenumber -- Do an efficient scan for e.g. next free
uidNumber.

ldaptor-ldap2dhcpconf -- Create dhcp.conf based on LDAP host info.

ldaptor-ldap2maradns -- Create a maradns zone file based on LDAP host
info.

ldaptor-ldap2pdns -- pdns pipe backend.

ldaptor-fetchschema -- Fetch schema from a server.

ldaptor-ldifdiff -- Read two LDIF files and output LDIF modifications
that modify entries in first file to look like entries in second file.

ldaptor-ldifpatch -- Read an LDIF file and LDIF modifications and
output LDIF with the modifications.

""".strip(),
	  author="Tommi Virtanen",
	  author_email="tv@debian.org",
	  #url="TODO",
	  license="GNU LGPL",

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
	"bin/ldaptor-ldap2pdns",
	"bin/ldaptor-find-server",
	"bin/ldaptor-rename",
	"bin/ldaptor-fetchschema",
	],
	  )
