#!/usr/bin/python
import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


if __name__ == '__main__':
    setup(name="ldaptor",
          version='0.0.54',
          description="Pure-Python library for LDAP",
          long_description=read('README.md'),
          author="Tommi Virtanen",
          author_email="tv@eagain.net",
          maintainer="Bret Curtis",
          maintainer_email="psi29a@gmail.com",
          url="https://github.com/twisted/ldaptor",
          license="MIT",
          install_requires=['zope.interface', 'Twisted', 'pyparsing', 'pyOpenSSL', 'PyCrypto'],
          classifiers=['Intended Audience :: Developers',
                       'License :: OSI Approved :: MIT License',
                       'Operating System :: OS Independent',
                       'Development Status :: 7 - Inactive',
                       'Framework :: Twisted', 'Programming Language :: Python',
                       'Topic :: Software Development :: Libraries :: Python Modules',
                       'Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP'],
          packages=["ldaptor",
                    "ldaptor.protocols",
                    "ldaptor.protocols.ldap",
                    "ldaptor.protocols.ldap.autofill",
                    "ldaptor.samba",
                    "ldaptor.test"],
          scripts=["bin/ldaptor-ldap2dhcpconf",
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
                   "bin/ldaptor-ldifpatch"]
          )