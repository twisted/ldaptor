#!/usr/bin/python

import codecs
import os
import re

from setuptools import setup


here = os.path.abspath(os.path.dirname(__file__))


def read(*parts):
    with codecs.open(os.path.join(here, *parts), 'r') as f:
        return f.read()


def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


if __name__ == '__main__':
    setup(name="ldaptor",
          version=find_version("ldaptor", "__init__.py"),
          description="A Pure-Python Twisted library for LDAP",
          long_description=read('README.rst'),
          author="Tommi Virtanen",
          author_email="tv@eagain.net",
          maintainer="Bret Curtis",
          maintainer_email="psi29a@gmail.com",
          url="https://github.com/twisted/ldaptor",
          license="MIT",
          install_requires=[
              'passlib',
              'Twisted[tls]',
              'pyparsing',
              'six >= 1.7',
              'zope.interface',
          ],
          classifiers=[
              'Intended Audience :: Developers',
              'License :: OSI Approved :: MIT License',
              'Operating System :: OS Independent',
              'Development Status :: 5 - Production/Stable',
              'Framework :: Twisted', 'Programming Language :: Python',
              'Topic :: Software Development :: Libraries :: Python Modules',
              'Topic :: System :: Systems Administration '
              ':: Authentication/Directory :: LDAP'
          ],
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
