#!/usr/bin/python

import os
from distutils.core import setup, Extension
from distutils import sysconfig, cmd
from distutils.command.build import build as _build
from distutils.command.clean import clean as _clean
from distutils.command.install import install as _install
from distutils.util import change_root
from distutils.dir_util import remove_tree, copy_tree

# quick hack to support generating locale files
class build(_build):
    def run(self):
        _build.run(self)
        self.spawn(['./admin/l10n-generate'])

class clean(_clean):
    def run(self):
        _clean.run(self)

        if os.path.exists('locale'):
            remove_tree('locale', dry_run=self.dry_run)

class install(_install):
    def run(self):
        _install.run(self)
        
        copy_tree(src='locale',
                  dst=os.path.join(change_root(self.root, self.prefix),
                                   'share', 'locale'),
                  dry_run=self.dry_run)

def grabAll(topdir, to=None, fileFilter=None):
    for dirpath, dirnames, filenames in os.walk(topdir):
        if '.svn' in dirnames:
            dirnames.remove('.svn')

        if len(dirpath) == len(topdir):
            path = '.'
        elif len(dirpath) > len(topdir):
            path = dirpath[len(topdir):]
            if path[0] != '/':
                raise RuntimeError, "all weird"
            path = path[1:]
        else:
            raise RuntimeError, "all weird"

        if to is not None:
            path = os.path.join(to, path)
        l = []
        for filename in filenames:
            if (fileFilter is None
                or fileFilter(dirpath, filename)):
                l.append(os.path.join(dirpath, filename))
        if l:
            yield (path, l)

if __name__=='__main__':
    setup(name="ldaptor",
	  description="Pure-Python library for LDAP",
	  long_description="""

Ldaptor is a pure-Python library that implements

- LDAP client logic.

- separately-accessible LDAP and BER protocol message
generation/parsing.

- ASCII-format LDAP filter generation and parsing.

- LDIF format data generation.

- Samba password changing logic.

Also included is a web-based user interface to search and edit
information in an LDAP directory and a set of LDAP utilities for use
from the command line.

""".strip(),
	  author="Tommi Virtanen",
	  author_email="tv@debian.org",
	  #url="TODO",
	  license="GNU LGPL",

          cmdclass={'build': build,
                    'clean': clean,
                    'install': install,
                    },

	  packages=[
	"ldaptor",
	"ldaptor.protocols",
        "ldaptor.protocols.ldap",
        "ldaptor.protocols.ldap.autofill",
	"ldaptor.samba",
	"ldaptor.apps",
	"ldaptor.apps.webui",
	"ldaptor.test",
	],
	  scripts=[
	"bin/ldaptor-webui",
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
          data_files=[
        (os.path.join(sysconfig.get_python_lib(), 'ldaptor/apps/webui'),
         [
        'ldaptor/apps/webui/add-really.xhtml',
        'ldaptor/apps/webui/add.xhtml',
        'ldaptor/apps/webui/basedn.xhtml',
        'ldaptor/apps/webui/change_password.xhtml',
        'ldaptor/apps/webui/change_service_passwords.xhtml',
        'ldaptor/apps/webui/delete-done.xhtml',
        'ldaptor/apps/webui/delete-nodn.xhtml',
        'ldaptor/apps/webui/delete.xhtml',
        'ldaptor/apps/webui/edit-really.xhtml',
        'ldaptor/apps/webui/edit.xhtml',
        'ldaptor/apps/webui/login.xhtml',
        'ldaptor/apps/webui/mass_change_password-really.xhtml',
        'ldaptor/apps/webui/mass_change_password.xhtml',
        'ldaptor/apps/webui/move.xhtml',
        'ldaptor/apps/webui/search.xhtml',

        'ldaptor/apps/webui/ldaptor.css',
        ]),
        ])
