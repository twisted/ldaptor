#!/usr/bin/python

import os, errno
from distutils.core import setup
from distutils import sysconfig, cmd
from distutils.command.build import build as _build
from distutils.command.clean import clean as _clean
from distutils.command.install import install as _install
from distutils.util import change_root
from distutils.dir_util import remove_tree, copy_tree, mkpath

# quick hack to support generating locale files
class build(_build):
    def __init__(self, *a, **kw):
        self.sub_commands = self.sub_commands + [
            ('build_locale', None),
            ]
        _build.__init__(self, *a, **kw)

class build_locale(cmd.Command):
    user_options = [
        ('build-dir=', 'd', "directory to build to"),
        ('po-dir=', 'd', "directory holding the domain dirs and in them PO-files"),
        ]

    def initialize_options(self):
        self.build_dir = 'locale'
        self.build_base = None
        self.po_dir = 'po'

    def finalize_options (self):
        self.set_undefined_options('build',
                                   ('build_base', 'build_base'))
        self.build_dir = change_root(self.build_base, self.build_dir)

    def run(self):
        for domain in os.listdir(self.po_dir):
            try:
                l = os.listdir(os.path.join(self.po_dir, domain))
            except OSError, e:
                if e.errno == errno.ENOTDIR:
                    continue
                else:
                    raise
            
            for po in l:
                if not po.endswith('.po'):
                    continue
                locale = po[:-len('.po')]
                path = os.path.join(self.build_dir,
                                    locale,
                                    'LC_MESSAGES')
                mkpath(path)
                self.spawn(['msgfmt', '-o',
                            os.path.join(path, '%s.mo' % domain),
                            os.path.join(self.po_dir,
                                         domain,
                                         po)])
class clean(_clean):
    def run(self):
        self.run_command('clean_locale')
        _clean.run(self)

class clean_locale(cmd.Command):
    user_options = [
        ('build-dir=', 'd', "directory to build to"),
        ]

    def initialize_options(self):
        self.build_dir = None

    def finalize_options (self):
        self.set_undefined_options('build_locale',
                                   ('build_dir', 'build_dir'))

    def run(self):
        if os.path.exists(self.build_dir):
            remove_tree(self.build_dir, dry_run=self.dry_run)

class install(_install):
    def __init__(self, *a, **kw):
        self.sub_commands = self.sub_commands + [
            ('install_locale', None),
            ]
        _install.__init__(self, *a, **kw)

class install_locale(cmd.Command):
    user_options = [
        ('install-dir=', 'd', "directory to install locales to"),
        ('build-dir=','b', "build directory (where to install from)"),
        ('skip-build', None, "skip the build steps"),
        ]

    boolean_options = ['skip-build']

    def initialize_options(self):
        self.build_dir = None
        self.install_dir = None
        self.root = None
        self.prefix = None
        self.skip_build = None

    def finalize_options (self):
        self.set_undefined_options('build_locale',
                                   ('build_dir', 'build_dir'))
        self.set_undefined_options('install',
                                   ('skip_build', 'skip_build'))
        if self.install_dir is None:
            self.set_undefined_options('install',
                                       ('root', 'root'))
            self.set_undefined_options('install',
                                       ('prefix', 'prefix'))
            prefix = self.prefix
            if self.root is not None:
                prefix = change_root(self.root, prefix)
            self.install_dir = os.path.join(prefix, 'share', 'locale')

    def run(self):
        if not self.skip_build:
            self.run_command('build_locale')
        copy_tree(src=self.build_dir,
                  dst=self.install_dir,
                  dry_run=self.dry_run)

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
                    'build_locale': build_locale,
                    'clean': clean,
                    'clean_locale': clean_locale,
                    'install': install,
                    'install_locale': install_locale,
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
