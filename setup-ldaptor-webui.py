#!/usr/bin/env python

#debian-section: admin
#debian-depends: python%(var PYTHON_VERSION_DEFAULT)s-nevow

import os
from distutils.core import setup, Extension
from distutils import sysconfig

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
	  license="GNU LGPL",

	  packages=[
	"ldaptor.apps.webui",
	],
	  scripts=[
	"bin/ldaptor-webui",
	],
          data_files=[
        (os.path.join(sysconfig.get_python_lib(), 'ldaptor/apps/webui'),
         [
        'ldaptor/apps/webui/add-really.xhtml',
        'ldaptor/apps/webui/add.xhtml',
        'ldaptor/apps/webui/basedn.xhtml',
        'ldaptor/apps/webui/change_password.xhtml',
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
        ],
	  )