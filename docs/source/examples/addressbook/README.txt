Creating a simple LDAP application

We will create a simple web-based address book application, utilizing
LDAP for information storage. Among the topics covered will be an
overview of LDAP, and an introduction to the Python programming
language and Ldaptor and Twisted programming libraries.

Estimated length: 1h 30min, including a short break.

First, you need to start the LDAP server. Have OpenLDAP installed
(apt-get install slapd), cd into the server directory and say "./run".
You don't need to be root.

Also, the examples use the Nevow programming library, which isn't
exactly stable yet. You will probably need to do a CVS checkout of it,
and add the directory to PYTHONPATH. For more information on Nevow,
please see http://www.divmod.org/Home/Projects/Nevow/index.html

The slides accompanying these data files are in directory
"addressbook-slides" in the parent directory of the examples
directory.


NOTE: These are slides for a talk, they might not make a lot of
sense without hearing the talk. If you have any questions, email
me at tv@debian.org.
