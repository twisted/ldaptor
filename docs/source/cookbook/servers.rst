============
LDAP Servers
============

An LDAP directory information tree (DIT) is a highly specialized
database with entries arranged in a tree-like structure.

.. contents:: :local:


""""""""""""""""""""
File-System LDAP DIT
""""""""""""""""""""
A minimal LDAP DIT that stores entries in the local file system

''''
Code
''''

First, a module that defines our DIT entries-- :file:`schema.py`

.. literalinclude:: /examples/schema.py
   :language: python
   :linenos:


Next, the server code-- :file:`ldaptor_basic.py`

.. literalinclude:: /examples/ldaptor_basic.py
   :language: python
   :linenos:


""""""""""""""""""""""""""""""""""""""
LDAP Server which allows BIND with UPN
""""""""""""""""""""""""""""""""""""""

The LDAP server implemented by Microsoft Active Directory allows using the
UPN as the BIND DN.

It is possible to implement something similar using ldaptor.

Below is a proof-of-concept implementation, which should not be used for
production as it has an heuristic method for detecting which BIND DN is an
UPN.

`handle_LDAPBindRequest` is the method called when a BIND request is
received.


.. literalinclude:: /examples/ldaptor_with_upn_bind.py
    :language: python
    :emphasize-lines: 34
    :linenos:
