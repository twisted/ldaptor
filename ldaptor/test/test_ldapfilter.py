"""
Test cases for ldaptor.protocols.ldap.ldapfilter module.
"""

from twisted.trial import unittest
from ldaptor.mutablestring import MutableString
from ldaptor.protocols import pureldap, pureber
from ldaptor import ldapfilter
import types

def s(*l):
    """Join all members of list to a string. Integer members are chr()ed"""
    r=''
    for e in l:
	if isinstance(e, types.IntType):
	    e=chr(e)
	r=r+str(e)
    return r

def l(s):
    """Split a string to ord's of chars."""
    return map(lambda x: ord(x), s)

#TODO
