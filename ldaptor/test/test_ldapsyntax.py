"""
Test cases for ldaptor.protocols.ldap.ldapsyntax module.
"""

from twisted.trial import unittest
from ldaptor import config
from ldaptor.protocols.ldap import ldapsyntax, distinguishedname, ldaperrors
from ldaptor.protocols import pureldap, pureber
from twisted.internet import defer
from twisted.python import failure
from ldaptor.testutil import LDAPClientTestDriver
from twisted.trial.util import deferredResult, deferredError

class LDAPSyntaxBasics(unittest.TestCase):
    def testCreation(self):
	"""Creating an LDAP object should succeed."""
        client = LDAPClientTestDriver()
	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a'],
	    'bValue': ['b'],
	    })
	self.failUnlessEqual(str(o.dn), 'cn=foo,dc=example,dc=com')
	self.failUnlessEqual(o['objectClass'], ['a', 'b'])
	self.failUnlessEqual(o['aValue'], ['a'])
	self.failUnlessEqual(o['bValue'], ['b'])
        client.assertNothingSent()

    def testKeys(self):
	"""Iterating over the keys of an LDAP object gives expected results."""
        client = LDAPClientTestDriver()
	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a'],
	    'bValue': ['b'],
	    })
        seen={}
        for k in o.keys():
            assert not seen.has_key(k)
            seen[k]=1
        assert seen == {'objectClass': 1,
                        'aValue': 1,
                        'bValue': 1,
                        }

    def testItems(self):
	"""Iterating over the items of an LDAP object gives expected results."""
        client = LDAPClientTestDriver()
	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a'],
	    'bValue': ['b'],
	    })
        seen={}
        for k,vs in o.items():
            assert not seen.has_key(k)
            seen[k]=vs
        assert seen == {'objectClass': ['a', 'b'],
                        'aValue': ['a'],
                        'bValue': ['b'],
                        }

    def testIn(self):
        """Key in object gives expected results."""
        client=LDAPClientTestDriver()
	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a'],
	    'bValue': ['b'],
	    })
        assert 'objectClass' in o
        assert 'aValue' in o
        assert 'bValue' in o
        assert 'foo' not in o
        assert '' not in o
        assert None not in o

        assert 'a' in o['objectClass']
        assert 'b' in o['objectClass']
        assert 'foo' not in o['objectClass']
        assert '' not in o['objectClass']
        assert None not in o['objectClass']

        assert 'a' in o['aValue']
        assert 'foo' not in o['aValue']
        assert '' not in o['aValue']
        assert None not in o['aValue']

class LDAPSyntaxAttributes(unittest.TestCase):
    def testAttributeSetting(self):
        client=LDAPClientTestDriver()
	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a'],
	    'bValue': ['b'],
	    })
	o['aValue']=['foo', 'bar']
	self.failUnlessEqual(o['aValue'], ['foo', 'bar'])
	o['aValue']=['quux']
	self.failUnlessEqual(o['aValue'], ['quux'])
	self.failUnlessEqual(o['bValue'], ['b'])
	o['cValue']=['thud']
	self.failUnlessEqual(o['aValue'], ['quux'])
	self.failUnlessEqual(o['bValue'], ['b'])
	self.failUnlessEqual(o['cValue'], ['thud'])

    def testAttributeDelete(self):
        client=LDAPClientTestDriver()
	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a'],
	    'bValue': ['b'],
	    })
	o['aValue']=['quux']
	del o['aValue']
	del o['bValue']
	self.failIf(o.has_key('aValue'))
	self.failIf(o.has_key('bValue'))

    def testAttributeAdd(self):
        client=LDAPClientTestDriver()
	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a'],
	    'bValue': ['b'],
	    })
	o['aValue'].add('foo')
	self.failUnlessEqual(o['aValue'], ['a', 'foo'])

    def testAttributeItemDelete(self):
        client=LDAPClientTestDriver()
	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a', 'b', 'c'],
	    'bValue': ['b'],
	    })
	o['aValue'].remove('b')
	self.failUnlessEqual(o['aValue'], ['a', 'c'])

    def testUndo(self):
	"""Undo should forget the modifications."""
        client=LDAPClientTestDriver()
	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a'],
	    'bValue': ['b'],
	    'cValue': ['c'],
	    })
	o['aValue']=['foo', 'bar']
	o['aValue']=['quux']
	del o['cValue']
	o.undo()
	self.failUnlessEqual(o['aValue'], ['a'])
	self.failUnlessEqual(o['bValue'], ['b'])
	self.failUnlessEqual(o['cValue'], ['c'])

    def testUndoJournaling(self):
	"""Journaling should still work after undo."""
        client=LDAPClientTestDriver(
            [ pureldap.LDAPModifyResponse(resultCode=0,
                                          matchedDN='',
                                          errorMessage=''),
            ])
	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a'],
	    'bValue': ['b'],
	    'cValue': ['c'],
	    })
	o['aValue']=['foo', 'bar']
	o['aValue']=['quux']
	del o['cValue']
        o.undo()
	o['aValue'].update(['newValue', 'anotherNewValue'])
	d=o.commit()
        val = deferredResult(d)
        
	self.failUnlessEqual(o['aValue'], ['a', 'newValue', 'anotherNewValue'])
	self.failUnlessEqual(o['bValue'], ['b'])
	self.failUnlessEqual(o['cValue'], ['c'])
        client.assertSent(pureldap.LDAPModifyRequest(
	    object='cn=foo,dc=example,dc=com',
	    modification=[
	    pureldap.LDAPModification_add(attributeType='aValue',
                                          vals=['newValue', 'anotherNewValue']),
	    ]))

    def testUndoAfterCommit(self):
	"""Undo should not undo things that have been commited."""

        client=LDAPClientTestDriver(
            [ pureldap.LDAPModifyResponse(resultCode=0,
                                          matchedDN='',
                                          errorMessage=''),
            ])
	o=ldapsyntax.LDAPEntry(
	    client=client,
	    dn='cn=foo,dc=example,dc=com',
	    attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a'],
	    'bValue': ['b'],
	    'cValue': ['c'],
	    })
	o['aValue']=['foo', 'bar']
	o['bValue']=['quux']
	del o['cValue']

	d=o.commit()
        val = deferredResult(d)

	o.undo()
	self.failUnlessEqual(o['aValue'], ['foo', 'bar'])
	self.failUnlessEqual(o['bValue'], ['quux'])
	self.failIf(o.has_key('cValue'))

class LDAPSyntaxAttributesModificationOnWire(unittest.TestCase):
    def testAdd(self):
	"""Modify & commit should write the right data to the server."""

        client = LDAPClientTestDriver(
            [	pureldap.LDAPModifyResponse(resultCode=0,
                                            matchedDN='',
                                            errorMessage=''),
                ])

	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a'],
	    })
	o['aValue'].update(['newValue', 'anotherNewValue'])

	d=o.commit()
        val = deferredResult(d)

        client.assertSent(pureldap.LDAPModifyRequest(
	    object='cn=foo,dc=example,dc=com',
	    modification=[
	    pureldap.LDAPModification_add(attributeType='aValue',
                                          vals=['newValue', 'anotherNewValue']),
	    ]))

    def testAddSeparate(self):
	"""Modify & commit should write the right data to the server."""

        client = LDAPClientTestDriver(
            [	pureldap.LDAPModifyResponse(resultCode=0,
                                            matchedDN='',
                                            errorMessage=''),
                ])

	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a'],
	    })
	o['aValue'].add('newValue')
	o['aValue'].add('anotherNewValue')

	d=o.commit()
        val = deferredResult(d)

        client.assertSent(pureldap.LDAPModifyRequest(
	    object='cn=foo,dc=example,dc=com',
	    modification=[
	    pureldap.LDAPModification_add(attributeType='aValue',
                                          vals=['newValue']),
	    pureldap.LDAPModification_add(attributeType='aValue',
                                          vals=['anotherNewValue']),
	    ]))

    def testDeleteAttribute(self):
	"""Modify & commit should write the right data to the server."""

        client = LDAPClientTestDriver(
            [	pureldap.LDAPModifyResponse(resultCode=0,
                                            matchedDN='',
                                            errorMessage='')
                ])

	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a'],
	    })
	o['aValue'].remove('a')

	d=o.commit()
        val = deferredResult(d)

	client.assertSent(pureldap.LDAPModifyRequest(
	    object='cn=foo,dc=example,dc=com',
	    modification=[
	    pureldap.LDAPModification_delete(attributeType='aValue',
                                             vals=['a']),
	    ]))

    def testDeleteAllAttribute(self):
	"""Modify & commit should write the right data to the server."""

        client = LDAPClientTestDriver(
            [	pureldap.LDAPModifyResponse(resultCode=0,
                                            matchedDN='',
                                            errorMessage=''),
                ])

	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a1', 'a2'],
	    'bValue': ['b1', 'b2'],
	    })
	del o['aValue']
	o['bValue'].clear()

	d=o.commit()
        val = deferredResult(d)

	client.assertSent(pureldap.LDAPModifyRequest(
	    object='cn=foo,dc=example,dc=com',
	    modification=[
	    pureldap.LDAPModification_delete('aValue'),
	    pureldap.LDAPModification_delete('bValue'),
	    ]))


    def testReplaceAttributes(self):
	"""Modify & commit should write the right data to the server."""

        client = LDAPClientTestDriver(
            [	pureldap.LDAPModifyResponse(resultCode=0,
                                            matchedDN='',
                                            errorMessage='')
                ])

	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a'],
	    })
	o['aValue']=['foo', 'bar']

	d=o.commit()
        val = deferredResult(d)

        client.assertSent(pureldap.LDAPModifyRequest(
	    object='cn=foo,dc=example,dc=com',
	    modification=[
	    pureldap.LDAPModification_replace(attributeType='aValue',
                                              vals=['foo', 'bar']),
	    ]))


class LDAPSyntaxSearch(unittest.TestCase):
    def testSearch(self):
	"""Test searches."""

	client=LDAPClientTestDriver([
            pureldap.LDAPSearchResultEntry(
            objectName='cn=foo,dc=example,dc=com',
            attributes=(('foo', ['a']),
                        ('bar', ['b', 'c']),
                        ),
            ),
            pureldap.LDAPSearchResultEntry(
            objectName='cn=bar,dc=example,dc=com',
            attributes=(('foo', ['a']),
                        ('bar', ['d', 'e']),
                        ),
            ),
            pureldap.LDAPSearchResultDone(
            resultCode=0,
            matchedDN='',
            errorMessage='')
            ])

	o=ldapsyntax.LDAPEntry(client=client,
                               dn='dc=example,dc=com',
                               attributes={
	    'objectClass': ['organizationalUnit'],
	    })

	d=o.search(filterText='(foo=a)',
		   attributes=['foo', 'bar'])
        val = deferredResult(d)

	client.assertSent(pureldap.LDAPSearchRequest(
	    baseObject='dc=example,dc=com',
	    scope=pureldap.LDAP_SCOPE_wholeSubtree,
	    derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
	    sizeLimit=0,
	    timeLimit=0,
	    typesOnly=0,
	    filter=pureldap.LDAPFilter_equalityMatch(
            attributeDesc=pureldap.LDAPAttributeDescription(value='foo'),
            assertionValue=pureldap.LDAPAssertionValue(value='a')),
	    attributes=['foo', 'bar']))
	self.failUnlessEqual(len(val), 2)

	self.failUnlessEqual(val[0],
			     ldapsyntax.LDAPEntry(
	    client=client,
	    dn='cn=foo,dc=example,dc=com',
	    attributes={
	    'foo': ['a'],
	    'bar': ['b', 'c'],
	    }))

	self.failUnlessEqual(val[1],
			     ldapsyntax.LDAPEntry(
	    client=client,
	    dn='cn=bar,dc=example,dc=com',
	    attributes={
	    'foo': ['a'],
	    'bar': ['d', 'e'],
	    }))

    def testSearch_defaultAttributes(self):
	"""Search without explicit list of attributes returns all attributes."""

	client=LDAPClientTestDriver([
            pureldap.LDAPSearchResultEntry(
            objectName='cn=foo,dc=example,dc=com',
            attributes=(('foo', ['a']),
                        ('bar', ['b', 'c']),
                        ),
            ),
            pureldap.LDAPSearchResultEntry(
            objectName='cn=bar,dc=example,dc=com',
            attributes=(('foo', ['a']),
                        ('bar', ['d', 'e']),
                        ),
            ),
            pureldap.LDAPSearchResultDone(
            resultCode=0,
            matchedDN='',
            errorMessage='')
            ])

	o=ldapsyntax.LDAPEntry(client=client,
                               dn='dc=example,dc=com',
                               attributes={
	    'objectClass': ['organizationalUnit'],
	    })

	d=o.search(filterText='(foo=a)')
        val = deferredResult(d)

	client.assertSent(pureldap.LDAPSearchRequest(
	    baseObject='dc=example,dc=com',
	    scope=pureldap.LDAP_SCOPE_wholeSubtree,
	    derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
	    sizeLimit=0,
	    timeLimit=0,
	    typesOnly=0,
	    filter=pureldap.LDAPFilter_equalityMatch(
            attributeDesc=pureldap.LDAPAttributeDescription(value='foo'),
            assertionValue=pureldap.LDAPAssertionValue(value='a')),
	    attributes=[]))
	self.failUnlessEqual(len(val), 2)

	self.failUnlessEqual(val[0],
			     ldapsyntax.LDAPEntry(
	    client=client,
	    dn='cn=foo,dc=example,dc=com',
	    attributes={
	    'foo': ['a'],
	    'bar': ['b', 'c'],
	    }))
	self.failUnless(val[0].complete)

	self.failUnlessEqual(val[1],
			     ldapsyntax.LDAPEntry(
	    client=client,
	    dn='cn=bar,dc=example,dc=com',
	    attributes={
	    'foo': ['a'],
	    'bar': ['d', 'e'],
	    }))
	self.failUnless(val[1].complete)

    def testSearch_noAttributes(self):
	"""Search with attributes=None returns no attributes."""

	client=LDAPClientTestDriver([
            pureldap.LDAPSearchResultEntry('cn=foo,dc=example,dc=com',
                                           attributes=()),
            pureldap.LDAPSearchResultEntry('cn=bar,dc=example,dc=com',
                                           attributes=()),
            pureldap.LDAPSearchResultDone(
            resultCode=0,
            matchedDN='',
            errorMessage='')
            ])

	o=ldapsyntax.LDAPEntry(client=client,
                               dn='dc=example,dc=com',
                               attributes={
	    'objectClass': ['organizationalUnit'],
	    })

	d=o.search(filterText='(foo=a)',
                   attributes=None)
        val = deferredResult(d)

	client.assertSent(pureldap.LDAPSearchRequest(
	    baseObject='dc=example,dc=com',
	    scope=pureldap.LDAP_SCOPE_wholeSubtree,
	    derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
	    sizeLimit=0,
	    timeLimit=0,
	    typesOnly=0,
	    filter=pureldap.LDAPFilter_equalityMatch(
            attributeDesc=pureldap.LDAPAttributeDescription(value='foo'),
            assertionValue=pureldap.LDAPAssertionValue(value='a')),
	    attributes=['1.1']))
	self.failUnlessEqual(len(val), 2)

	self.failUnlessEqual(val[0],
			     ldapsyntax.LDAPEntry(
	    client=client,
	    dn='cn=foo,dc=example,dc=com'))
	self.failIf(val[0].complete)

	self.failUnlessEqual(val[1],
			     ldapsyntax.LDAPEntry(
	    client=client,
	    dn='cn=bar,dc=example,dc=com'))
	self.failIf(val[1].complete)

    def testSearch_ImmediateProcessing(self):
	"""Test searches with the immediate processing feature."""

	client=LDAPClientTestDriver([
            pureldap.LDAPSearchResultEntry(
            objectName='cn=foo,dc=example,dc=com',
            attributes=(('bar', ['b', 'c']),
                        ),
            ),

            pureldap.LDAPSearchResultEntry(
            objectName='cn=bar,dc=example,dc=com',
            attributes=(('bar', ['b', 'c']),
                        ),
            ),

            pureldap.LDAPSearchResultDone(
            resultCode=0,
            matchedDN='',
            errorMessage='')
            ])

	o=ldapsyntax.LDAPEntry(client=client,
                               dn='dc=example,dc=com',
                               attributes={
	    'objectClass': ['organizationalUnit'],
	    })

	seen=[]
	def process(o):
	    seen.append(o)

	d=o.search(filterText='(foo=a)',
		   attributes=['bar'],
		   callback=process)
        val = deferredResult(d)

	self.assertEquals(val, None)

        client.assertSent(pureldap.LDAPSearchRequest(
	    baseObject='dc=example,dc=com',
	    scope=pureldap.LDAP_SCOPE_wholeSubtree,
	    derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
	    sizeLimit=0,
	    timeLimit=0,
	    typesOnly=0,
	    filter=pureldap.LDAPFilter_equalityMatch(
            attributeDesc=pureldap.LDAPAttributeDescription(value='foo'),
            assertionValue=pureldap.LDAPAssertionValue(value='a')),
	    attributes=['bar']))

	self.failUnlessEqual(seen,
			     [
	    ldapsyntax.LDAPEntry(
	    client=client,
	    dn='cn=foo,dc=example,dc=com',
	    attributes={
	    'bar': ['b', 'c'],
	    }),
	    ldapsyntax.LDAPEntry(
	    client=client,
	    dn='cn=bar,dc=example,dc=com',
	    attributes={
	    'bar': ['b', 'c'],
	    })])

    def testSearch_fail(self):
	client=LDAPClientTestDriver([
            pureldap.LDAPSearchResultDone(
            resultCode=ldaperrors.LDAPBusy.resultCode,
            matchedDN='',
            errorMessage='Go away')
            ])

	o=ldapsyntax.LDAPEntry(client=client, dn='dc=example,dc=com')
	d=o.search(filterText='(foo=a)')
        fail = deferredError(d)
        fail.trap(ldaperrors.LDAPBusy)
        self.assertEquals(fail.value.message, 'Go away')

	client.assertSent(pureldap.LDAPSearchRequest(
	    baseObject='dc=example,dc=com',
	    scope=pureldap.LDAP_SCOPE_wholeSubtree,
	    derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
	    sizeLimit=0,
	    timeLimit=0,
	    typesOnly=0,
	    filter=pureldap.LDAPFilter_equalityMatch(
            attributeDesc=pureldap.LDAPAttributeDescription(value='foo'),
            assertionValue=pureldap.LDAPAssertionValue(value='a')),
            ))

class LDAPSyntaxDNs(unittest.TestCase):
    def testDNKeyExistenceSuccess(self):
        client = LDAPClientTestDriver()
	ldapsyntax.LDAPEntry(client=client,
                             dn='cn=foo,dc=example,dc=com',
                             attributes={
	    'cn': ['foo'],
	    })

    def TODOtestDNKeyExistenceFailure(self):
        client = LDAPClientTestDriver()
	self.failUnlessRaises(ldapsyntax.DNNotPresentError,
			      ldapsyntax.LDAPEntry,
			      client=client,
			      dn='cn=foo,dc=example,dc=com',
			      attributes={
	    'foo': ['bar'],
	    })

class LDAPSyntaxLDIF(unittest.TestCase):
    def testLDIFConversion(self):
        client = LDAPClientTestDriver()
	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a', 'b'],
	    'bValue': ['c'],
	    })
	self.failUnlessEqual(str(o),
			     '\n'.join((
	    "dn: cn=foo,dc=example,dc=com",
	    "objectClass: a",
	    "objectClass: b",
	    "aValue: a",
	    "aValue: b",
	    "bValue: c",
	    "\n")))

class LDAPSyntaxDelete(unittest.TestCase):
    def testDeleteInvalidates(self):
	"""Deleting an LDAPEntry invalidates it."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPDelResponse(resultCode=0,
                                      matchedDN='',
                                      errorMessage=''),
             ])
	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a'],
	    })
        d=o.delete()
        val = deferredResult(d)

        self.failUnlessRaises(
            ldapsyntax.ObjectDeletedError,
            o.search,
            filterText='(foo=a)')
        self.failUnlessRaises(
            ldapsyntax.ObjectDeletedError,
            o.get,
            'objectClass')

    def testDeleteOnWire(self):
	"""LDAPEntry.delete should write the right data to the server."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPDelResponse(resultCode=0,
                                      matchedDN='',
                                      errorMessage=''),
             ])
	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a'],
	    })
	d=o.delete()
        val = deferredResult(d)

	client.assertSent(pureldap.LDAPDelRequest(
	    entry='cn=foo,dc=example,dc=com',
            ))

    def testErrorHandling(self):
	"""LDAPEntry.delete should pass LDAP errors to it's deferred."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPDelResponse(resultCode=ldaperrors.LDAPBusy.resultCode,
                                      matchedDN='',
                                      errorMessage='Go away'),
             ])
	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a'],
	    })
	d=o.delete()
        fail = deferredError(d)
        fail.trap(ldaperrors.LDAPBusy)
        self.assertEquals(fail.value.message, 'Go away')

	client.assertSent(pureldap.LDAPDelRequest(
	    entry='cn=foo,dc=example,dc=com',
            ))

    def testErrorHandling_extended(self):
	"""LDAPEntry.delete should pass even non-LDAPDelResponse errors to it's deferred."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPExtendedResponse(resultCode=ldaperrors.LDAPProtocolError.resultCode,
                                                 responseName='1.3.6.1.4.1.1466.20036',
                                                 errorMessage='Unknown request')
             ])
	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a'],
	    })
	d=o.delete()
        fail = deferredError(d)
        fail.trap(ldaperrors.LDAPProtocolError)
        self.assertEquals(fail.value.message, 'Unknown request')

	client.assertSent(pureldap.LDAPDelRequest(
	    entry='cn=foo,dc=example,dc=com',
            ))

class LDAPSyntaxAddChild(unittest.TestCase):
    def testAddChildOnWire(self):
	"""LDAPEntry.addChild should write the right data to the server."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPAddResponse(resultCode=0,
                                      matchedDN='',
                                      errorMessage=''),
             ])
	o=ldapsyntax.LDAPEntry(client=client,
                               dn='ou=things,dc=example,dc=com',
                               attributes={
	    'objectClass': ['organizationalUnit'],
            'ou': ['things'],
	    })
	d=o.addChild(
            rdn='givenName=Firstname+surname=Lastname',
            attributes={'objectClass': ['person', 'otherStuff'],
                        'givenName': ['Firstname'],
                        'surname': ['Lastname'],
                        })
        val = deferredResult(d)

	client.assertSent(pureldap.LDAPAddRequest(
	    entry='givenName=Firstname+surname=Lastname,ou=things,dc=example,dc=com',
            attributes=[ (pureldap.LDAPAttributeDescription('objectClass'),
                          pureber.BERSet([pureldap.LDAPAttributeValue('person'),
                                          pureldap.LDAPAttributeValue('otherStuff'),
                                          ])),
                         (pureldap.LDAPAttributeDescription('givenName'),
                          pureber.BERSet([pureldap.LDAPAttributeValue('Firstname')])),
                         (pureldap.LDAPAttributeDescription('surname'),
                          pureber.BERSet([pureldap.LDAPAttributeValue('Lastname')])),
                         ],
            ))

class LDAPSyntaxContainingNamingContext(unittest.TestCase):
    def testNamingContext(self):
	"""LDAPEntry.namingContext returns the naming context that contains this object (via a Deferred)."""
	client=LDAPClientTestDriver(
            [	pureldap.LDAPSearchResultEntry(
            objectName='',
            attributes=[('namingContexts',
                         ('dc=foo,dc=example',
                          'dc=example,dc=com',
                          'dc=bar,dc=example',
                          ))]),

                pureldap.LDAPSearchResultDone(resultCode=0,
                                              matchedDN='',
                                              errorMessage='')
            ])

	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,ou=bar,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a'],
	    })
        d=o.namingContext()
        val = deferredResult(d)

        p=val
        assert isinstance(p, ldapsyntax.LDAPEntry)
        assert p.client == o.client
        assert str(p.dn) == 'dc=example,dc=com'

	client.assertSent(pureldap.LDAPSearchRequest(
            baseObject='',
            scope=pureldap.LDAP_SCOPE_baseObject,
            filter=pureldap.LDAPFilter_present('objectClass'),
            attributes=['namingContexts'],
            ))


class LDAPSyntaxPasswords(unittest.TestCase):
    def setUp(self):
        cfg = config.loadConfig()
        cfg.set('samba', 'use-lmhash', 'no')

    def testPasswordSetting_ExtendedOperation(self):
        """LDAPEntry.setPassword_ExtendedOperation(newPasswd=...) changes the password."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPExtendedResponse(resultCode=0,
                                           matchedDN='',
                                           errorMessage='')],
            )

	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com')
        d=o.setPassword_ExtendedOperation(newPasswd='new')
        val = deferredResult(d)

	client.assertSent(pureldap.LDAPPasswordModifyRequest(
            userIdentity='cn=foo,dc=example,dc=com',
            newPasswd='new'),
                        )

    def testPasswordSetting_Samba_sambaAccount(self):
        """LDAPEntry.setPassword_Samba(newPasswd=...,
        style='sambaAccount') changes the password."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPModifyResponse(resultCode=0,
                                         matchedDN='',
                                         errorMessage='')],
            )

	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com')
        d=o.setPassword_Samba(newPasswd='new', style='sambaAccount')
        val = deferredResult(d)

	client.assertSent(pureldap.LDAPModifyRequest(
	    object='cn=foo,dc=example,dc=com',
	    modification=[
	    pureldap.LDAPModification_replace(attributeType='ntPassword',
                                              vals=['89963F5042E5041A59C249282387A622']),
	    pureldap.LDAPModification_replace(attributeType='lmPassword',
                                              vals=['XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX']),
            ]))

    def testPasswordSetting_Samba_sambaSamAccount(self):
        """LDAPEntry.setPassword_Samba(newPasswd=..., style='sambaSamAccount') changes the password."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPModifyResponse(resultCode=0,
                                         matchedDN='',
                                         errorMessage='')],
            )

	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com')
        d=o.setPassword_Samba(newPasswd='new', style='sambaSamAccount')
        val = deferredResult(d)

	client.assertSent(pureldap.LDAPModifyRequest(
	    object='cn=foo,dc=example,dc=com',
	    modification=[
	    pureldap.LDAPModification_replace(attributeType='sambaNTPassword',
                                              vals=['89963F5042E5041A59C249282387A622']),
	    pureldap.LDAPModification_replace(attributeType='sambaLMPassword',
                                              vals=['XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX']),
            ]))

    def testPasswordSetting_Samba_defaultStyle(self):
        """LDAPEntry.setPassword_Samba(newPasswd=...) changes the password."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPModifyResponse(resultCode=0,
                                         matchedDN='',
                                         errorMessage='')],
            )

	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com')
        d=o.setPassword_Samba(newPasswd='new')
        val = deferredResult(d)

	client.assertSent(pureldap.LDAPModifyRequest(
	    object='cn=foo,dc=example,dc=com',
	    modification=[
	    pureldap.LDAPModification_replace(attributeType='sambaNTPassword',
                                              vals=['89963F5042E5041A59C249282387A622']),
	    pureldap.LDAPModification_replace(attributeType='sambaLMPassword',
                                              vals=['XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX']),
            ]))

    def testPasswordSetting_Samba_badStyle(self):
        """LDAPEntry.setPassword_Samba(..., style='foo') fails."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPModifyResponse(resultCode=0,
                                         matchedDN='',
                                         errorMessage='')],
            )

	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com')
        d=defer.maybeDeferred(o.setPassword_Samba, newPasswd='new', style='foo')
        fail = deferredError(d)
        fail.trap(RuntimeError)
        self.assertEquals(fail.getErrorMessage(),
                          "Unknown samba password style 'foo'")
        client.assertNothingSent()

    def testPasswordSettingAll_noSamba(self):
        """LDAPEntry.setPassword(newPasswd=...) changes the password."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPExtendedResponse(resultCode=0,
                                           matchedDN='',
                                           errorMessage='')],
            )

	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
            'objectClass': ['foo'],
            },
                               complete=1)
        d=o.setPassword(newPasswd='new')
        val = deferredResult(d)

	client.assertSent(pureldap.LDAPPasswordModifyRequest(
            userIdentity='cn=foo,dc=example,dc=com',
            newPasswd='new'),
                          )


    def testPasswordSettingAll_hasSamba(self):
        """LDAPEntry.setPassword(newPasswd=...) changes the password."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPExtendedResponse(resultCode=0,
                                           matchedDN='',
                                           errorMessage='')],
	    [pureldap.LDAPModifyResponse(resultCode=0,
                                         matchedDN='',
                                         errorMessage='')],
            )

	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
            'objectClass': ['foo', 'sambaAccount'],
            },
                               complete=1)
        d=o.setPassword(newPasswd='new')
        val = deferredResult(d)

	client.assertSent(pureldap.LDAPPasswordModifyRequest(
            userIdentity='cn=foo,dc=example,dc=com',
            newPasswd='new'),
                          pureldap.LDAPModifyRequest(
	    object='cn=foo,dc=example,dc=com',
	    modification=[
	    pureldap.LDAPModification_replace(attributeType='ntPassword',
                                              vals=['89963F5042E5041A59C249282387A622']),
	    pureldap.LDAPModification_replace(attributeType='lmPassword',
                                              vals=['XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX']),
            ]))


    def testPasswordSettingAll_maybeSamba_WillFind(self):
        """LDAPEntry.setPassword(newPasswd=...) changes the password."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPExtendedResponse(resultCode=0,
                                           matchedDN='',
                                           errorMessage='')],
            [
            pureldap.LDAPSearchResultEntry(objectName='',
                                           attributes=[('objectClass',
                                                        ('foo',
                                                         'sambaAccount',
                                                         'bar'))]),
            pureldap.LDAPSearchResultDone(resultCode=0,
                                          matchedDN='',
                                          errorMessage=''),
            ],
	    [pureldap.LDAPModifyResponse(resultCode=0,
                                         matchedDN='',
                                         errorMessage='')],
            )

	o=ldapsyntax.LDAPEntry(client=client, dn='cn=foo,dc=example,dc=com')
        d=o.setPassword(newPasswd='new')
        val = deferredResult(d)

	client.assertSent(
            pureldap.LDAPPasswordModifyRequest(userIdentity='cn=foo,dc=example,dc=com',
                                               newPasswd='new'),
            pureldap.LDAPSearchRequest(baseObject='cn=foo,dc=example,dc=com',
                                       scope=pureldap.LDAP_SCOPE_baseObject,
                                       derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=pureldap.LDAPFilterMatchAll,
                                       attributes=('objectClass',)),
            pureldap.LDAPModifyRequest(object='cn=foo,dc=example,dc=com',
                                       modification=[
	    pureldap.LDAPModification_replace(attributeType='ntPassword',
                                              vals=['89963F5042E5041A59C249282387A622']),
	    pureldap.LDAPModification_replace(attributeType='lmPassword',
                                              vals=['XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX']),
            ]),
            )

    def testPasswordSettingAll_maybeSamba_WillNotFind(self):
        """LDAPEntry.setPassword(newPasswd=...) changes the password."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPExtendedResponse(resultCode=0,
                                           matchedDN='',
                                           errorMessage='')],
            [pureldap.LDAPSearchResultEntry(objectName='',
                                            attributes=[('objectClass',
                                                         ('foo',
                                                          'bar'))]),
             pureldap.LDAPSearchResultDone(resultCode=0,
                                          matchedDN='',
                                          errorMessage=''),
            ],
	    [pureldap.LDAPModifyResponse(resultCode=0,
                                         matchedDN='',
                                         errorMessage='')],
            )

	o=ldapsyntax.LDAPEntry(client=client, dn='cn=foo,dc=example,dc=com')
        d=o.setPassword(newPasswd='new')
        val = deferredResult(d)

	client.assertSent(
            pureldap.LDAPPasswordModifyRequest(userIdentity='cn=foo,dc=example,dc=com',
                                               newPasswd='new'),
            pureldap.LDAPSearchRequest(baseObject='cn=foo,dc=example,dc=com',
                                       scope=pureldap.LDAP_SCOPE_baseObject,
                                       derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=pureldap.LDAPFilterMatchAll,
                                       attributes=('objectClass',)),
            )

    def testPasswordSettingAll_maybeSamba_WillNotFindAnything(self):
        """LDAPEntry.setPassword(newPasswd=...) changes the password."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPExtendedResponse(resultCode=0,
                                           matchedDN='',
                                           errorMessage='')],
            [
             pureldap.LDAPSearchResultDone(resultCode=0,
                                          matchedDN='',
                                          errorMessage=''),
            ],
	    [pureldap.LDAPModifyResponse(resultCode=0,
                                         matchedDN='',
                                         errorMessage='')],
            )

	o=ldapsyntax.LDAPEntry(client=client, dn='cn=foo,dc=example,dc=com')
        d=o.setPassword(newPasswd='new')

        def checkError(fail):
            fail.trap(ldapsyntax.PasswordSetAggregateError)
            l=fail.value.errors
            assert len(l)==1
            assert len(l[0])==2
            assert l[0][0]=='Samba'
            assert isinstance(l[0][1], failure.Failure)
            l[0][1].trap(ldapsyntax.DNNotPresentError)
            return 'This test run should succeed'

        def chainMustErrback(dummy):
            raise 'Should never get here'
        d.addCallbacks(callback=chainMustErrback, errback=checkError)
        val = deferredResult(d)

        self.assertEquals(val, 'This test run should succeed')

	client.assertSent(
            pureldap.LDAPPasswordModifyRequest(userIdentity='cn=foo,dc=example,dc=com',
                                               newPasswd='new'),
            pureldap.LDAPSearchRequest(baseObject='cn=foo,dc=example,dc=com',
                                       scope=pureldap.LDAP_SCOPE_baseObject,
                                       derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=pureldap.LDAPFilterMatchAll,
                                       attributes=('objectClass',)),
            )


class LDAPSyntaxFetch(unittest.TestCase):
    def testFetch_WithDirtyJournal(self):
        """Trying to fetch attributes with a dirty journal fails."""
        client = LDAPClientTestDriver()
	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com')
        o['x']=['foo']

        self.failUnlessRaises(
            ldapsyntax.ObjectDirtyError,
            o.fetch)

    def testFetch_Empty(self):
        """Fetching attributes for a newly-created object works."""
        client = LDAPClientTestDriver(
            [	pureldap.LDAPSearchResultEntry(objectName='cn=foo,dc=example,dc=com',
                                               attributes=(
            ('foo', ['a']),
            ('bar', ['b', 'c']),
            )),
                pureldap.LDAPSearchResultDone(resultCode=0,
                                              matchedDN='',
                                              errorMessage=''),
                ])
	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com')
        d=o.fetch()
        val = deferredResult(d)

	client.assertSent(pureldap.LDAPSearchRequest(
            baseObject='cn=foo,dc=example,dc=com',
            scope=pureldap.LDAP_SCOPE_baseObject,
            ))

        has=o.keys()
        has.sort()
        want=['foo', 'bar']
        want.sort()
        self.assertEquals(has, want)
        self.assertEquals(o['foo'], ['a'])
        self.assertEquals(o['bar'], ['b', 'c'])

    def testFetch_Prefilled(self):
        """Fetching attributes for a (partially) known object overwrites the old attributes."""
        client = LDAPClientTestDriver(
	    [	pureldap.LDAPSearchResultEntry(objectName='cn=foo,dc=example,dc=com',
                                               attributes=(
            ('foo', ['a']),
            ('bar', ['b', 'c']),
            )),
                pureldap.LDAPSearchResultDone(resultCode=0,
                                              matchedDN='',
                                              errorMessage=''),
                ])
	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
            'foo': ['x'],
            'quux': ['baz', 'xyzzy']
            })
        d=o.fetch()
        val = deferredResult(d)

	client.assertSent(pureldap.LDAPSearchRequest(
            baseObject='cn=foo,dc=example,dc=com',
            scope=pureldap.LDAP_SCOPE_baseObject,
            ))

        has=o.keys()
        has.sort()
        want=['foo', 'bar']
        want.sort()
        self.assertEquals(has, want)
        self.assertEquals(o['foo'], ['a'])
        self.assertEquals(o['bar'], ['b', 'c'])

    def testFetch_Partial(self):
        """Fetching only some of the attributes does not overwrite existing values of different attribute types."""
        client = LDAPClientTestDriver(
	    [	pureldap.LDAPSearchResultEntry(objectName='cn=foo,dc=example,dc=com',
                                               attributes=(
            ('foo', ['a']),
            ('bar', ['b', 'c']),
            )),
                pureldap.LDAPSearchResultDone(resultCode=0,
                                              matchedDN='',
                                              errorMessage=''),
                ])
	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
            'foo': ['x'],
            'quux': ['baz', 'xyzzy']
            })
        d=o.fetch('foo', 'bar', 'thud')
        val = deferredResult(d)

        client.assertSent(pureldap.LDAPSearchRequest(
            baseObject='cn=foo,dc=example,dc=com',
            scope=pureldap.LDAP_SCOPE_baseObject,
            attributes=('foo', 'bar', 'thud'),
            ))

        has=o.keys()
        has.sort()
        want=['foo', 'bar', 'quux']
        want.sort()
        self.assertEquals(has, want)
        self.assertEquals(o['foo'], ['a'])
        self.assertEquals(o['bar'], ['b', 'c'])
        self.assertEquals(o['quux'], ['baz', 'xyzzy'])

    def testCommitAndFetch(self):
	"""Fetching after a commit works."""

        client = LDAPClientTestDriver(
            [	pureldap.LDAPModifyResponse(resultCode=0,
                                            matchedDN='',
                                            errorMessage='')
                ],
            [	pureldap.LDAPSearchResultEntry('cn=foo,dc=example,dc=com',
                                               [('aValue', ['foo', 'bar'])],
                                               ),
                pureldap.LDAPSearchResultDone(resultCode=0),
                ])
	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a'],
	    })

	o['aValue']=['foo', 'bar']
	d=o.commit()
        val = deferredResult(d)
        self.assertIdentical(o, val)

	d=o.fetch('aValue')
        val2 = deferredResult(d)
        self.assertIdentical(o, val2)

        client.assertSent(pureldap.LDAPModifyRequest(
	    object='cn=foo,dc=example,dc=com',
	    modification=[
	    pureldap.LDAPModification_replace(attributeType='aValue',
                                              vals=['foo', 'bar']),
	    ]),
                          pureldap.LDAPSearchRequest(
	    baseObject='cn=foo,dc=example,dc=com',
            scope=pureldap.LDAP_SCOPE_baseObject,
            attributes=['aValue'],
	    ))

class LDAPSyntaxRDNHandling(unittest.TestCase):
    def testRemovingRDNFails(self):
        """Removing RDN fails with CannotRemoveRDNError."""
	o=ldapsyntax.LDAPEntry(client=None, dn='cn=foo,dc=example,dc=com',
                               attributes={
            'objectClass': ['someObjectClass'],
            'cn': ['foo', 'bar', 'baz'],
            'a': ['aValue'],
            })
        o['cn'].remove('bar')
        del o['a']
        self.assertRaises(ldapsyntax.CannotRemoveRDNError,
                          o['cn'].remove,
                          'foo')
        def f():
            del o['cn']
        self.assertRaises(ldapsyntax.CannotRemoveRDNError,
                          f)
        def f():
            o['cn']=['thud']
        self.assertRaises(ldapsyntax.CannotRemoveRDNError,
                          f)

        # TODO maybe this should be ok, it preserves the RDN.
        # For now, disallow it.
        def f():
            o['cn']=['foo']
        self.assertRaises(ldapsyntax.CannotRemoveRDNError,
                          f)

class LDAPSyntaxMove(unittest.TestCase):
    def test_move(self):
        client = LDAPClientTestDriver(
            [	pureldap.LDAPModifyDNResponse(resultCode=0,
                                              matchedDN='',
                                              errorMessage=''),
                ])

	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
	    'objectClass': ['a', 'b'],
            'cn': ['foo'],
	    'aValue': ['a'],
	    })
	d = o.move('cn=bar,ou=somewhere,dc=example,dc=com')
        val = deferredResult(d)

        client.assertSent(pureldap.LDAPModifyDNRequest(
	    entry='cn=foo,dc=example,dc=com',
            newrdn='cn=bar',
            deleteoldrdn=1,
            newSuperior='ou=somewhere,dc=example,dc=com',
            ))

        self.assertEquals(o.dn, 'cn=bar,ou=somewhere,dc=example,dc=com')

class Bind(unittest.TestCase):
    def test_ok(self):
        client = LDAPClientTestDriver(
            [	pureldap.LDAPBindResponse(resultCode=0,
                                          matchedDN=''),
                ])

	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com')
	d = defer.maybeDeferred(o.bind, 's3krit')
        val = deferredResult(d)

        client.assertSent(pureldap.LDAPBindRequest(
	    dn='cn=foo,dc=example,dc=com',
            auth='s3krit'))

        self.assertIdentical(val, o)

    def test_fail(self):
        client = LDAPClientTestDriver(
            [	pureldap.LDAPBindResponse(
            resultCode=ldaperrors.LDAPInvalidCredentials.resultCode,
            matchedDN=''),
                ])

	o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com')
	d = defer.maybeDeferred(o.bind, 's3krit')
        fail = deferredError(d)
        fail.trap(ldaperrors.LDAPInvalidCredentials)
