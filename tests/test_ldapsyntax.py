#!/usr/bin/python

"""
Test cases for ldaptor.protocols.ldap.ldapsyntax module.
"""

import unittest
from ldaptor.protocols.ldap import ldapsyntax
from ldaptor.protocols import pureldap
from twisted.internet import reactor, defer

class DummyLDAPClient:
    pass

class LDAPSyntaxBasics(unittest.TestCase):
    def testCreation(self):
	"""Creating an LDAP object should succeed."""
	o=ldapsyntax.LDAPObject(client=DummyLDAPClient(),
				dn='cn=foo,dc=example,dc=com',
				attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a'],
	    'bValue': ['b'],
	    })
	self.failUnlessEqual(o.dn, 'cn=foo,dc=example,dc=com')
	self.failUnlessEqual(o['objectClass'], ['a', 'b'])
	self.failUnlessEqual(o['aValue'], ['a'])
	self.failUnlessEqual(o['bValue'], ['b'])

class LDAPSyntaxAttributes(unittest.TestCase):
    def testAttributeSetting(self):
	o=ldapsyntax.LDAPObject(client=DummyLDAPClient(),
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
	o=ldapsyntax.LDAPObject(client=DummyLDAPClient(),
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
	o=ldapsyntax.LDAPObject(client=DummyLDAPClient(),
				dn='cn=foo,dc=example,dc=com',
				attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a'],
	    'bValue': ['b'],
	    })
	o['aValue'].add('foo')
	self.failUnlessEqual(o['aValue'], ['a', 'foo'])

    def testAttributeItemDelete(self):
	o=ldapsyntax.LDAPObject(client=DummyLDAPClient(),
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
	o=ldapsyntax.LDAPObject(client=DummyLDAPClient(),
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

    def testUndoAfterCommit(self):
	"""Undo should not undo things that have been commited."""

	class DummyLDAPClient:
	    def queue(self, x, callback):
		callback(pureldap.LDAPModifyResponse(
		    resultCode=0,
		    matchedDN='',
		    errorMessage=''))

	o=ldapsyntax.LDAPObject(
	    client=DummyLDAPClient(),
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
	l=[]
	d.addCallback(l.append)
	d.addBoth(lambda x, r=reactor: r.callLater(0, r.crash))
	reactor.run()
	self.assertEquals(len(l), 1)
	# now the commit is done

	o.undo()
	self.failUnlessEqual(o['aValue'], ['foo', 'bar'])
	self.failUnlessEqual(o['bValue'], ['quux'])
	self.failIf(o.has_key('cValue'))

class LDAPSyntaxAttributesModificationOnWire(unittest.TestCase):
    class DummyLDAPClient:
	def __init__(self):
	    self.sent=[]
	def queue(self, x, callback):
	    self.sent.append(x)
	    callback(pureldap.LDAPModifyResponse(
		resultCode=0,
		matchedDN='',
		errorMessage=''))

    def testAdd(self):
	"""Modify & commit should write the right data to the server."""

	client=self.DummyLDAPClient()

	o=ldapsyntax.LDAPObject(client=client,
				dn='cn=foo,dc=example,dc=com',
				attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a'],
	    })
	o['aValue'].add('newValue')
	o['aValue'].add('anotherNewValue')

	d=o.commit()
	l=[]
	d.addCallback(l.append)
	d.addBoth(lambda x, r=reactor: r.callLater(0, r.crash))
	reactor.run()
	self.assertEquals(len(l), 1)
	# now the commit is done

	shouldBeSent = [pureldap.LDAPModifyRequest(
	    object='cn=foo,dc=example,dc=com',
	    modification=[
	    pureldap.LDAPModification_add(vals=(('aValue',
						 ['newValue']),)),
	    pureldap.LDAPModification_add(vals=(('aValue',
						 ['anotherNewValue']),)),
	    ])]
	self.assertEquals(client.sent, shouldBeSent)

	sentStr = ''.join([str(x) for x in client.sent])
	shouldBeSentStr = ''.join([str(x) for x in shouldBeSent])
	self.assertEquals(sentStr, shouldBeSentStr)

    def testDeleteAttribute(self):
	"""Modify & commit should write the right data to the server."""

	client=self.DummyLDAPClient()

	o=ldapsyntax.LDAPObject(client=client,
				dn='cn=foo,dc=example,dc=com',
				attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a'],
	    })
	o['aValue'].remove('a')

	d=o.commit()
	l=[]
	d.addCallback(l.append)
	d.addBoth(lambda x, r=reactor: r.callLater(0, r.crash))
	reactor.run()
	self.assertEquals(len(l), 1)
	# now the commit is done

	shouldBeSent = [pureldap.LDAPModifyRequest(
	    object='cn=foo,dc=example,dc=com',
	    modification=[
	    pureldap.LDAPModification_delete(vals=(('aValue',
						    ['a']),)),
	    ])]
	self.assertEquals(client.sent, shouldBeSent)

	sentStr = ''.join([str(x) for x in client.sent])
	shouldBeSentStr = ''.join([str(x) for x in shouldBeSent])
	self.assertEquals(sentStr, shouldBeSentStr)


    def testDeleteAllAttribute(self):
	"""Modify & commit should write the right data to the server."""

	client=self.DummyLDAPClient()

	o=ldapsyntax.LDAPObject(client=client,
				dn='cn=foo,dc=example,dc=com',
				attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a1', 'a2'],
	    'bValue': ['b1', 'b2'],
	    })
	del o['aValue']
	o['bValue'].clear()

	d=o.commit()
	l=[]
	d.addCallback(l.append)
	d.addBoth(lambda x, r=reactor: r.callLater(0, r.crash))
	reactor.run()
	self.assertEquals(len(l), 1)
	# now the commit is done

	shouldBeSent = [pureldap.LDAPModifyRequest(
	    object='cn=foo,dc=example,dc=com',
	    modification=[
	    pureldap.LDAPModification_delete(vals=(('aValue',),)),
	    pureldap.LDAPModification_delete(vals=(('bValue',),)),
	    ])]
	self.assertEquals(client.sent, shouldBeSent)

	sentStr = ''.join([str(x) for x in client.sent])
	shouldBeSentStr = ''.join([str(x) for x in shouldBeSent])
	self.assertEquals(sentStr, shouldBeSentStr)


    def testReplaceAttributes(self):
	"""Modify & commit should write the right data to the server."""

	client=self.DummyLDAPClient()

	o=ldapsyntax.LDAPObject(client=client,
				dn='cn=foo,dc=example,dc=com',
				attributes={
	    'objectClass': ['a', 'b'],
	    'aValue': ['a'],
	    })
	o['aValue']=['foo', 'bar']

	d=o.commit()
	l=[]
	d.addCallback(l.append)
	d.addBoth(lambda x, r=reactor: r.callLater(0, r.crash))
	reactor.run()
	self.assertEquals(len(l), 1)
	# now the commit is done

	shouldBeSent = [pureldap.LDAPModifyRequest(
	    object='cn=foo,dc=example,dc=com',
	    modification=[
	    pureldap.LDAPModification_replace(vals=(('aValue',
						     ['foo', 'bar']),)),
	    ])]
	self.assertEquals(client.sent, shouldBeSent)

	sentStr = ''.join([str(x) for x in client.sent])
	shouldBeSentStr = ''.join([str(x) for x in shouldBeSent])
	self.assertEquals(sentStr, shouldBeSentStr)


class LDAPSyntaxSearch(unittest.TestCase):
    def testSearch(self):
	"""Test searches."""

	class DummyLDAPClient:
	    sent=''
	    def queue(self, x, callback):
		self.sent = self.sent + str(x)

		r=callback(pureldap.LDAPSearchResultEntry(
		    objectName='cn=foo,dc=example,dc=com',
		    attributes=(
		    ('foo', ['a']),
		    ('bar', ['b', 'c']),
		    ),
		    ))
		assert r==0

		r=callback(pureldap.LDAPSearchResultEntry(
		    objectName='cn=bar,dc=example,dc=com',
		    attributes=(
		    ('foo', ['a']),
		    ('bar', ['d', 'e']),
		    ),
		    ))
		assert r==0

		r=callback(pureldap.LDAPSearchResultDone(
		    resultCode=0,
		    matchedDN='',
		    errorMessage=''))
		assert r==1

	client=DummyLDAPClient()

	o=ldapsyntax.LDAPObject(client=client,
				dn='dc=example,dc=com',
				attributes={
	    'objectClass': ['organizationalUnit'],
	    })

	d=o.search(filterText='(foo=a)',
		   attributes=['foo', 'bar'])
	l=[]
	d.addCallback(l.append)
	d.addBoth(lambda x, r=reactor: r.callLater(0, r.crash))
	reactor.run()
	self.assertEquals(len(l), 1)
	# now the search is done

	self.failUnlessEqual(
	    client.sent,
	    str(pureldap.LDAPSearchRequest(
	    baseObject='dc=example,dc=com',
	    scope=pureldap.LDAP_SCOPE_wholeSubtree,
	    derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
	    sizeLimit=0,
	    timeLimit=0,
	    typesOnly=0,
	    filter=pureldap.LDAPFilter_equalityMatch(
		attributeDesc=pureldap.LDAPAttributeDescription(value='foo'),
		assertionValue=pureldap.LDAPAssertionValue(value='a')),
	    attributes=['foo', 'bar'])))
	self.failUnlessEqual(len(l), 1)
	self.failUnlessEqual(len(l[0]), 2)

	self.failUnlessEqual(l[0][0],
			     ldapsyntax.LDAPObject(
	    client=client,
	    dn='cn=foo,dc=example,dc=com',
	    attributes={
	    'foo': ['a'],
	    'bar': ['b', 'c'],
	    }))

	self.failUnlessEqual(l[0][1],
			     ldapsyntax.LDAPObject(
	    client=client,
	    dn='cn=bar,dc=example,dc=com',
	    attributes={
	    'foo': ['a'],
	    'bar': ['d', 'e'],
	    }))

    def testSearch_ImmediateProcessing(self):
	"""Test searches with the immediate processing feature."""

	class DummyLDAPClient:
	    sent=''
	    def queue(self, x, callback):
		self.sent = self.sent+str(x)
		callback(pureldap.LDAPSearchResultEntry(
		    objectName='cn=foo,dc=example,dc=com',
		    attributes=(
		    ('bar', ['b', 'c']),
		    ),
		    ))
		callback(pureldap.LDAPSearchResultEntry(
		    objectName='cn=bar,dc=example,dc=com',
		    attributes=(
		    ('bar', ['b', 'c']),
		    ),
		    ))
		callback(pureldap.LDAPSearchResultDone(
		    resultCode=0,
		    matchedDN='',
		    errorMessage=''))

	client=DummyLDAPClient()

	o=ldapsyntax.LDAPObject(client=client,
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
	l=[]
	d.addCallback(l.append)
	d.addBoth(lambda x, r=reactor: r.callLater(0, r.crash))
	reactor.run()
	self.assertEquals(len(l), 1)
	# now the commit is done

	self.assertEquals(l[0], None)

	self.failUnlessEqual(
	    client.sent,
	    str(pureldap.LDAPSearchRequest(
	    baseObject='dc=example,dc=com',
	    scope=pureldap.LDAP_SCOPE_wholeSubtree,
	    derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
	    sizeLimit=0,
	    timeLimit=0,
	    typesOnly=0,
	    filter=pureldap.LDAPFilter_equalityMatch(
		attributeDesc=pureldap.LDAPAttributeDescription(value='foo'),
		assertionValue=pureldap.LDAPAssertionValue(value='a')),
	    attributes=['bar'])))

	self.failUnlessEqual(seen,
			     [
	    ldapsyntax.LDAPObject(
	    client=client,
	    dn='cn=foo,dc=example,dc=com',
	    attributes={
	    'bar': ['b', 'c'],
	    }),
	    ldapsyntax.LDAPObject(
	    client=client,
	    dn='cn=bar,dc=example,dc=com',
	    attributes={
	    'bar': ['b', 'c'],
	    })])

class LDAPSyntaxDNs(unittest.TestCase):
    def testDNKeyExistenceSuccess(self):
	ldapsyntax.LDAPObject(client=DummyLDAPClient(),
			      dn='cn=foo,dc=example,dc=com',
			      attributes={
	    'cn': ['foo'],
	    })

    def TODOtestDNKeyExistenceFailure(self):
	self.failUnlessRaises(ldapsyntax.DNNotPresentError,
			      ldapsyntax.LDAPObject,
			      client=DummyLDAPClient(),
			      dn='cn=foo,dc=example,dc=com',
			      attributes={
	    'foo': ['bar'],
	    })

class LDAPSyntaxLDIF(unittest.TestCase):
    def testLDIFConversion(self):
	class DummyLDAPClient:
	    pass
	o=ldapsyntax.LDAPObject(client=DummyLDAPClient(),
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

if __name__ == '__main__':
    unittest.main()
