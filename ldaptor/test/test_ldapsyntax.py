"""
Test cases for ldaptor.protocols.ldap.ldapsyntax module.
"""

from twisted.trial import unittest
from ldaptor import config, testutil, delta
from ldaptor.protocols.ldap import ldapclient, ldapsyntax, ldaperrors
from ldaptor.protocols import pureldap, pureber
from twisted.internet import defer
from twisted.internet import error
from twisted.python import failure
from ldaptor.testutil import LDAPClientTestDriver

class LDAPEntryTests(unittest.TestCase):
    """
    Unit tests for LDAPEntry.
    """

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
        self.failUnlessEqual(o.dn.getText(), u'cn=foo,dc=example,dc=com')
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
            assert k not in seen
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
            assert k not in seen
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

    def testInequalityOtherObject(self):
        """
        It is not equal with non LDAPEntry objects.
        """
        client = LDAPClientTestDriver()
        sut = ldapsyntax.LDAPEntry(
            client=client,
            dn='dc=example,dc=com',
            )

        self.assertNotEqual('dc=example,dc=com', sut)

    def testInequalityDN(self):
        """
        Entries with different DN are not equal.
        """
        client = LDAPClientTestDriver()
        first = ldapsyntax.LDAPEntry(
            client=client,
            dn='dc=example,dc=com',
            )
        second = ldapsyntax.LDAPEntry(
            client=client,
            dn='dc=example,dc=org',
            )

        self.assertNotEqual(first, second)

    def testInequalityAttributes(self):
        """
        Entries with same DN but different attributes are not equal.
        """
        client = LDAPClientTestDriver()
        first = ldapsyntax.LDAPEntry(
            client=client,
            dn='dc=example,dc=com',
            attributes={'attr_key1': ['some-value']},
            )
        second = ldapsyntax.LDAPEntry(
            client=client,
            dn='dc=example,dc=com',
            attributes={'attr_key2': ['some-value']},
            )

        self.assertNotEqual(first, second)

    def testInequalityValues(self):
        """
        Entries with same DN same attributes, but different
        values for attributes are not equal.
        """
        client = LDAPClientTestDriver()
        first = ldapsyntax.LDAPEntry(
            client=client,
            dn='dc=example,dc=com',
            attributes={'attr_key1': ['some-value']},
            )
        second = ldapsyntax.LDAPEntry(
            client=client,
            dn='dc=example,dc=com',
            attributes={'attr_key1': ['other-value']},
            )

        self.assertNotEqual(first, second)

    def testEquality(self):
        """
        Entries with same DN, same attributes, and same values for
        attributes equal, regardless of the order of the attributes.
        """
        client = LDAPClientTestDriver()
        first = ldapsyntax.LDAPEntry(
            client=client,
            dn='dc=example,dc=com',
            attributes={
                'attr_key1': ['some-value'],
                'attr_key2': ['second-value'],
                },
            )
        second = ldapsyntax.LDAPEntry(
            client=client,
            dn='dc=example,dc=com',
            attributes={
                'attr_key2': ['second-value'],
                'attr_key1': ['some-value'],
                },
            )

        self.assertEqual(first, second)

    def testHashEqual(self):
        """
        Entries which are equal have the same hash.
        """
        client = LDAPClientTestDriver()
        first = ldapsyntax.LDAPEntry(
            client=client,
            dn='dc=example,dc=com',
            )
        second = ldapsyntax.LDAPEntry(
            client=client,
            dn='dc=example,dc=com',
            )

        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))

    def testHashNotEqual(self):
        """
        Entries which are not equal have different hash values.
        """
        client = LDAPClientTestDriver()
        first = ldapsyntax.LDAPEntry(
            client=client,
            dn='dc=example,dc=com',
            )
        second = ldapsyntax.LDAPEntry(
            client=client,
            dn='dc=example,dc=org',
            )

        self.assertNotEqual(first, second)
        self.assertNotEqual(hash(first), hash(second))


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
        self.failIf('aValue' in o)
        self.failIf('bValue' in o)

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
        def cb(dummy):
            self.failUnlessEqual(o['aValue'], ['a', 'newValue', 'anotherNewValue'])
            self.failUnlessEqual(o['bValue'], ['b'])
            self.failUnlessEqual(o['cValue'], ['c'])
            client.assertSent(delta.ModifyOp('cn=foo,dc=example,dc=com', [
                delta.Add('aValue', ['newValue', 'anotherNewValue']),
                ]).asLDAP())
        d.addCallback(cb)
        return d

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
        def cb(dummy):
            o.undo()
            self.failUnlessEqual(o['aValue'], ['foo', 'bar'])
            self.failUnlessEqual(o['bValue'], ['quux'])
            self.failIf('cValue' in o)
        d.addCallback(cb)
        return d

class LDAPSyntaxAttributesModificationOnWire(unittest.TestCase):
    def testAdd(self):
        """Modify & commit should write the right data to the server."""

        client = LDAPClientTestDriver(
            [   pureldap.LDAPModifyResponse(resultCode=0,
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
        def cb(dummy):
            client.assertSent(delta.ModifyOp('cn=foo,dc=example,dc=com', [
                delta.Add('aValue', ['newValue', 'anotherNewValue']),
                ]).asLDAP())
        d.addCallback(cb)
        return d

    def testAddSeparate(self):
        """Modify & commit should write the right data to the server."""

        client = LDAPClientTestDriver(
            [   pureldap.LDAPModifyResponse(resultCode=0,
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
        def cb(dummy):
            client.assertSent(delta.ModifyOp('cn=foo,dc=example,dc=com', [
                delta.Add('aValue', ['newValue']),
                delta.Add('aValue', ['anotherNewValue']),
                ]).asLDAP())
        d.addCallback(cb)
        return d

    def testDeleteAttribute(self):
        """Modify & commit should write the right data to the server."""

        client = LDAPClientTestDriver(
            [   pureldap.LDAPModifyResponse(resultCode=0,
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
        def cb(dummy):
            client.assertSent(delta.ModifyOp('cn=foo,dc=example,dc=com', [
                delta.Delete('aValue', ['a']),
                ]).asLDAP())
        d.addCallback(cb)
        return d

    def testDeleteAllAttribute(self):
        """Modify & commit should write the right data to the server."""

        client = LDAPClientTestDriver(
            [   pureldap.LDAPModifyResponse(resultCode=0,
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
        def cb(dummy):
            client.assertSent(delta.ModifyOp('cn=foo,dc=example,dc=com', [
                delta.Delete('aValue'),
                delta.Delete('bValue'),
                ]).asLDAP())
        d.addCallback(cb)
        return d


    def testReplaceAttributes(self):
        """Modify & commit should write the right data to the server."""

        client = LDAPClientTestDriver(
            [   pureldap.LDAPModifyResponse(resultCode=0,
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
        def cb(dummy):
            client.assertSent(delta.ModifyOp('cn=foo,dc=example,dc=com', [
                delta.Replace('aValue', ['foo', 'bar']),
                ]).asLDAP())
        d.addCallback(cb)
        return d


class LDAPSyntaxSearch(unittest.TestCase):
    timeout = 3

    def _test_search(self, return_controls=False):
        """
        Create a test search.
        Return Deferred with no handler.
        """
        client=LDAPClientTestDriver([
            pureldap.LDAPSearchResultEntry(
                objectName='cn=foo,dc=example,dc=com',
                attributes=(
                    ('foo', ['a']),
                    ('bar', ['b', 'c']),
                ),
            ),
            pureldap.LDAPSearchResultEntry(
                objectName='cn=bar,dc=example,dc=com',
                attributes=(
                    ('foo', ['a']),
                    ('bar', ['d', 'e']),
                ),
            ),
            pureldap.LDAPSearchResultDone(
                resultCode=0,
                matchedDN='',
                errorMessage='')
            ])
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn='dc=example,dc=com',
            attributes={
                'objectClass': ['organizationalUnit'],
            }
        )
        d = o.search(
            filterText='(foo=a)',
            attributes=['foo', 'bar'],
            return_controls=return_controls)

        def cb(val):
            if return_controls:
                val = val[0]
            client.assertSent(
                pureldap.LDAPSearchRequest(
                    baseObject='dc=example,dc=com',
                    scope=pureldap.LDAP_SCOPE_wholeSubtree,
                    derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
                    sizeLimit=0,
                    timeLimit=0,
                    typesOnly=0,
                    filter=pureldap.LDAPFilter_equalityMatch(
                        attributeDesc=pureldap.LDAPAttributeDescription(value='foo'),
                        assertionValue=pureldap.LDAPAssertionValue(value='a')
                    ),
                    attributes=['foo', 'bar']
                )
            )
            self.failUnlessEqual(len(val), 2)
            self.failUnlessEqual(
                val[0],
                ldapsyntax.LDAPEntry(
                    client=client,
                    dn='cn=foo,dc=example,dc=com',
                    attributes={
                        b'foo': [b'a'],
                        b'bar': [b'b', b'c'],
                    }
                )
            )
            self.failUnlessEqual(
                val[1],
                ldapsyntax.LDAPEntry(
                    client=client,
                    dn='cn=bar,dc=example,dc=com',
                    attributes={
                        b'foo': [b'a'],
                        b'bar': [b'd', b'e'],
                    }
                )
            )

        d.addCallback(cb)
        return d

    def testSearch(self):
        """Test searches."""
        return self._test_search()

    def test_search_not_connected(self):
        client = ldapclient.LDAPClient()
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn='dc=example,dc=com',
            attributes={
                'objectClass': ['organizationalUnit'],
            }
        )
        d = o.search(
            filterText='(foo=a)',
            attributes=['foo', 'bar'])

        def cb_(thing):
            self.assertEqual(
                ldapclient.LDAPClientConnectionLostException,
                type(thing.value))

        d.addErrback(cb_)
        return d
        

    def test_search_controls_returned(self):
        return self._test_search(return_controls=True)

    def test_search_size_limit_exceeded(self):
        client=LDAPClientTestDriver([
            pureldap.LDAPSearchResultEntry(
                objectName='cn=foo,dc=example,dc=com',
                attributes=(
                    ('foo', ['a']),
                    ('bar', ['b', 'c']),
                ),
            ),
            pureldap.LDAPSearchResultDone(
                resultCode=ldaperrors.LDAPSizeLimitExceeded.resultCode,
                matchedDN='',
                errorMessage='Size limit exceeded.')
            ])
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn='dc=example,dc=com',
            attributes={
                'objectClass': ['organizationalUnit'],
            }
        )
        d = o.search(
            filterText='(foo=a)',
            attributes=['foo', 'bar'],
            sizeLimit=1,
            return_controls=False)

        def cb_(thing):
            self.failUnlessEqual(len(thing), 1)

        d.addCallback(cb_)
        d.addErrback(cb_)
        return d

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
        def cb(val):
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
                b'foo': [b'a'],
                b'bar': [b'b', b'c'],
                }))
            self.failUnless(val[0].complete)

            self.failUnlessEqual(val[1],
                                 ldapsyntax.LDAPEntry(
                client=client,
                dn='cn=bar,dc=example,dc=com',
                attributes={
                b'foo': [b'a'],
                b'bar': [b'd', b'e'],
                }))
            self.failUnless(val[1].complete)
        d.addCallback(cb)
        return d

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
        def cb(val):
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
        d.addCallback(cb)
        return d

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
        def cb(val):
            self.assertEqual(val, None)

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
                b'bar': [b'b', b'c'],
                }),
                ldapsyntax.LDAPEntry(
                client=client,
                dn='cn=bar,dc=example,dc=com',
                attributes={
                b'bar': [b'b', b'c'],
                })])
        d.addCallback(cb)
        return d

    def testSearch_fail(self):
        client=LDAPClientTestDriver([
            pureldap.LDAPSearchResultDone(
            resultCode=ldaperrors.LDAPBusy.resultCode,
            matchedDN='',
            errorMessage='Go away')
            ])

        o=ldapsyntax.LDAPEntry(client=client, dn='dc=example,dc=com')
        d=o.search(filterText='(foo=a)')
        def eb(fail):
            fail.trap(ldaperrors.LDAPBusy)
            self.assertEqual(fail.value.message, 'Go away')

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
        d.addCallbacks(testutil.mustRaise, eb)
        return d

    def testSearch_err(self):
        client=LDAPClientTestDriver([
                failure.Failure(error.ConnectionLost())
                ])
        o = ldapsyntax.LDAPEntry(client=client, dn='dc=example,dc=com')
        d = o.search(filterText='(foo=a)')
        def eb(fail):
            fail.trap(error.ConnectionLost)
        d.addCallbacks(testutil.mustRaise, eb)
        return d

class LDAPSyntaxDNs(unittest.TestCase):
    def testDNKeyExistenceSuccess(self):
        client = LDAPClientTestDriver()
        ldapsyntax.LDAPEntry(client=client,
                             dn='cn=foo,dc=example,dc=com',
                             attributes={
            'cn': ['foo'],
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
        self.failUnlessEqual(o.toWire(),
                             b'''dn: cn=foo,dc=example,dc=com
objectClass: a
objectClass: b
aValue: a
aValue: b
bValue: c

''')


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
        def cb(dummy):
            self.failUnlessRaises(
                ldapsyntax.ObjectDeletedError,
                o.search,
                filterText='(foo=a)')
            self.failUnlessRaises(
                ldapsyntax.ObjectDeletedError,
                o.get,
                'objectClass')
        d.addCallback(cb)
        return d

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
        def cb(dummy):
            client.assertSent(pureldap.LDAPDelRequest(
                entry='cn=foo,dc=example,dc=com',
                ))
        d.addCallback(cb)
        return d

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
        def eb(fail):
            fail.trap(ldaperrors.LDAPBusy)
            self.assertEqual(fail.value.message, 'Go away')

            client.assertSent(pureldap.LDAPDelRequest(
                entry='cn=foo,dc=example,dc=com',
                ))
        d.addCallbacks(testutil.mustRaise, eb)
        return d

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
        def eb(fail):
            fail.trap(ldaperrors.LDAPProtocolError)
            self.assertEqual(fail.value.message, 'Unknown request')

            client.assertSent(pureldap.LDAPDelRequest(
                entry='cn=foo,dc=example,dc=com',
                ))
        d.addCallbacks(testutil.mustRaise, eb)
        return d

class LDAPSyntaxAddChild(unittest.TestCase):
    def testAddChildOnWire(self):
        """LDAPEntry.addChild should write the right data to the server."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPAddResponse(resultCode=0,
                                      matchedDN='',
                                      errorMessage=''),
             ])
        sut = ldapsyntax.LDAPEntry(
            client=client,
            dn='ou=things,dc=example,dc=com',
            attributes={
                'objectClass': ['organizationalUnit'],
                'ou': ['things'],
                },
            )
        d = sut.addChild(
            rdn='givenName=Firstname+surname=Lastname',
            attributes={
                'objectClass': ['person', 'otherStuff'],
                'givenName': ['Firstname'],
                'surname': ['Lastname'],
                },
            )
        self.successResultOf(d)

        client.assertSent(pureldap.LDAPAddRequest(
            entry='givenName=Firstname+surname=Lastname,ou=things,dc=example,dc=com',
            attributes=[
                (
                    pureldap.LDAPAttributeDescription('objectClass'),
                    pureber.BERSet([
                        pureldap.LDAPAttributeValue('person'),
                        pureldap.LDAPAttributeValue('otherStuff'),
                        ]),
                    ),
                (
                    pureldap.LDAPAttributeDescription('givenName'),
                    pureber.BERSet([pureldap.LDAPAttributeValue('Firstname')])),
                    (
                        pureldap.LDAPAttributeDescription('surname'),
                        pureber.BERSet([pureldap.LDAPAttributeValue('Lastname')],
                            ),
                        ),
            ],
            ))


class LDAPSyntaxContainingNamingContext(unittest.SynchronousTestCase):
    def setUp(self):
        attributes = [
            (
                'namingContexts',
                (
                    'dc=foo,dc=example',
                    'dc=example,dc=com',
                    'dc=bar,dc=example',
                )
            )
        ]
        self.client = LDAPClientTestDriver([
            pureldap.LDAPSearchResultEntry(objectName='', attributes=attributes),
            pureldap.LDAPSearchResultDone(resultCode=0, matchedDN='', errorMessage='')
        ])

    def testNamingContext(self):
        """LDAPEntry.namingContext returns the naming context that contains this object (via a Deferred)."""
        o = ldapsyntax.LDAPEntry(
            client=self.client,
            dn='cn=foo,ou=bar,dc=example,dc=com',
            attributes={'objectClass': ['a']}
        )
        d = o.namingContext()
        def cb(p):
            assert isinstance(p, ldapsyntax.LDAPEntry)
            assert p.client == o.client
            assert p.dn.getText() == u'dc=example,dc=com'

            self.client.assertSent(pureldap.LDAPSearchRequest(
                baseObject='',
                scope=pureldap.LDAP_SCOPE_baseObject,
                filter=pureldap.LDAPFilter_present('objectClass'),
                attributes=['namingContexts'],
                ))
        d.addCallback(cb)
        return d

    def testNoContainingNamingContext(self):
        """LDAPEntry.namingContext raises exception if there are no naming contexts with it"""
        o = ldapsyntax.LDAPEntry(
            client=self.client,
            dn='cn=foo,dc=foo,dc=com',
            attributes={'objectClass': ['a']}
        )
        fail = self.failureResultOf(o.namingContext())
        self.assertIsInstance(fail.value, ldapsyntax.NoContainingNamingContext)


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
        d=o.setPassword_ExtendedOperation(newPasswd=b'new')
        def cb(dummy):
            client.assertSent(pureldap.LDAPPasswordModifyRequest(
                userIdentity='cn=foo,dc=example,dc=com',
                newPasswd=b'new'),
                              )
        d.addCallback(cb)
        return d

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
        d=o.setPassword_Samba(newPasswd=b'new', style='sambaAccount')
        def cb(dummy):
            client.assertSent(delta.ModifyOp('cn=foo,dc=example,dc=com', [
                delta.Replace('ntPassword',
                              ['89963F5042E5041A59C249282387A622']),
                delta.Replace('lmPassword',
                              ['XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX']),
                ]).asLDAP())
        d.addCallback(cb)
        return d

    def testPasswordSetting_Samba_sambaSamAccount(self):
        """LDAPEntry.setPassword_Samba(newPasswd=..., style='sambaSamAccount') changes the password."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPModifyResponse(resultCode=0,
                                         matchedDN='',
                                         errorMessage='')],
            )

        o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com')
        d=o.setPassword_Samba(newPasswd=b'new', style='sambaSamAccount')
        def cb(dummy):
            client.assertSent(delta.ModifyOp('cn=foo,dc=example,dc=com', [
                delta.Replace('sambaNTPassword',
                              ['89963F5042E5041A59C249282387A622']),
                delta.Replace('sambaLMPassword',
                              ['XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX']),
                ]).asLDAP())
        d.addCallback(cb)
        return d

    def testPasswordSetting_Samba_defaultStyle(self):
        """LDAPEntry.setPassword_Samba(newPasswd=...) changes the password."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPModifyResponse(resultCode=0,
                                         matchedDN='',
                                         errorMessage='')],
            )

        o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com')
        d=o.setPassword_Samba(newPasswd=b'new')
        def cb(dummy):
            client.assertSent(delta.ModifyOp('cn=foo,dc=example,dc=com', [
                delta.Replace('sambaNTPassword',
                              ['89963F5042E5041A59C249282387A622']),
                            delta.Replace('sambaLMPassword',
                                          ['XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX']),
                ]).asLDAP())
        d.addCallback(cb)
        return d

    def testPasswordSetting_Samba_badStyle(self):
        """LDAPEntry.setPassword_Samba(..., style='foo') fails."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPModifyResponse(resultCode=0,
                                         matchedDN='',
                                         errorMessage='')],
            )

        o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com')
        d=defer.maybeDeferred(o.setPassword_Samba, newPasswd=b'new', style='foo')
        def eb(fail):
            fail.trap(RuntimeError)
            self.assertEqual(fail.getErrorMessage(),
                              "Unknown samba password style 'foo'")
            client.assertNothingSent()
        d.addCallbacks(testutil.mustRaise, eb)
        return d

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
        d=o.setPassword(newPasswd=b'new')
        def cb(dummy):
            client.assertSent(pureldap.LDAPPasswordModifyRequest(
                userIdentity='cn=foo,dc=example,dc=com',
                newPasswd=b'new'),
                              )
        d.addCallback(cb)
        return d


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
        d=o.setPassword(newPasswd=b'new')
        def cb(dummy):
            client.assertSent(pureldap.LDAPPasswordModifyRequest(
                userIdentity='cn=foo,dc=example,dc=com',
                newPasswd=b'new'),
                              delta.ModifyOp('cn=foo,dc=example,dc=com', [
                delta.Replace('ntPassword',
                              ['89963F5042E5041A59C249282387A622']),
                delta.Replace('lmPassword',
                              ['XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX']),
                ]).asLDAP())
        d.addCallback(cb)
        return d


    def testPasswordSettingAll_hasSambaSam(self):
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
            'objectClass': ['foo', 'sambaSamAccount'],
            },
                               complete=1)
        d=o.setPassword(newPasswd=b'new')
        def cb(dummy):
            client.assertSent(pureldap.LDAPPasswordModifyRequest(
                userIdentity='cn=foo,dc=example,dc=com',
                newPasswd=b'new'),
                              delta.ModifyOp('cn=foo,dc=example,dc=com', [
                delta.Replace('sambaNTPassword',
                              ['89963F5042E5041A59C249282387A622']),
                delta.Replace('sambaLMPassword',
                              ['XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX']),
                ]).asLDAP())
        d.addCallback(cb)
        return d


    def testPasswordSettingAll_hasSamba_differentCase(self):
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
            'objectClass': ['foo', 'saMBaAccOuNT'],
            },
                               complete=1)
        d=o.setPassword(newPasswd=b'new')
        def cb(dummy):
            client.assertSent(pureldap.LDAPPasswordModifyRequest(
                userIdentity='cn=foo,dc=example,dc=com',
                newPasswd=b'new'),
                              delta.ModifyOp('cn=foo,dc=example,dc=com', [
                delta.Replace('ntPassword',
                              ['89963F5042E5041A59C249282387A622']),
                delta.Replace('lmPassword',
                              ['XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX']),
                ]).asLDAP())
        d.addCallback(cb)
        return d


    def testPasswordSettingAll_hasSambaSam_differentCase(self):
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
            'objectClass': ['foo', 'sAmbASAmaccoUnt'],
            },
                               complete=1)
        d=o.setPassword(newPasswd=b'new')
        def cb(dummy):
            client.assertSent(pureldap.LDAPPasswordModifyRequest(
                userIdentity='cn=foo,dc=example,dc=com',
                newPasswd=b'new'),
                              delta.ModifyOp('cn=foo,dc=example,dc=com', [
                delta.Replace('sambaNTPassword',
                              ['89963F5042E5041A59C249282387A622']),
                delta.Replace('sambaLMPassword',
                              ['XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX']),
                ]).asLDAP())
        d.addCallback(cb)
        return d


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
        d=o.setPassword(newPasswd=b'new')
        def cb(dummy):
            client.assertSent(
                pureldap.LDAPPasswordModifyRequest(userIdentity='cn=foo,dc=example,dc=com',
                                                   newPasswd=b'new'),
                pureldap.LDAPSearchRequest(baseObject='cn=foo,dc=example,dc=com',
                                           scope=pureldap.LDAP_SCOPE_baseObject,
                                           derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
                                           sizeLimit=0,
                                           timeLimit=0,
                                           typesOnly=0,
                                           filter=pureldap.LDAPFilterMatchAll,
                                           attributes=('objectClass',)),
                delta.ModifyOp('cn=foo,dc=example,dc=com', [
                delta.Replace('ntPassword', ['89963F5042E5041A59C249282387A622']),
                delta.Replace('lmPassword', ['XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX']),
                ]).asLDAP(),
                )
        d.addCallback(cb)
        return d

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
        d=o.setPassword(newPasswd=b'new')
        def cb(dummy):
            client.assertSent(
                pureldap.LDAPPasswordModifyRequest(userIdentity='cn=foo,dc=example,dc=com',
                                                   newPasswd=b'new'),
                pureldap.LDAPSearchRequest(baseObject='cn=foo,dc=example,dc=com',
                                           scope=pureldap.LDAP_SCOPE_baseObject,
                                           derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
                                           sizeLimit=0,
                                           timeLimit=0,
                                           typesOnly=0,
                                           filter=pureldap.LDAPFilterMatchAll,
                                           attributes=('objectClass',)),
                )
        d.addCallback(cb)
        return d

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

        o = ldapsyntax.LDAPEntry(client=client, dn='cn=foo,dc=example,dc=com')
        d = o.setPassword(newPasswd=b'new')

        def checkError(fail):
            fail.trap(ldapsyntax.PasswordSetAggregateError)
            l=fail.value.errors
            assert len(l)==1
            assert len(l[0])==2
            assert l[0][0]=='Samba'
            assert isinstance(l[0][1], failure.Failure)
            l[0][1].trap(ldapsyntax.DNNotPresentError)
            return 'All checks are fine'

        d.addErrback(checkError)

        self.assertEqual('All checks are fine', self.successResultOf(d))
        client.assertSent(
            pureldap.LDAPPasswordModifyRequest(userIdentity='cn=foo,dc=example,dc=com',
                                               newPasswd=b'new'),
            pureldap.LDAPSearchRequest(baseObject='cn=foo,dc=example,dc=com',
                                       scope=pureldap.LDAP_SCOPE_baseObject,
                                       derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=pureldap.LDAPFilterMatchAll,
                                       attributes=('objectClass',)),
            )

    def testPasswordSetting_abortsOnFirstError(self):
        """LDAPEntry.setPassword() aborts on first error (does not parallelize, as it used to)."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPExtendedResponse(resultCode=ldaperrors.LDAPInsufficientAccessRights.resultCode,
                                           matchedDN='',
                                           errorMessage='')],
            )

        o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
            'objectClass': ['foo', 'sambaAccount'],
            },
                               complete=1)
        d=o.setPassword(newPasswd=b'new')
        def eb(fail):
            fail.trap(ldapsyntax.PasswordSetAggregateError)
            l=fail.value.errors
            assert len(l)==2

            assert len(l[0])==2
            self.assertEqual(l[0][0], 'ExtendedOperation')
            assert isinstance(l[0][1], failure.Failure)
            l[0][1].trap(ldaperrors.LDAPInsufficientAccessRights)

            assert len(l[1])==2
            self.assertEqual(l[1][0], 'Samba')
            assert isinstance(l[1][1], failure.Failure)
            l[1][1].trap(ldapsyntax.PasswordSetAborted)

            client.assertSent(pureldap.LDAPPasswordModifyRequest(
                userIdentity='cn=foo,dc=example,dc=com',
                newPasswd=b'new'),
                              )
        d.addCallbacks(testutil.mustRaise, eb)
        return d


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
            [   pureldap.LDAPSearchResultEntry(objectName='cn=foo,dc=example,dc=com',
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
        def cb(dummy):
            client.assertSent(pureldap.LDAPSearchRequest(
                baseObject='cn=foo,dc=example,dc=com',
                scope=pureldap.LDAP_SCOPE_baseObject,
                ))

            has=o.keys()
            has.sort()
            want=[b'foo', b'bar']
            want.sort()
            self.assertEqual(has, want)
            self.assertEqual(o['foo'], [b'a'])
            self.assertEqual(o['bar'], [b'b', b'c'])
        d.addCallback(cb)
        return d

    def testFetch_Prefilled(self):
        """Fetching attributes for a (partially) known object overwrites the old attributes."""
        client = LDAPClientTestDriver(
            [   pureldap.LDAPSearchResultEntry(objectName='cn=foo,dc=example,dc=com',
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
        def cb(dummy):
            client.assertSent(pureldap.LDAPSearchRequest(
                baseObject='cn=foo,dc=example,dc=com',
                scope=pureldap.LDAP_SCOPE_baseObject,
                ))

            has=o.keys()
            has.sort()
            want=[b'foo', b'bar']
            want.sort()
            self.assertEqual(has, want)
            self.assertEqual(o['foo'], [b'a'])
            self.assertEqual(o['bar'], [b'b', b'c'])
        d.addCallback(cb)
        return d

    def testFetch_Partial(self):
        """Fetching only some of the attributes does not overwrite existing values of different attribute types."""
        client = LDAPClientTestDriver(
            [   pureldap.LDAPSearchResultEntry(objectName='cn=foo,dc=example,dc=com',
                                               attributes=(
            (b'foo', [b'a']),
            (b'bar', [b'b', b'c']),
            )),
                pureldap.LDAPSearchResultDone(resultCode=0,
                                              matchedDN='',
                                              errorMessage=''),
                ])
        o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com',
                               attributes={
            b'foo': [b'x'],
            b'quux': [b'baz', b'xyzzy']
            })
        d=o.fetch(b'foo', b'bar', b'thud')
        def cb(dummy):
            client.assertSent(pureldap.LDAPSearchRequest(
                baseObject='cn=foo,dc=example,dc=com',
                scope=pureldap.LDAP_SCOPE_baseObject,
                attributes=(b'foo', b'bar', b'thud'),
                ))

            has=o.keys()
            has.sort()
            want=[b'foo', b'bar', b'quux']
            want.sort()
            self.assertEqual(has, want)
            self.assertEqual(o[b'foo'], [b'a'])
            self.assertEqual(o[b'bar'], [b'b', b'c'])
            self.assertEqual(o[b'quux'], [b'baz', b'xyzzy'])
        d.addCallback(cb)
        return d

    def testCommitAndFetch(self):
        """Fetching after a commit works."""

        client = LDAPClientTestDriver(
            [   pureldap.LDAPModifyResponse(resultCode=0,
                                            matchedDN='',
                                            errorMessage='')
                ],
            [   pureldap.LDAPSearchResultEntry('cn=foo,dc=example,dc=com',
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
        d.addCallback(self.assertIdentical, o)

        d.addCallback(lambda _: o.fetch('aValue'))
        d.addCallback(self.assertIdentical, o)

        def cb(dummy):
            client.assertSent(delta.ModifyOp('cn=foo,dc=example,dc=com', [
                delta.Replace('aValue', ['foo', 'bar']),
                ]).asLDAP(),
                              pureldap.LDAPSearchRequest(
                baseObject='cn=foo,dc=example,dc=com',
                scope=pureldap.LDAP_SCOPE_baseObject,
                attributes=['aValue'],
                ))
        d.addCallback(cb)
        return d

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
            [   pureldap.LDAPModifyDNResponse(resultCode=0,
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
        def cb(dummy):
            client.assertSent(pureldap.LDAPModifyDNRequest(
                entry='cn=foo,dc=example,dc=com',
                newrdn='cn=bar',
                deleteoldrdn=1,
                newSuperior='ou=somewhere,dc=example,dc=com',
                ))

            self.assertEqual(o.dn, u'cn=bar,ou=somewhere,dc=example,dc=com')
        d.addCallback(cb)
        return d

class Bind(unittest.TestCase):
    def test_ok(self):
        client = LDAPClientTestDriver(
            [   pureldap.LDAPBindResponse(resultCode=0,
                                          matchedDN=''),
                ])

        o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com')
        d = defer.maybeDeferred(o.bind, 's3krit')
        d.addCallback(self.assertIdentical, o)
        def cb(dummy):
            client.assertSent(pureldap.LDAPBindRequest(
                dn='cn=foo,dc=example,dc=com',
                auth='s3krit'))
        d.addCallback(cb)
        return d

    def test_fail(self):
        client = LDAPClientTestDriver(
            [   pureldap.LDAPBindResponse(
            resultCode=ldaperrors.LDAPInvalidCredentials.resultCode,
            matchedDN=''),
                ])

        o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com')
        d = defer.maybeDeferred(o.bind, 's3krit')
        def eb(fail):
            fail.trap(ldaperrors.LDAPInvalidCredentials)
        d.addCallbacks(testutil.mustRaise, eb)
        return d

    def test_err(self):
        client = LDAPClientTestDriver([
                failure.Failure(error.ConnectionLost())])

        o=ldapsyntax.LDAPEntry(client=client,
                               dn='cn=foo,dc=example,dc=com')
        d = defer.maybeDeferred(o.bind, 'whatever')
        def eb(fail):
            fail.trap(error.ConnectionLost)
        d.addCallbacks(testutil.mustRaise, eb)
        return d
