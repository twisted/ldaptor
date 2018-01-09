# Copyright (C) 2001 Tommi Virtanen
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

"""
Test cases for ldaptor.protocols.pureldap module.
"""

from twisted.trial import unittest
from ldaptor.protocols import pureldap, pureber
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

class KnownValues(unittest.TestCase):
    knownValues=( # class, args, kwargs, expected_result

        (pureldap.LDAPModifyRequest,
         [],
         { "object": 'cn=foo, dc=example, dc=com',
           "modification": [
                      pureber.BERSequence([
                        pureber.BEREnumerated(0),
                        pureber.BERSequence([
                          pureldap.LDAPAttributeDescription('bar'),
                          pureber.BERSet([
                            pureldap.LDAPString('a'),
                            pureldap.LDAPString('b'),
                            ]),
                          ]),
                        ]),
                      ],
           },
         None,
         [0x66, 50]
         + ([0x04, 0x1a] + l("cn=foo, dc=example, dc=com")
            + [0x30, 20]
            + ([0x30, 18]
               + ([0x0a, 0x01, 0x00]
                  + [0x30, 13]
                  + ([0x04, len("bar")] + l("bar")
                     + [0x31, 0x06]
                     + ([0x04, len("a")] + l("a")
                        + [0x04, len("b")] + l("b"))))))
            ),

        (pureldap.LDAPModifyRequest,
         [],
         { "object": 'cn=foo, dc=example, dc=com',
           "modification": [
                      pureber.BERSequence([
                        pureber.BEREnumerated(1),
                        pureber.BERSequence([
                          pureber.BEROctetString('bar'),
                          pureber.BERSet([]),
                          ]),
                        ]),
                      ],
           },
         None,
         [0x66, 0x2c]
         + ([0x04, 0x1a] + l("cn=foo, dc=example, dc=com")
            + [0x30, 0x0e]
            + ([0x30, 0x0c]
               + ([0x0a, 0x01, 0x01]
                  + [0x30, 0x07]
                  + ([0x04, 0x03] + l("bar")
                     + [0x31, 0x00]))))
        ),

        (pureldap.LDAPFilter_not,
         [],
         { "value": pureldap.LDAPFilter_present("foo"),
           },
         pureldap.LDAPBERDecoderContext_Filter(fallback=pureber.BERDecoderContext()),
         [0xa2, 0x05]
         + [0x87]
         + [len("foo")]
         + l("foo")),

        (pureldap.LDAPFilter_or,
         [],
         { "value": [pureldap.LDAPFilter_equalityMatch(
        attributeDesc=pureldap.LDAPAttributeDescription(value='cn'),
        assertionValue=pureldap.LDAPAssertionValue(value='foo')),
                     pureldap.LDAPFilter_equalityMatch(
        attributeDesc=pureldap.LDAPAttributeDescription(value='uid'),
        assertionValue=pureldap.LDAPAssertionValue(value='foo')),
                     ]
           },
         pureldap.LDAPBERDecoderContext_Filter(fallback=pureber.BERDecoderContext()),
         [0xa1, 23]
         + [0xa3, 9]
         + [0x04] + [len("cn")] + l("cn")
         + [0x04] + [len("foo")] + l("foo")
         + [0xa3, 10]
         + [0x04] + [len("uid")] + l("uid")
         + [0x04] + [len("foo")] + l("foo"),
         ),

        (pureldap.LDAPFilter_and,
         [],
         { "value": [pureldap.LDAPFilter_equalityMatch(
        attributeDesc=pureldap.LDAPAttributeDescription(value='cn'),
        assertionValue=pureldap.LDAPAssertionValue(value='foo')),
                     pureldap.LDAPFilter_equalityMatch(
        attributeDesc=pureldap.LDAPAttributeDescription(value='uid'),
        assertionValue=pureldap.LDAPAssertionValue(value='foo')),
                     ]
           },
         pureldap.LDAPBERDecoderContext_Filter(fallback=pureber.BERDecoderContext()),
         [0xa0, 23]
         + [0xa3, 9]
         + [0x04] + [len("cn")] + l("cn")
         + [0x04] + [len("foo")] + l("foo")
         + [0xa3, 10]
         + [0x04] + [len("uid")] + l("uid")
         + [0x04] + [len("foo")] + l("foo"),
         ),

        (pureldap.LDAPModifyDNRequest,
         [],
         {'entry': 'cn=foo,dc=example,dc=com',
          'newrdn': 'uid=bar',
          'deleteoldrdn': 0,
          },
         None,
         [0x6c, 0x26]
         + [0x04]
         + [len("cn=foo,dc=example,dc=com")]
         + l("cn=foo,dc=example,dc=com")
         + [0x04]
         + [len("uid=bar")]
         + l("uid=bar")
         + [0x01, 0x01, 0x00]),

        (pureldap.LDAPModifyDNRequest,
         [],
         {'entry': 'cn=aoue,dc=example,dc=com',
          'newrdn': 'uid=aoue',
          'deleteoldrdn': 0,
          'newSuperior': 'ou=People,dc=example,dc=com',
          },
         None,
         [0x6c, 69]
         + [0x04]
         + [len("cn=aoue,dc=example,dc=com")]
         + l("cn=aoue,dc=example,dc=com")
         + [0x04]
         + [len("uid=aoue")]
         + l("uid=aoue")
         + [0x01, 0x01, 0x00]
         + [0x80]
         + [len("ou=People,dc=example,dc=com")]
         + l("ou=People,dc=example,dc=com")),

        (pureldap.LDAPSearchRequest,
         [],
         {'baseObject': 'dc=yoja,dc=example,dc=com',
          },
         None,
         [0x63, 57]
         + [0x04]
         + [len('dc=yoja,dc=example,dc=com')]
         + l('dc=yoja,dc=example,dc=com')
         # scope
         + [0x0a, 1, 2]
         # derefAliases
         + [0x0a, 1, 0]
         # sizeLimit
         + [0x02, 1, 0]
         # timeLimit
         + [0x02, 1, 0]
         # typesOnly
         + [0x01, 1, 0]
         # filter
         + [135, 11] + l('objectClass')
         # attributes
         + [48, 0]
         ),

        (pureldap.LDAPUnbindRequest,
         [],
         {},
         None,
         [0x42, 0x00]
        ),

        (pureldap.LDAPSearchResultDone,
         [],
         {'resultCode': 0,
          },
         None,
         [0x65, 0x07]
         # resultCode
         + [0x0a, 0x01, 0x00]
         # matchedDN
         + [0x04]
         + [len('')]
         + l('')
         # errorMessage
         + [0x04]
         + [len('')]
         + l('')
         # referral, TODO
         + []
        ),

        (pureldap.LDAPSearchResultDone,
         [],
         {'resultCode': 0,
          'matchedDN': 'dc=foo,dc=example,dc=com',
          },
         None,
         [0x65, 31]
         # resultCode
         + [0x0a, 0x01, 0x00]
         # matchedDN
         + [0x04]
         + [len('dc=foo,dc=example,dc=com')]
         + l('dc=foo,dc=example,dc=com')
         # errorMessage
         + [0x04]
         + [len('')]
         + l('')
         # referral, TODO
         + []
        ),

        (pureldap.LDAPSearchResultDone,
         [],
         {'resultCode': 0,
          'matchedDN': 'dc=foo,dc=example,dc=com',
          'errorMessage': 'the foobar was fubar',
          },
         None,
         [0x65, 51]
         # resultCode
         + [0x0a, 0x01, 0x00]
         # matchedDN
         + [0x04]
         + [len('dc=foo,dc=example,dc=com')]
         + l('dc=foo,dc=example,dc=com')
         # errorMessage
         + [0x04]
         + [len('the foobar was fubar')]
         + l('the foobar was fubar',)
         # referral, TODO
         + []
        ),

        (pureldap.LDAPSearchResultDone,
         [],
         {'resultCode': 0,
          'errorMessage': 'the foobar was fubar',
          },
         None,
         [0x65, 27]
         # resultCode
         + [0x0a, 0x01, 0x00]
         # matchedDN
         + [0x04]
         + [len('')]
         + l('')
         # errorMessage
         + [0x04]
         + [len('the foobar was fubar')]
         + l('the foobar was fubar',)
         # referral, TODO
         + []
        ),

        (pureldap.LDAPMessage,
         [],
         {'id': 42,
          'value': pureldap.LDAPBindRequest(),
          },
         pureldap.LDAPBERDecoderContext_TopLevel(
        inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
        fallback=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext()),
        inherit=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext()))),
         [0x30, 12]
         # id
         + [0x02, 0x01, 42]
         # value
         + l(str(pureldap.LDAPBindRequest()))
         ),

        (pureldap.LDAPControl,
         [],
         {'controlType': '1.2.3.4',
          },
         None,
         [0x30, 9]
         # controlType
         + [0x04, 7]
         + l("1.2.3.4")
         ),

        (pureldap.LDAPControl,
         [],
         {'controlType': '1.2.3.4',
          'criticality': True,
          },
         None,
         [0x30, 12]
         # controlType
         + [0x04, 7]
         + l("1.2.3.4")
         # criticality
         + [0x01, 1, 0xFF]
         ),

        (pureldap.LDAPControl,
         [],
         {'controlType': '1.2.3.4',
          'criticality': True,
          'controlValue': 'silly',
          },
         None,
         [0x30, 19]
         # controlType
         + [0x04, 7]
         + l("1.2.3.4")
         # criticality
         + [0x01, 1, 0xFF]
         # controlValue
         + [0x04, len("silly")]
         + l("silly")
         ),

        (pureldap.LDAPMessage,
         [],
         {'id': 42,
          'value': pureldap.LDAPBindRequest(),
          'controls': [ ('1.2.3.4', None, None),
                        ('2.3.4.5', False),
                        ('3.4.5.6', True, '\x00\x01\x02\xFF'),
                        ('4.5.6.7', None, '\x00\x01\x02\xFF'),
                        ],
          },
         pureldap.LDAPBERDecoderContext_TopLevel(
        inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
        fallback=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext()),
        inherit=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext()))),
         [0x30, 76]
         # id
         + [0x02, 0x01, 42]
         # value
         + l(str(pureldap.LDAPBindRequest()))
         # controls
         + l(str(pureldap.LDAPControls(value=[
        pureldap.LDAPControl(controlType='1.2.3.4'),
        pureldap.LDAPControl(controlType='2.3.4.5',
                             criticality=False),
        pureldap.LDAPControl(controlType='3.4.5.6',
                             criticality=True,
                             controlValue='\x00\x01\x02\xFF'),
        pureldap.LDAPControl(controlType='4.5.6.7',
                             criticality=None,
                             controlValue='\x00\x01\x02\xFF'),
        ]))),
         ),

        (pureldap.LDAPFilter_equalityMatch,
         [],
         {'attributeDesc': pureldap.LDAPAttributeDescription('cn'),
          'assertionValue': pureldap.LDAPAssertionValue('foo'),
          },
         pureldap.LDAPBERDecoderContext_Filter(
        fallback=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext()),
        inherit=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext())),

         [0xa3, 9]
         + ([0x04, 2] + l('cn')
            + [0x04, 3] + l('foo'))
         ),

        (pureldap.LDAPFilter_or,
         [[pureldap.LDAPFilter_equalityMatch(attributeDesc=pureldap.LDAPAttributeDescription('cn'),
                                             assertionValue=pureldap.LDAPAssertionValue('foo')),
           pureldap.LDAPFilter_equalityMatch(attributeDesc=pureldap.LDAPAttributeDescription('uid'),
                                             assertionValue=pureldap.LDAPAssertionValue('foo')),
           pureldap.LDAPFilter_equalityMatch(attributeDesc=pureldap.LDAPAttributeDescription('mail'),
                                             assertionValue=pureldap.LDAPAssertionValue('foo')),
           pureldap.LDAPFilter_substrings(type='mail', substrings=[pureldap.LDAPFilter_substrings_initial('foo@')]),
           ]],
         {},
         pureldap.LDAPBERDecoderContext_Filter(
        fallback=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext()),
        inherit=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext())),

         [0xA1, 52]
         + ([0xa3, 9]
            + ([0x04, 2] + l('cn')
               + [0x04, 3] + l('foo'))
            + [0xa3, 10]
            + ([0x04, 3] + l('uid')
               + [0x04, 3] + l('foo'))
            + [0xa3, 11]
               + ([0x04, 4] + l('mail')
                  + [0x04, 3] + l('foo'))
            + [0xa4, 14]
            + ([0x04, 4] + l('mail')
               + [0x30, 6]
               + ([0x80, 4] + l('foo@'))))
         ),

        (pureldap.LDAPSearchRequest,
         [],
         {'baseObject': 'dc=example,dc=com',
          'scope': pureldap.LDAP_SCOPE_wholeSubtree,
          'derefAliases': pureldap.LDAP_DEREF_neverDerefAliases,
          'sizeLimit': 1,
          'timeLimit': 0,
          'typesOnly': False,
          'filter': pureldap.LDAPFilter_or([
        pureldap.LDAPFilter_equalityMatch(attributeDesc=pureldap.LDAPAttributeDescription('cn'),
                                          assertionValue=pureldap.LDAPAssertionValue('foo')),
        pureldap.LDAPFilter_equalityMatch(attributeDesc=pureldap.LDAPAttributeDescription('uid'),
                                          assertionValue=pureldap.LDAPAssertionValue('foo')),
        pureldap.LDAPFilter_equalityMatch(attributeDesc=pureldap.LDAPAttributeDescription('mail'),
                                          assertionValue=pureldap.LDAPAssertionValue('foo')),
        pureldap.LDAPFilter_substrings(type='mail', substrings=[pureldap.LDAPFilter_substrings_initial('foo@')]),
        ]),
          'attributes': [''],
        },
         pureldap.LDAPBERDecoderContext_LDAPMessage(
        fallback=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext()),
        inherit=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext())),

         [0x63, 92]
         + ([0x04, 17] + l('dc=example,dc=com')
            + [0x0a, 1, 0x02]
            + [0x0a, 1, 0x00]
            + [0x02, 1, 0x01]
            + [0x02, 1, 0x00]
            + [0x01, 1, 0x00]
            + [0xA1, 52]
            + ([0xa3, 9]
               + ([0x04, 2] + l('cn')
                  + [0x04, 3] + l('foo'))
               + [0xa3, 10]
               + ([0x04, 3] + l('uid')
                  + [0x04, 3] + l('foo'))
               + [0xa3, 11]
               + ([0x04, 4] + l('mail')
                  + [0x04, 3] + l('foo'))
               + [0xa4, 14]
               + ([0x04, 4] + l('mail')
                  + [0x30, 6]
                  + ([0x80, 4] + l('foo@'))))
            + [0x30, 2]
            + ([0x04, 0])
            )
         ),

        (pureldap.LDAPMessage,
         [],
         {'id': 1,
          'value': pureldap.LDAPSearchRequest(
        baseObject='dc=example,dc=com',
        scope=pureldap.LDAP_SCOPE_wholeSubtree,
        derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
        sizeLimit=1,
        timeLimit=0,
        typesOnly=False,
        filter=pureldap.LDAPFilter_or([
        pureldap.LDAPFilter_equalityMatch(attributeDesc=pureldap.LDAPAttributeDescription('cn'),
                                          assertionValue=pureldap.LDAPAssertionValue('foo')),
        pureldap.LDAPFilter_equalityMatch(attributeDesc=pureldap.LDAPAttributeDescription('uid'),
                                          assertionValue=pureldap.LDAPAssertionValue('foo')),
        pureldap.LDAPFilter_equalityMatch(attributeDesc=pureldap.LDAPAttributeDescription('mail'),
                                          assertionValue=pureldap.LDAPAssertionValue('foo')),
        pureldap.LDAPFilter_substrings(type='mail', substrings=[pureldap.LDAPFilter_substrings_initial('foo@')]),
        ]),
        attributes=[''],
        ),
          },
         pureldap.LDAPBERDecoderContext_TopLevel(
        inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
        fallback=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext()),
        inherit=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext()))),

         [0x30, 97]
         # id
         + [0x02, 1, 1]
         # value
         + [0x63, 92]
         + ([0x04, 17] + l('dc=example,dc=com')
            + [0x0a, 1, 0x02]
            + [0x0a, 1, 0x00]
            + [0x02, 1, 0x01]
            + [0x02, 1, 0x00]
            + [0x01, 1, 0x00]
            + [0xA1, 52]
            + ([0xa3, 9]
               + ([0x04, 2] + l('cn')
                  + [0x04, 3] + l('foo'))
               + [0xa3, 10]
               + ([0x04, 3] + l('uid')
                  + [0x04, 3] + l('foo'))
               + [0xa3, 11]
               + ([0x04, 4] + l('mail')
                  + [0x04, 3] + l('foo'))
               + [0xa4, 14]
               + ([0x04, 4] + l('mail')
                  + [0x30, 6]
                  + ([0x80, 4] + l('foo@'))))
            + [0x30, 2]
            + ([0x04, 0])
            )
         ),

        (pureldap.LDAPExtendedRequest,
         [],
         {'requestName': '42.42.42',
          'requestValue': 'foo',
          },
         None,
         [0x40|0x20|23, 1+1+8+1+1+3]
         + ([0x80|0]
            + [len('42.42.42')]
            + l('42.42.42'))
         + ([0x80|1]
            + [len('foo')]
            + l('foo'))
         ),

        (pureldap.LDAPExtendedRequest,
         [],
         {'requestName': '42.42.42',
          'requestValue': None,
          },
         None,
         [0x40|0x20|23, 1+1+8]
         + ([0x80|0]
            + [len('42.42.42')]
            + l('42.42.42'))
         ),

        (pureldap.LDAPExtendedResponse,
         [],
         {'resultCode': 49,
          'matchedDN': 'foo',
          'errorMessage': 'bar',
          'responseName': None,
          'response': None,
          },
         None,
         [0x40|0x20|24, 3+2+3+2+3,
          0x0a, 1, 49,
          0x04, len('foo')] + l('foo') + [
          0x04, len('bar')] + l('bar'),
         ),

        (pureldap.LDAPExtendedResponse,
         [],
         {'resultCode': 49,
          'matchedDN': 'foo',
          'errorMessage': 'bar',
          'responseName': '1.2.3.4.5.6.7.8.9',
          'response': 'baz',
          },
         None,
         [0x40|0x20|24, 3+2+3+2+3+2+len('1.2.3.4.5.6.7.8.9')+2+3,
          0x0a, 1, 49,
          0x04, len('foo')] + l('foo') + [
          0x04, len('bar')] + l('bar') + [
          0x8a, len('1.2.3.4.5.6.7.8.9')] + l('1.2.3.4.5.6.7.8.9') + [
          0x8b, len('baz')] + l('baz'),
         ),

        (pureldap.LDAPAbandonRequest,
         [],
         {'id': 3},
         None,
         [0x40|0x10, 0x01, 3]
         ),

        (pureldap.LDAPBindRequest,
         [],
         {'auth': ('PLAIN', 'test'),
          'sasl': True},
         pureldap.LDAPBERDecoderContext(
                fallback=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext()),
                inherit=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext())),
         [ord(x) for x in str(pureldap.LDAPBindRequest(auth=('PLAIN', 'test'), sasl=True))]
         )
        )

    def testToLDAP(self):
        """str(LDAPClass(...)) should give known result with known input"""
        for klass, args, kwargs, decoder, encoded in self.knownValues:
            result = klass(*args, **kwargs)
            result = str(result)
            result = map(ord, result)

            message = (
                "Class %s(*%r, **%r) doesn't encode properly: "
                "%r != %r" % (
                    klass.__name__, args, kwargs, result, encoded))
            self.assertEqual(encoded, result, message)

    def testFromLDAP(self):
        """LDAPClass(encoded="...") should give known result with known input"""
        for klass, args, kwargs, decoder, encoded in self.knownValues:
            if decoder is None:
                decoder = pureldap.LDAPBERDecoderContext(
                    fallback=pureber.BERDecoderContext())
            m=s(*encoded)
            result, bytes = pureber.berDecodeObject(decoder, m)
            self.assertEqual(bytes, len(m))

            shouldBe = klass(*args, **kwargs)
            #TODO shouldn't use str below
            assert str(result)==str(shouldBe), \
                   "Class %s(*%s, **%s) doesn't decode properly: " \
                   "%s != %s" % (klass.__name__,
                                 repr(args), repr(kwargs),
                                 repr(result), repr(shouldBe))

    def testPartial(self):
        """LDAPClass(encoded="...") with too short input should throw BERExceptionInsufficientData"""
        for klass, args, kwargs, decoder, encoded in self.knownValues:
            if decoder is None:
                decoder = pureldap.LDAPBERDecoderContext(
                    fallback=pureber.BERDecoderContext())
            for i in xrange(1, len(encoded)):
                m=s(*encoded)[:i]
                self.assertRaises(pureber.BERExceptionInsufficientData,
                                  pureber.berDecodeObject,
                                  decoder, m)
            self.assertEqual((None, 0), pureber.berDecodeObject(decoder, ''))

class TestEquality(unittest.TestCase):
    valuesToTest=(
        (pureldap.LDAPFilter_equalityMatch,
         [ pureldap.LDAPAttributeDescription(value='cn'),
           pureldap.LDAPAssertionValue(value='foo'),
           ]),
        (pureldap.LDAPFilter_equalityMatch,
         [ pureldap.LDAPAttributeDescription(value='cn'),
           pureldap.LDAPAssertionValue(value='bar'),
           ]),
        (pureber.BERInteger, [0]),
        )

    def testEquality(self):
        """LDAP objects equal LDAP objects with same type and content"""
        for class_, args in self.valuesToTest:
            x=class_(*args)
            y=class_(*args)
            self.assertEqual(x, x)
            self.assertEqual(x, y)

    def testInEquality(self):
        """LDAP objects do not equal LDAP objects with different type or content"""
        for i in xrange(len(self.valuesToTest)):
            for j in xrange(len(self.valuesToTest)):
                if i!=j:
                    i_class, i_args = self.valuesToTest[i]
                    j_class, j_args = self.valuesToTest[j]
                    x=i_class(*i_args)
                    y=j_class(*j_args)
                    self.assertNotEquals(x, y)

class Substrings(unittest.TestCase):
    def test_length(self):
        """LDAPFilter_substrings.substrings behaves like a proper list."""
        decoder = pureldap.LDAPBERDecoderContext(
            fallback=pureber.BERDecoderContext())
        filt = pureldap.LDAPFilter_substrings.fromBER(
            tag=pureldap.LDAPFilter_substrings.tag,
            content=s(0x04, 4, 'mail',
                      0x30, 6,
                      0x80, 4, 'foo@'),
            berdecoder=decoder)
        # The confusion that used to occur here was because
        # filt.substrings was left as a BERSequence, which under the
        # current str()-to-wire-protocol system had len() > 1 even
        # when empty, and that tripped e.g. entry.match()
        self.assertEqual(len(filt.substrings), 1)

class TestEscaping(unittest.TestCase):
    def test_escape(self):
        s = '\\*()\0'

        result = pureldap.escape(s)
        expected = '\\5c\\2a\\28\\29\\00'

        self.assertEqual(expected, result)

    def test_binary_escape(self):
        s = 'HELLO'

        result = pureldap.binary_escape(s)
        expected = '\\48\\45\\4c\\4c\\4f'

        self.assertEqual(expected, result)

    def test_smart_escape_regular(self):
        s = 'HELLO'

        result = pureldap.smart_escape(s)
        expected = 'HELLO'

        self.assertEqual(expected, result)

    def test_smart_escape_binary(self):
        s = '\x10\x11\x12\x13\x14'

        result = pureldap.smart_escape(s)
        expected = '\\10\\11\\12\\13\\14'

        self.assertEqual(expected, result)

    def test_smart_escape_threshold(self):
        s = '\x10\x11ABC'

        result = pureldap.smart_escape(s, threshold=0.10)
        expected = '\\10\\11\\41\\42\\43'

        self.assertEqual(expected, result)

    def test_default_escaper(self):
        chars = '\\*()\0'
        escaped_chars = '\\5c\\2a\\28\\29\\00'

        filters = [
            (
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription('key'),
                    assertionValue=pureldap.LDAPAttributeValue(chars)
                ),
                '(key={})'.format(escaped_chars)
            ),
            (
                pureldap.LDAPFilter_substrings_initial(
                    value=chars
                ),
                '{}'.format(escaped_chars)
            ),
            (
                pureldap.LDAPFilter_substrings_any(
                    value=chars
                ),
                '{}'.format(escaped_chars)
            ),
            (
                pureldap.LDAPFilter_substrings_final(
                    value=chars
                ),
                '{}'.format(escaped_chars)
            ),
            (
                pureldap.LDAPFilter_greaterOrEqual(
                    attributeDesc=pureldap.LDAPString('key'),
                    assertionValue=pureldap.LDAPString(chars)
                ),
                '(key>={})'.format(escaped_chars)
            ),
            (
                pureldap.LDAPFilter_lessOrEqual(
                    attributeDesc=pureldap.LDAPString('key'),
                    assertionValue=pureldap.LDAPString(chars)
                ),
                '(key<={})'.format(escaped_chars)
            ),
            (
                pureldap.LDAPFilter_approxMatch(
                    attributeDesc=pureldap.LDAPString('key'),
                    assertionValue=pureldap.LDAPString(chars)
                ),
                '(key~={})'.format(escaped_chars)
            ),
        ]

        for filt, expected in filters:
            result = filt.asText()
            self.assertEqual(expected, result)

    def test_custom_escaper(self):
        chars = 'HELLO'
        escaped_chars = '0b10010000b10001010b10011000b10011000b1001111'

        def custom_escaper(s):
            return ''.join(bin(ord(c)) for c in s)

        filters = [
            (
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription('key'),
                    assertionValue=pureldap.LDAPAttributeValue(chars),
                    escaper=custom_escaper
                ),
                '(key={})'.format(escaped_chars)
            ),
            (
                pureldap.LDAPFilter_substrings_initial(
                    value=chars,
                    escaper=custom_escaper
                ),
                '{}'.format(escaped_chars)
            ),
            (
                pureldap.LDAPFilter_substrings_any(
                    value=chars,
                    escaper=custom_escaper
                ),
                '{}'.format(escaped_chars)
            ),
            (
                pureldap.LDAPFilter_substrings_final(
                    value=chars,
                    escaper=custom_escaper
                ),
                '{}'.format(escaped_chars)
            ),
            (
                pureldap.LDAPFilter_greaterOrEqual(
                    attributeDesc=pureldap.LDAPString('key'),
                    assertionValue=pureldap.LDAPString(chars),
                    escaper=custom_escaper
                ),
                '(key>={})'.format(escaped_chars)
            ),
            (
                pureldap.LDAPFilter_lessOrEqual(
                    attributeDesc=pureldap.LDAPString('key'),
                    assertionValue=pureldap.LDAPString(chars),
                    escaper=custom_escaper
                ),
                '(key<={})'.format(escaped_chars)
            ),
            (
                pureldap.LDAPFilter_approxMatch(
                    attributeDesc=pureldap.LDAPString('key'),
                    assertionValue=pureldap.LDAPString(chars),
                    escaper=custom_escaper
                ),
                '(key~={})'.format(escaped_chars)
            ),
        ]

        for filt, expected in filters:
            result = filt.asText()
            self.assertEqual(expected, result)


class TestFilterSetEquality(unittest.TestCase):
    def test_basic_and_equal(self):
        filter1 = pureldap.LDAPFilter_and([
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('foo'),
                assertionValue=pureldap.LDAPAttributeValue('1')
            ),
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('bar'),
                assertionValue=pureldap.LDAPAttributeValue('2')
            ),
        ])
        filter2 = pureldap.LDAPFilter_and([
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('bar'),
                assertionValue=pureldap.LDAPAttributeValue('2')
            ),
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('foo'),
                assertionValue=pureldap.LDAPAttributeValue('1')
            ),
        ])

        self.assertEqual(filter1, filter2)

    def test_basic_and_not_equal(self):
        filter1 = pureldap.LDAPFilter_and([
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('foo'),
                assertionValue=pureldap.LDAPAttributeValue('1')
            ),
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('bar'),
                assertionValue=pureldap.LDAPAttributeValue('2')
            ),
        ])
        filter2 = pureldap.LDAPFilter_and([
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('bar'),
                assertionValue=pureldap.LDAPAttributeValue('1')
            ),
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('foo'),
                assertionValue=pureldap.LDAPAttributeValue('1')
            ),
        ])

        self.assertNotEqual(filter1, filter2)

    def test_basic_or_equal(self):
        filter1 = pureldap.LDAPFilter_or([
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('foo'),
                assertionValue=pureldap.LDAPAttributeValue('1')
            ),
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('bar'),
                assertionValue=pureldap.LDAPAttributeValue('2')
            ),
        ])
        filter2 = pureldap.LDAPFilter_or([
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('bar'),
                assertionValue=pureldap.LDAPAttributeValue('2')
            ),
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('foo'),
                assertionValue=pureldap.LDAPAttributeValue('1')
            ),
        ])

        self.assertEqual(filter1, filter2)

    def test_basic_or_not_equal(self):
        filter1 = pureldap.LDAPFilter_or([
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('foo'),
                assertionValue=pureldap.LDAPAttributeValue('1')
            ),
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('bar'),
                assertionValue=pureldap.LDAPAttributeValue('2')
            ),
        ])
        filter2 = pureldap.LDAPFilter_or([
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('bar'),
                assertionValue=pureldap.LDAPAttributeValue('1')
            ),
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('foo'),
                assertionValue=pureldap.LDAPAttributeValue('1')
            ),
        ])

        self.assertNotEqual(filter1, filter2)

    def test_nested_equal(self):
        filter1 = pureldap.LDAPFilter_or([
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('foo'),
                assertionValue=pureldap.LDAPAttributeValue('1')
            ),
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('bar'),
                assertionValue=pureldap.LDAPAttributeValue('2')
            ),
            pureldap.LDAPFilter_and([
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription('baz'),
                    assertionValue=pureldap.LDAPAttributeValue('1')
                ),
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription('bob'),
                    assertionValue=pureldap.LDAPAttributeValue('2')
                ),
            ]),
        ])
        filter2 = pureldap.LDAPFilter_or([
            pureldap.LDAPFilter_and([
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription('bob'),
                    assertionValue=pureldap.LDAPAttributeValue('2')
                ),
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription('baz'),
                    assertionValue=pureldap.LDAPAttributeValue('1')
                ),
            ]),
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('bar'),
                assertionValue=pureldap.LDAPAttributeValue('2')
            ),
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('foo'),
                assertionValue=pureldap.LDAPAttributeValue('1')
            ),
        ])

        self.assertEqual(filter1, filter2)

    def test_escape_and_equal(self):

        filter1 = pureldap.LDAPFilter_and([
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('foo'),
                assertionValue=pureldap.LDAPAttributeValue('1'),
            ),
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('foo'),
                assertionValue=pureldap.LDAPAttributeValue('2')
            ),
        ])
        filter2 = pureldap.LDAPFilter_and([
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('foo'),
                assertionValue=pureldap.LDAPAttributeValue('1')
            ),
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription('foo'),
                assertionValue=pureldap.LDAPAttributeValue('2'),
            ),
        ])

        self.assertEqual(filter1, filter2)
