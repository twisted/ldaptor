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
import six
from twisted.trial import unittest

from ldaptor.protocols import pureldap, pureber


def s(*l):
    """Join all members of list to a byte string. Integer members are chr()ed"""
    return b''.join([six.int2byte(e) if isinstance(e, int) else e for e in l])


def l(s):
    """Split a byte string to ord's of chars."""
    return [six.byte2int([x]) for x in s]


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
         + ([0x04, 0x1a] + l(b"cn=foo, dc=example, dc=com")
            + [0x30, 20]
            + ([0x30, 18]
               + ([0x0a, 0x01, 0x00]
                  + [0x30, 13]
                  + ([0x04, len(b"bar")] + l(b"bar")
                     + [0x31, 0x06]
                     + ([0x04, len(b"a")] + l(b"a")
                        + [0x04, len(b"b")] + l(b"b"))))))
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
         + ([0x04, 0x1a] + l(b"cn=foo, dc=example, dc=com")
            + [0x30, 0x0e]
            + ([0x30, 0x0c]
               + ([0x0a, 0x01, 0x01]
                  + [0x30, 0x07]
                  + ([0x04, 0x03] + l(b"bar")
                     + [0x31, 0x00]))))
        ),

        (pureldap.LDAPFilter_not,
         [],
         { "value": pureldap.LDAPFilter_present("foo"),
           },
         pureldap.LDAPBERDecoderContext_Filter(fallback=pureber.BERDecoderContext()),
         [0xa2, 0x05]
         + [0x87]
         + [len(b"foo")]
         + l(b"foo")),

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
         + [0x04] + [len(b"cn")] + l(b"cn")
         + [0x04] + [len(b"foo")] + l(b"foo")
         + [0xa3, 10]
         + [0x04] + [len(b"uid")] + l(b"uid")
         + [0x04] + [len(b"foo")] + l(b"foo"),
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
         + [0x04] + [len(b"cn")] + l(b"cn")
         + [0x04] + [len(b"foo")] + l(b"foo")
         + [0xa3, 10]
         + [0x04] + [len(b"uid")] + l(b"uid")
         + [0x04] + [len(b"foo")] + l(b"foo"),
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
         + [len(b"cn=foo,dc=example,dc=com")]
         + l(b"cn=foo,dc=example,dc=com")
         + [0x04]
         + [len(b"uid=bar")]
         + l(b"uid=bar")
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
         + [len(b"cn=aoue,dc=example,dc=com")]
         + l(b"cn=aoue,dc=example,dc=com")
         + [0x04]
         + [len(b"uid=aoue")]
         + l(b"uid=aoue")
         + [0x01, 0x01, 0x00]
         + [0x80]
         + [len(b"ou=People,dc=example,dc=com")]
         + l(b"ou=People,dc=example,dc=com")),

        (pureldap.LDAPSearchRequest,
         [],
         {'baseObject': 'dc=yoja,dc=example,dc=com',
          },
         None,
         [0x63, 57]
         + [0x04]
         + [len(b'dc=yoja,dc=example,dc=com')]
         + l(b'dc=yoja,dc=example,dc=com')
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
         + [135, 11] + l(b'objectClass')
         # attributes
         + [48, 0]
         ),

        (pureldap.LDAPUnbindRequest,
         [],
         {},
         None,
         [0x42, 0x00]
        ),

        (pureldap.LDAPSearchResultReference,
         [],
         {'uris': [pureldap.LDAPString(b'ldap://example.com/dc=foo,dc=example,dc=com'),
                   pureldap.LDAPString(b'ldap://example.com/dc=bar,dc=example,dc=com')]
          },
         None,
         [0x73, 90]
         + [0x04]
         + [len(b'ldap://example.com/dc=foo,dc=example,dc=com')]
         + l(b'ldap://example.com/dc=foo,dc=example,dc=com')
         + [0x04]
         + [len(b'ldap://example.com/dc=bar,dc=example,dc=com')]
         + l(b'ldap://example.com/dc=bar,dc=example,dc=com'),
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
         + [len(b'')]
         + l(b'')
         # errorMessage
         + [0x04]
         + [len(b'')]
         + l(b'')
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
         + [len(b'dc=foo,dc=example,dc=com')]
         + l(b'dc=foo,dc=example,dc=com')
         # errorMessage
         + [0x04]
         + [len(b'')]
         + l(b'')
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
         + [len(b'dc=foo,dc=example,dc=com')]
         + l(b'dc=foo,dc=example,dc=com')
         # errorMessage
         + [0x04]
         + [len(b'the foobar was fubar')]
         + l(b'the foobar was fubar',)
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
         + [len(b'')]
         + l(b'')
         # errorMessage
         + [0x04]
         + [len(b'the foobar was fubar')]
         + l(b'the foobar was fubar',)
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
         + l(pureldap.LDAPBindRequest().toWire())
         ),

        (pureldap.LDAPControl,
         [],
         {'controlType': '1.2.3.4',
          },
         None,
         [0x30, 9]
         # controlType
         + [0x04, 7]
         + l(b"1.2.3.4")
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
         + l(b"1.2.3.4")
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
         + l(b"1.2.3.4")
         # criticality
         + [0x01, 1, 0xFF]
         # controlValue
         + [0x04, len(b"silly")]
         + l(b"silly")
         ),

        (pureldap.LDAPMessage,
         [],
         {'id': 42,
          'value': pureldap.LDAPBindRequest(),
          'controls': [ ('1.2.3.4', None, None),
                        ('2.3.4.5', False),
                        ('3.4.5.6', True, b'\x00\x01\x02\xFF'),
                        ('4.5.6.7', None, b'\x00\x01\x02\xFF'),
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
         + l(pureldap.LDAPBindRequest().toWire())
         # controls
         + l(pureldap.LDAPControls(value=[
        pureldap.LDAPControl(controlType='1.2.3.4'),
        pureldap.LDAPControl(controlType='2.3.4.5',
                             criticality=False),
        pureldap.LDAPControl(controlType='3.4.5.6',
                             criticality=True,
                             controlValue=b'\x00\x01\x02\xFF'),
        pureldap.LDAPControl(controlType='4.5.6.7',
                             criticality=None,
                             controlValue=b'\x00\x01\x02\xFF'),
        ]).toWire()),
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
         + ([0x04, 2] + l(b'cn')
            + [0x04, 3] + l(b'foo'))
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
            + ([0x04, 2] + l(b'cn')
               + [0x04, 3] + l(b'foo'))
            + [0xa3, 10]
            + ([0x04, 3] + l(b'uid')
               + [0x04, 3] + l(b'foo'))
            + [0xa3, 11]
               + ([0x04, 4] + l(b'mail')
                  + [0x04, 3] + l(b'foo'))
            + [0xa4, 14]
            + ([0x04, 4] + l(b'mail')
               + [0x30, 6]
               + ([0x80, 4] + l(b'foo@'))))
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
         + ([0x04, 17] + l(b'dc=example,dc=com')
            + [0x0a, 1, 0x02]
            + [0x0a, 1, 0x00]
            + [0x02, 1, 0x01]
            + [0x02, 1, 0x00]
            + [0x01, 1, 0x00]
            + [0xA1, 52]
            + ([0xa3, 9]
               + ([0x04, 2] + l(b'cn')
                  + [0x04, 3] + l(b'foo'))
               + [0xa3, 10]
               + ([0x04, 3] + l(b'uid')
                  + [0x04, 3] + l(b'foo'))
               + [0xa3, 11]
               + ([0x04, 4] + l(b'mail')
                  + [0x04, 3] + l(b'foo'))
               + [0xa4, 14]
               + ([0x04, 4] + l(b'mail')
                  + [0x30, 6]
                  + ([0x80, 4] + l(b'foo@'))))
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
         + ([0x04, 17] + l(b'dc=example,dc=com')
            + [0x0a, 1, 0x02]
            + [0x0a, 1, 0x00]
            + [0x02, 1, 0x01]
            + [0x02, 1, 0x00]
            + [0x01, 1, 0x00]
            + [0xA1, 52]
            + ([0xa3, 9]
               + ([0x04, 2] + l(b'cn')
                  + [0x04, 3] + l(b'foo'))
               + [0xa3, 10]
               + ([0x04, 3] + l(b'uid')
                  + [0x04, 3] + l(b'foo'))
               + [0xa3, 11]
               + ([0x04, 4] + l(b'mail')
                  + [0x04, 3] + l(b'foo'))
               + [0xa4, 14]
               + ([0x04, 4] + l(b'mail')
                  + [0x30, 6]
                  + ([0x80, 4] + l(b'foo@'))))
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
            + [len(b'42.42.42')]
            + l(b'42.42.42'))
         + ([0x80|1]
            + [len(b'foo')]
            + l(b'foo'))
         ),

        (pureldap.LDAPExtendedRequest,
         [],
         {'requestName': '42.42.42',
          'requestValue': None,
          },
         None,
         [0x40|0x20|23, 1+1+8]
         + ([0x80|0]
            + [len(b'42.42.42')]
            + l(b'42.42.42'))
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
          0x04, len(b'foo')] + l(b'foo') + [
          0x04, len(b'bar')] + l(b'bar'),
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
          0x04, len(b'foo')] + l(b'foo') + [
          0x04, len(b'bar')] + l(b'bar') + [
          0x8a, len(b'1.2.3.4.5.6.7.8.9')] + l(b'1.2.3.4.5.6.7.8.9') + [
          0x8b, len(b'baz')] + l(b'baz'),
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
         l(pureldap.LDAPBindRequest(auth=('PLAIN', 'test'), sasl=True).toWire())
         )
        )

    def testToLDAP(self):
        """LDAPClass(...).toWire() should give known result with known input"""
        for klass, args, kwargs, decoder, encoded in self.knownValues:
            result = klass(*args, **kwargs)
            result = result.toWire()
            result = l(result)

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
            assert result.toWire() == shouldBe.toWire(), \
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
            for i in six.moves.range(1, len(encoded)):
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
        for i in six.moves.range(len(self.valuesToTest)):
            for j in six.moves.range(len(self.valuesToTest)):
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
            content=s(0x04, 4, b'mail',
                      0x30, 6,
                      0x80, 4, b'foo@'),
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


class Representations(unittest.TestCase):

    def test_message_repr(self):
        page_size = 10
        cookie = "xyzzy"
        control_value = pureber.BERSequence([
            pureber.BERInteger(page_size),
            pureber.BEROctetString(cookie),
        ])
        controls = [('1.2.840.113556.1.4.319', None, control_value)]
        search_request = pureldap.LDAPSearchRequest(
            "cn=foo,ou=baz,dc=example,dc=org")
        ldap_msg = pureldap.LDAPMessage(
            id=1,
            value=search_request,
            controls=controls,
            tag=1)
        expected_value = "LDAPMessage(id=1, value=LDAPSearchRequest(baseObject='cn=foo,ou=baz,dc=example,dc=org', scope=2, derefAliases=0, sizeLimit=0, timeLimit=0, typesOnly=0, filter=LDAPFilter_present(value='objectClass'), attributes=[]), controls=[('1.2.840.113556.1.4.319', None, BERSequence(value=[BERInteger(value=10), BEROctetString(value='xyzzy')]))], tag=1)"
        self.assertEqual(
            expected_value,
            repr(ldap_msg))


class TestRepresentations(unittest.TestCase):
    """
    Test representations of common LDAP opbjects.
    """

    def test_bind_request_repr(self):
        """LDAPBindRequest.__repr__"""
        dns = [b'uid=user,ou=users,dc=example,dc=org', u'uid=user,ou=users,dc=example,dc=org']
        for dn in dns:
            req = pureldap.LDAPBindRequest(dn=dn)
            req_repr = "LDAPBindRequest(version=3, dn='uid=user,ou=users,dc=example,dc=org', auth='', sasl=False)"
            self.assertEqual(repr(req), req_repr)

    def test_bind_request_with_tag_repr(self):
        """LDAPBindRequest.__repr__ with custom tag attribute"""
        dns = [b'uid=user,ou=users,dc=example,dc=org', u'uid=user,ou=users,dc=example,dc=org']
        for dn in dns:
            req = pureldap.LDAPBindRequest(dn=dn, auth='pass', tag=42)
            req_repr = "LDAPBindRequest(version=3, dn='uid=user,ou=users,dc=example,dc=org', " \
                       "auth='****', tag=42, sasl=False)"
            self.assertEqual(repr(req), req_repr)

    def test_bind_response_repr(self):
        """LDAPBindResponse.__repr__"""
        matched_dns = [b'uid=user,ou=users,dc=example,dc=org', u'uid=user,ou=users,dc=example,dc=org']
        for matched_dn in matched_dns:
            res = pureldap.LDAPBindResponse(resultCode=0, matchedDN=matched_dn)
            res_repr = "LDAPBindResponse(resultCode=0, matchedDN='uid=user,ou=users,dc=example,dc=org')"
            self.assertEqual(repr(res), res_repr)

    def test_result_with_matched_dn_repr(self):
        """LDAPResult.__repr__ with matchedDN attribute"""
        matched_dns = [b'uid=user,ou=users,dc=example,dc=org', u'uid=user,ou=users,dc=example,dc=org']
        for matched_dn in matched_dns:
            res = pureldap.LDAPResult(resultCode=0, matchedDN=matched_dn)
            res_repr = "LDAPResult(resultCode=0, matchedDN='uid=user,ou=users,dc=example,dc=org')"
            self.assertEqual(repr(res), res_repr)

    def test_result_with_error_message_repr(self):
        """LDAPResult.__repr__ with errorMessage attribute"""
        error_messages = [b'error_message', u'error_message']
        for error_message in error_messages:
            res = pureldap.LDAPResult(resultCode=1, errorMessage=error_message)
            res_repr = "LDAPResult(resultCode=1, errorMessage='error_message')"
            self.assertEqual(repr(res), res_repr)

    def test_result_with_tag_repr(self):
        """LDAPResult.__repr__ with custom tag attribute"""
        res = pureldap.LDAPResult(resultCode=0, tag=42)
        res_repr = "LDAPResult(resultCode=0, tag=42)"
        self.assertEqual(repr(res), res_repr)

    def test_search_request_repr(self):
        """LDAPSearchRequest.__repr__"""
        base_objects = [b'ou=users,dc=example,dc=org', u'ou=users,dc=example,dc=org']
        for base_object in base_objects:
            req = pureldap.LDAPSearchRequest(
                baseObject=base_object,
                filter=pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureber.BEROctetString('key'),
                    assertionValue=pureber.BEROctetString('value'),
                ),
            )
            req_repr = "LDAPSearchRequest(baseObject='ou=users,dc=example,dc=org', scope=2, derefAliases=0, " \
                       "sizeLimit=0, timeLimit=0, typesOnly=0, filter=LDAPFilter_equalityMatch(" \
                       "attributeDesc=BEROctetString(value='key'), assertionValue=BEROctetString(value='value')), " \
                       "attributes=[])"
            self.assertEqual(repr(req), req_repr)

    def test_search_request_with_tag_repr(self):
        """LDAPSearchRequest.__repr__ with custom tag attribute"""
        base_objects = [b'ou=users,dc=example,dc=org', u'ou=users,dc=example,dc=org']
        for base_object in base_objects:
            req = pureldap.LDAPSearchRequest(
                baseObject=base_object,
                filter=pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureber.BEROctetString('key'),
                    assertionValue=pureber.BEROctetString('value'),
                ),
                tag=42,
            )
            req_repr = "LDAPSearchRequest(baseObject='ou=users,dc=example,dc=org', scope=2, derefAliases=0, " \
                       "sizeLimit=0, timeLimit=0, typesOnly=0, filter=LDAPFilter_equalityMatch(" \
                       "attributeDesc=BEROctetString(value='key'), assertionValue=BEROctetString(value='value')), " \
                       "attributes=[], tag=42)"
            self.assertEqual(repr(req), req_repr)

    def test_search_result_entry_repr(self):
        """LDAPSearchResultEntry.__repr__"""
        object_names = [b'uid=mohamed,ou=people,dc=example,dc=fr', u'uid=mohamed,ou=people,dc=example,dc=fr']
        attributes_list = [(b'uid', [b'mohamed']), (u'uid', [u'mohamed'])]
        for object_name in object_names:
            for attributes in attributes_list:
                resp = pureldap.LDAPSearchResultEntry(
                    objectName=object_name,
                    attributes=[attributes],
                )
                resp_repr = "LDAPSearchResultEntry(objectName='uid=mohamed,ou=people,dc=example,dc=fr', " \
                            "attributes=[('uid', ['mohamed'])])"
                self.assertEqual(repr(resp), resp_repr)

    def test_search_result_entry_with_tag_repr(self):
        """LDAPSearchResultEntry.__repr__ with custom tag attribute"""
        object_names = [b'uid=mohamed,ou=people,dc=example,dc=fr', u'uid=mohamed,ou=people,dc=example,dc=fr']
        attributes_list = [(b'uid', [b'mohamed']), (u'uid', [u'mohamed'])]
        for object_name in object_names:
            for attributes in attributes_list:
                resp = pureldap.LDAPSearchResultEntry(
                    objectName=object_name,
                    attributes=[attributes],
                    tag=42,
                )
                resp_repr = "LDAPSearchResultEntry(objectName='uid=mohamed,ou=people,dc=example,dc=fr', " \
                            "attributes=[('uid', ['mohamed'])], tag=42)"
                self.assertEqual(repr(resp), resp_repr)

    def test_search_result_reference_repr(self):
        """LDAPSearchResultReference.__repr__"""
        uris_list = [
            [
                b'ldap://example.com/dc=foo,dc=example,dc=com',
                b'ldap://example.com/dc=foo,dc=example,dc=com',
            ],
            [
                u'ldap://example.com/dc=foo,dc=example,dc=com',
                u'ldap://example.com/dc=foo,dc=example,dc=com',
            ]
        ]
        for uris in uris_list:
            resp = pureldap.LDAPSearchResultReference(uris=uris)
            resp_repr = "LDAPSearchResultReference(uris=['ldap://example.com/dc=foo,dc=example,dc=com', " \
                        "'ldap://example.com/dc=foo,dc=example,dc=com'])"
            self.assertEqual(repr(resp), resp_repr)

    def test_search_result_reference_with_tag_repr(self):
        """LDAPSearchResultReference.__repr__ with custom tag attribute"""
        uris_list = [
            [
                b'ldap://example.com/dc=foo,dc=example,dc=com',
                b'ldap://example.com/dc=foo,dc=example,dc=com',
            ],
            [
                u'ldap://example.com/dc=foo,dc=example,dc=com',
                u'ldap://example.com/dc=foo,dc=example,dc=com',
            ]
        ]
        for uris in uris_list:
            resp = pureldap.LDAPSearchResultReference(uris=uris, tag=42)
            resp_repr = "LDAPSearchResultReference(uris=['ldap://example.com/dc=foo,dc=example,dc=com', " \
                        "'ldap://example.com/dc=foo,dc=example,dc=com'], tag=42)"
            self.assertEqual(repr(resp), resp_repr)

    def test_modify_request_repr(self):
        """LDAPModifyRequest.__repr__"""
        object_names = [b'uid=user,ou=users,dc=example,dc=org', u'uid=user,ou=users,dc=example,dc=org']
        for object_name in object_names:
            mr = pureldap.LDAPModifyRequest(
                object=object_name,
                modification=pureber.BERSequence([
                    pureber.BEREnumerated(0),
                    pureber.BERSequence([
                        pureldap.LDAPAttributeDescription('key'),
                        pureber.BERSet([pureldap.LDAPString('value')])
                    ]),
                ]),
            )
            mr_repr = "LDAPModifyRequest(object='uid=user,ou=users,dc=example,dc=org', " \
                      "modification=BERSequence(value=[BEREnumerated(value=0), " \
                      "BERSequence(value=[LDAPAttributeDescription(value='key'), " \
                      "BERSet(value=[LDAPString(value='value')])])]))"
            self.assertEqual(repr(mr), mr_repr)

    def test_modify_request_with_tag_repr(self):
        """LDAPModifyRequest.__repr__ with custom tag attribute"""
        object_names = [b'uid=user,ou=users,dc=example,dc=org', u'uid=user,ou=users,dc=example,dc=org']
        for object_name in object_names:
            mr = pureldap.LDAPModifyRequest(
                object=object_name,
                modification=pureber.BERSequence([
                    pureber.BEREnumerated(0),
                    pureber.BERSequence([
                        pureldap.LDAPAttributeDescription('key'),
                        pureber.BERSet([pureldap.LDAPString('value')])
                    ]),
                ]),
                tag=42,
            )
            mr_repr = "LDAPModifyRequest(object='uid=user,ou=users,dc=example,dc=org', " \
                      "modification=BERSequence(value=[BEREnumerated(value=0), " \
                      "BERSequence(value=[LDAPAttributeDescription(value='key'), " \
                      "BERSet(value=[LDAPString(value='value')])])]), tag=42)"
            self.assertEqual(repr(mr), mr_repr)

    def test_add_request_repr(self):
        """LDAPAddRequest.__repr__"""
        entries = [b'uid=user,ou=users,dc=example,dc=org', u'uid=user,ou=users,dc=example,dc=org']
        for entry in entries:
            ar = pureldap.LDAPAddRequest(
                entry=entry,
                attributes=[
                    (
                        pureldap.LDAPAttributeDescription('key'),
                        pureber.BERSet([pureldap.LDAPAttributeValue('value')]),
                    ),
                ],
            )
            ar_repr = "LDAPAddRequest(entry='uid=user,ou=users,dc=example,dc=org', " \
                      "attributes=[(LDAPAttributeDescription(value='key'), " \
                      "BERSet(value=[LDAPAttributeValue(value='value')]))])"
            self.assertEqual(repr(ar), ar_repr)

    def test_add_request_with_tag_repr(self):
        """LDAPAddRequest.__repr__ with custom tag attribute"""
        entries = [b'uid=user,ou=users,dc=example,dc=org', u'uid=user,ou=users,dc=example,dc=org']
        for entry in entries:
            ar = pureldap.LDAPAddRequest(
                entry=entry,
                attributes=[
                    (
                        pureldap.LDAPAttributeDescription('key'),
                        pureber.BERSet([pureldap.LDAPAttributeValue('value')]),
                    ),
                ],
                tag=42,
            )
            ar_repr = "LDAPAddRequest(entry='uid=user,ou=users,dc=example,dc=org', " \
                      "attributes=[(LDAPAttributeDescription(value='key'), " \
                      "BERSet(value=[LDAPAttributeValue(value='value')]))], tag=42)"
            self.assertEqual(repr(ar), ar_repr)

    def test_del_request_repr(self):
        """LDAPDelRequest.__repr__"""
        entries = [b'uid=user,ou=users,dc=example,dc=org', u'uid=user,ou=users,dc=example,dc=org']
        for entry in entries:
            dr = pureldap.LDAPDelRequest(entry=entry)
            dr_repr = "LDAPDelRequest(entry='uid=user,ou=users,dc=example,dc=org')"
            self.assertEqual(repr(dr), dr_repr)

    def test_del_request_with_tag_repr(self):
        """LDAPDelRequest.__repr__ with custom tag attribute"""
        entries = [b'uid=user,ou=users,dc=example,dc=org', u'uid=user,ou=users,dc=example,dc=org']
        for entry in entries:
            dr = pureldap.LDAPDelRequest(entry=entry, tag=42)
            dr_repr = "LDAPDelRequest(entry='uid=user,ou=users,dc=example,dc=org', tag=42)"
            self.assertEqual(repr(dr), dr_repr)

    def test_modify_dn_request_repr(self):
        """LDAPModifyDNRequest.__repr__"""
        entries = [b'uid=user,ou=users,dc=example,dc=org', u'uid=user,ou=users,dc=example,dc=org']
        rdns = [b'uid=newuser', u'uid=newuser']
        for entry in entries:
            for rdn in rdns:
                mdnr = pureldap.LDAPModifyDNRequest(
                    entry=entry,
                    newrdn=rdn,
                    deleteoldrdn=True,
                )
                mdnr_repr = "LDAPModifyDNRequest(entry='uid=user,ou=users,dc=example,dc=org', " \
                            "newrdn='uid=newuser', deleteoldrdn=True)"
                self.assertEqual(repr(mdnr), mdnr_repr)

    def test_modify_dn_request_with_new_superior_repr(self):
        """LDAPModifyDNRequest.__repr__ with newSuperior attribute"""
        entries = [b'uid=user,ou=users,dc=example,dc=org', u'uid=user,ou=users,dc=example,dc=org']
        rdns = [b'uid=newuser', u'uid=newuser']
        new_superiors = [b'ou=newusers,dc=example,dc=org', u'ou=newusers,dc=example,dc=org']
        for entry in entries:
            for rdn in rdns:
                for new_superior in new_superiors:
                    mdnr = pureldap.LDAPModifyDNRequest(
                        entry=entry,
                        newrdn=rdn,
                        deleteoldrdn=False,
                        newSuperior=new_superior,
                    )
                    mdnr_repr = "LDAPModifyDNRequest(entry='uid=user,ou=users,dc=example,dc=org', " \
                                "newrdn='uid=newuser', deleteoldrdn=False, " \
                                "newSuperior='ou=newusers,dc=example,dc=org')"
                    self.assertEqual(repr(mdnr), mdnr_repr)

    def test_modify_dn_request_with_tag_repr(self):
        """LDAPModifyDNRequest.__repr__ with custom tag attribute"""
        entries = [b'uid=user,ou=users,dc=example,dc=org', u'uid=user,ou=users,dc=example,dc=org']
        rdns = [b'uid=newuser', u'uid=newuser']
        for entry in entries:
            for rdn in rdns:
                mdnr = pureldap.LDAPModifyDNRequest(
                    entry=entry,
                    newrdn=rdn,
                    deleteoldrdn=True,
                    tag=42,
                )
                mdnr_repr = "LDAPModifyDNRequest(entry='uid=user,ou=users,dc=example,dc=org', " \
                            "newrdn='uid=newuser', deleteoldrdn=True, tag=42)"
                self.assertEqual(repr(mdnr), mdnr_repr)

    def test_compare_request_repr(self):
        """LDAPCompareRequest.__repr__"""
        entries = [b'uid=user,ou=users,dc=example,dc=org', u'uid=user,ou=users,dc=example,dc=org']
        for entry in entries:
            cr = pureldap.LDAPCompareRequest(
                entry=entry,
                ava=pureldap.LDAPAttributeValueAssertion(
                    pureber.BEROctetString('key'),
                    pureber.BEROctetString('value'),
                ),
            )
            cr_repr = "LDAPCompareRequest(entry='uid=user,ou=users,dc=example,dc=org', " \
                      "ava=LDAPAttributeValueAssertion(attributeDesc=BEROctetString(value='key'), " \
                      "assertionValue=BEROctetString(value='value')))"
            self.assertEqual(repr(cr), cr_repr)

    def test_abandon_request_repr(self):
        """LDAPAbandonRequest.__repr__"""
        ar = pureldap.LDAPAbandonRequest(1)
        ar_repr = "LDAPAbandonRequest(id=1)"
        self.assertEqual(repr(ar), ar_repr)

    def test_abandon_request_with_tag_repr(self):
        """LDAPAbandonRequest.__repr__ with custom tag attribute"""
        ar = pureldap.LDAPAbandonRequest(1, tag=42)
        ar_repr = "LDAPAbandonRequest(id=1, tag=42)"
        self.assertEqual(repr(ar), ar_repr)

    def test_password_modify_request_repr(self):
        """LDAPPasswordModifyRequest.__repr__"""
        user_identities = [b'uid=user,ou=users,dc=example,dc=org', u'uid=user,ou=users,dc=example,dc=org']
        old_passwords = [b'qwerty', u'qwerty']
        new_passwords = [b'asdfgh', u'asdfgh']
        for user_identity in user_identities:
            for old_password in old_passwords:
                for new_password in new_passwords:
                    pmr = pureldap.LDAPPasswordModifyRequest(
                        userIdentity=user_identity,
                        oldPasswd=old_password,
                        newPasswd=new_password,
                    )
                    pmr_repr = "LDAPPasswordModifyRequest(userIdentity=LDAPPasswordModifyRequest_userIdentity(" \
                               "value='uid=user,ou=users,dc=example,dc=org'), " \
                               "oldPasswd=LDAPPasswordModifyRequest_oldPasswd(value='******'), " \
                               "newPasswd=LDAPPasswordModifyRequest_newPasswd(value='******'))"
                    self.assertEqual(repr(pmr), pmr_repr)

    def test_password_modify_request_with_tag_repr(self):
        """LDAPPasswordModifyRequest.__repr__ with custom tag attribute"""
        user_identities = [b'uid=user,ou=users,dc=example,dc=org', u'uid=user,ou=users,dc=example,dc=org']
        old_passwords = [b'qwerty', u'qwerty']
        new_passwords = [b'asdfgh', u'asdfgh']
        for user_identity in user_identities:
            for old_password in old_passwords:
                for new_password in new_passwords:
                    pmr = pureldap.LDAPPasswordModifyRequest(
                        userIdentity=user_identity,
                        oldPasswd=old_password,
                        newPasswd=new_password,
                        tag=42,
                    )
                    pmr_repr = "LDAPPasswordModifyRequest(userIdentity=LDAPPasswordModifyRequest_userIdentity(" \
                               "value='uid=user,ou=users,dc=example,dc=org'), " \
                               "oldPasswd=LDAPPasswordModifyRequest_oldPasswd(value='******'), " \
                               "newPasswd=LDAPPasswordModifyRequest_newPasswd(value='******'), tag=42)"
                    self.assertEqual(repr(pmr), pmr_repr)

    def test_starttls_request_repr(self):
        """LDAPStartTLSRequest.__repr__"""
        req = pureldap.LDAPStartTLSRequest()
        req_repr = "LDAPStartTLSRequest()"
        self.assertEqual(repr(req), req_repr)

    def test_starttls_request_with_tag_repr(self):
        """LDAPStartTLSRequest.__repr__ with custom tag attribute"""
        ar = pureldap.LDAPStartTLSRequest(tag=42)
        ar_repr = "LDAPStartTLSRequest(tag=42)"
        self.assertEqual(repr(ar), ar_repr)

    def test_starttls_response_repr(self):
        """LDAPStartTLSResponse.__repr__"""
        resp = pureldap.LDAPStartTLSResponse(resultCode=0)
        resp_repr = "LDAPStartTLSResponse()"
        self.assertEqual(repr(resp), resp_repr)

    def test_starttls_response_with_tag_repr(self):
        """LDAPStartTLSResponse.__repr__ with custom tag attribute"""
        resp = pureldap.LDAPStartTLSResponse(resultCode=0, tag=42)
        resp_repr = "LDAPStartTLSResponse(tag=42)"
        self.assertEqual(repr(resp), resp_repr)

    def test_attribute_value_assertion_repr(self):
        """LDAPAttributeValueAssertion.__repr__"""
        attributes = [(b'key', b'value'), (u'key', u'value')]
        for key, value in attributes:
            ava = pureldap.LDAPAttributeValueAssertion(
                pureber.BEROctetString(key),
                pureber.BEROctetString(value),
            )
            ava_repr = "LDAPAttributeValueAssertion(attributeDesc=BEROctetString(value='key'), " \
                       "assertionValue=BEROctetString(value='value'))"
            self.assertEqual(repr(ava), ava_repr)

    def test_attribute_value_assertion_with_tag_repr(self):
        """LDAPAttributeValueAssertion.__repr__ with custom tag attribute"""
        attributes = [(b'key', b'value'), (u'key', u'value')]
        for key, value in attributes:
            ava = pureldap.LDAPAttributeValueAssertion(
                pureber.BEROctetString(key),
                pureber.BEROctetString(value),
                tag=42,
            )
            ava_repr = "LDAPAttributeValueAssertion(attributeDesc=BEROctetString(value='key'), " \
                       "assertionValue=BEROctetString(value='value'), tag=42)"
            self.assertEqual(repr(ava), ava_repr)

    def test_ldapfilter_not_repr(self):
        """LDAPFilter_not.__repr__"""
        values = [b'value', u'value']
        for value in values:
            lf = pureldap.LDAPFilter_not(pureber.BEROctetString(value))
            lf_repr = "LDAPFilter_not(value=BEROctetString(value='value'))"
            self.assertEqual(repr(lf), lf_repr)

    def test_ldapfilter_not_with_tag_repr(self):
        """LDAPFilter_not.__repr__ with custom tag attribute"""
        values = [b'value', u'value']
        for value in values:
            lf = pureldap.LDAPFilter_not(pureber.BEROctetString(value), tag=42)
            lf_repr = "LDAPFilter_not(value=BEROctetString(value='value'), tag=42)"
            self.assertEqual(repr(lf), lf_repr)

    def test_ldapfilter_substrings_repr(self):
        """LDAPFilter_substrings.__repr__"""
        types = [b'cn', u'cn']
        values = [b'value', u'value']
        for tp in types:
            for value in values:
                lf = pureldap.LDAPFilter_substrings(
                    type=tp,
                    substrings=[pureldap.LDAPFilter_substrings_initial(value=value)],
                )
                lf_repr = "LDAPFilter_substrings(type='cn', " \
                          "substrings=[LDAPFilter_substrings_initial(value='value')])"
                self.assertEqual(repr(lf), lf_repr)

    def test_ldapfilter_substrings_with_tag_repr(self):
        """LDAPFilter_substrings.__repr__ with custom tag attribute"""
        types = [b'cn', u'cn']
        values = [b'value', u'value']
        for tp in types:
            for value in values:
                lf = pureldap.LDAPFilter_substrings(
                    type=tp,
                    substrings=[pureldap.LDAPFilter_substrings_initial(value=value)],
                    tag=42,
                )
                lf_repr = "LDAPFilter_substrings(type='cn', " \
                          "substrings=[LDAPFilter_substrings_initial(value='value')], tag=42)"
                self.assertEqual(repr(lf), lf_repr)

    def test_matching_rule_assertion_repr(self):
        """LDAPMatchingRuleAssertion.__repr__"""
        rules = [b'rule', u'rule']
        types = [b'type', u'type']
        values = [b'value', u'value']
        for rule in rules:
            for tp in types:
                for value in values:
                    mra = pureldap.LDAPMatchingRuleAssertion(rule, tp, value)
                    mra_repr = "LDAPMatchingRuleAssertion(matchingRule=LDAPMatchingRuleAssertion_matchingRule(" \
                               "value='rule'), type=LDAPMatchingRuleAssertion_type(value='type'), matchValue=" \
                               "LDAPMatchingRuleAssertion_matchValue(value='value'), dnAttributes=None)"
                    self.assertEqual(repr(mra), mra_repr)

    def test_matching_rule_assertion_with_tag_repr(self):
        """LDAPMatchingRuleAssertion.__repr__ with custom tag attribute"""
        rules = [b'rule', u'rule']
        types = [b'type', u'type']
        values = [b'value', u'value']
        for rule in rules:
            for tp in types:
                for value in values:
                    mra = pureldap.LDAPMatchingRuleAssertion(rule, tp, value, tag=42)
                    mra_repr = "LDAPMatchingRuleAssertion(matchingRule=LDAPMatchingRuleAssertion_matchingRule(" \
                               "value='rule'), type=LDAPMatchingRuleAssertion_type(value='type'), matchValue=" \
                               "LDAPMatchingRuleAssertion_matchValue(value='value'), dnAttributes=None, tag=42)"
                    self.assertEqual(repr(mra), mra_repr)

    def test_ldap_bind_response_server_sasl_creds_repr(self):
        """ ServerSaslCreds will often have binary data. A custom repr is needed because
        it cannot be turned into a unicode string like most BEROctetString objects.
        """
        sasl_creds = pureldap.LDAPBindResponse_serverSaslCreds(value=b'NTLMSSP\xbe')
        if six.PY3:
            expected_repr = r"LDAPBindResponse_serverSaslCreds(value=b'NTLMSSP\xbe')"
        else:
            expected_repr = "LDAPBindResponse_serverSaslCreds(value=NTLMSSP\xbe)"

        actual_repr = repr(sasl_creds)
        self.assertEqual(actual_repr, expected_repr)

    def test_ldap_bind_response_server_sasl_creds_with_tag_repr(self):
        """ ServerSaslCreds will often have binary data. A custom repr is needed because
        it cannot be turned into a unicode string like most BEROctetString objects.
        """
        sasl_creds = pureldap.LDAPBindResponse_serverSaslCreds(value=b'NTLMSSP\xbe', tag=12)
        if six.PY3:
            expected_repr = r"LDAPBindResponse_serverSaslCreds(value=b'NTLMSSP\xbe', tag=12)"
        else:
            expected_repr = "LDAPBindResponse_serverSaslCreds(value=NTLMSSP\xbe, tag=12)"

        actual_repr = repr(sasl_creds)
        self.assertEqual(actual_repr, expected_repr)
