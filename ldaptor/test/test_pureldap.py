"""
Test cases for ldaptor.protocols.pureldap module.
"""

from twisted.trial import unittest

from ldaptor.protocols import pureldap, pureber


def s(*l):
    """Join all members of list to a byte string. Integer members are chr()ed"""
    return b"".join([bytes((e,)) if isinstance(e, int) else e for e in l])


def l(s):
    """Split a byte string to ord's of chars."""
    return [[x][0] for x in s]


class KnownValues(unittest.TestCase):
    knownValues = (  # class, args, kwargs, expected_result
        (
            pureldap.LDAPModifyRequest,
            [],
            {
                "object": "cn=foo, dc=example, dc=com",
                "modification": [
                    pureber.BERSequence(
                        [
                            pureber.BEREnumerated(0),
                            pureber.BERSequence(
                                [
                                    pureldap.LDAPAttributeDescription("bar"),
                                    pureber.BERSet(
                                        [
                                            pureldap.LDAPString("a"),
                                            pureldap.LDAPString("b"),
                                        ]
                                    ),
                                ]
                            ),
                        ]
                    ),
                ],
            },
            None,
            [0x66, 50]
            + (
                [0x04, 0x1A]
                + l(b"cn=foo, dc=example, dc=com")
                + [0x30, 20]
                + (
                    [0x30, 18]
                    + (
                        [0x0A, 0x01, 0x00]
                        + [0x30, 13]
                        + (
                            [0x04, len(b"bar")]
                            + l(b"bar")
                            + [0x31, 0x06]
                            + (
                                [0x04, len(b"a")]
                                + l(b"a")
                                + [0x04, len(b"b")]
                                + l(b"b")
                            )
                        )
                    )
                )
            ),
        ),
        (
            pureldap.LDAPModifyRequest,
            [],
            {
                "object": "cn=foo, dc=example, dc=com",
                "modification": [
                    pureber.BERSequence(
                        [
                            pureber.BEREnumerated(1),
                            pureber.BERSequence(
                                [
                                    pureber.BEROctetString("bar"),
                                    pureber.BERSet([]),
                                ]
                            ),
                        ]
                    ),
                ],
            },
            None,
            [0x66, 0x2C]
            + (
                [0x04, 0x1A]
                + l(b"cn=foo, dc=example, dc=com")
                + [0x30, 0x0E]
                + (
                    [0x30, 0x0C]
                    + (
                        [0x0A, 0x01, 0x01]
                        + [0x30, 0x07]
                        + ([0x04, 0x03] + l(b"bar") + [0x31, 0x00])
                    )
                )
            ),
        ),
        (
            pureldap.LDAPFilter_not,
            [],
            {
                "value": pureldap.LDAPFilter_present("foo"),
            },
            pureldap.LDAPBERDecoderContext_Filter(fallback=pureber.BERDecoderContext()),
            [0xA2, 0x05] + [0x87] + [len(b"foo")] + l(b"foo"),
        ),
        (
            pureldap.LDAPFilter_or,
            [],
            {
                "value": [
                    pureldap.LDAPFilter_equalityMatch(
                        attributeDesc=pureldap.LDAPAttributeDescription(value="cn"),
                        assertionValue=pureldap.LDAPAssertionValue(value="foo"),
                    ),
                    pureldap.LDAPFilter_equalityMatch(
                        attributeDesc=pureldap.LDAPAttributeDescription(value="uid"),
                        assertionValue=pureldap.LDAPAssertionValue(value="foo"),
                    ),
                ]
            },
            pureldap.LDAPBERDecoderContext_Filter(fallback=pureber.BERDecoderContext()),
            [0xA1, 23]
            + [0xA3, 9]
            + [0x04]
            + [len(b"cn")]
            + l(b"cn")
            + [0x04]
            + [len(b"foo")]
            + l(b"foo")
            + [0xA3, 10]
            + [0x04]
            + [len(b"uid")]
            + l(b"uid")
            + [0x04]
            + [len(b"foo")]
            + l(b"foo"),
        ),
        (
            pureldap.LDAPFilter_and,
            [],
            {
                "value": [
                    pureldap.LDAPFilter_equalityMatch(
                        attributeDesc=pureldap.LDAPAttributeDescription(value="cn"),
                        assertionValue=pureldap.LDAPAssertionValue(value="foo"),
                    ),
                    pureldap.LDAPFilter_equalityMatch(
                        attributeDesc=pureldap.LDAPAttributeDescription(value="uid"),
                        assertionValue=pureldap.LDAPAssertionValue(value="foo"),
                    ),
                ]
            },
            pureldap.LDAPBERDecoderContext_Filter(fallback=pureber.BERDecoderContext()),
            [0xA0, 23]
            + [0xA3, 9]
            + [0x04]
            + [len(b"cn")]
            + l(b"cn")
            + [0x04]
            + [len(b"foo")]
            + l(b"foo")
            + [0xA3, 10]
            + [0x04]
            + [len(b"uid")]
            + l(b"uid")
            + [0x04]
            + [len(b"foo")]
            + l(b"foo"),
        ),
        (
            pureldap.LDAPModifyDNRequest,
            [],
            {
                "entry": "cn=foo,dc=example,dc=com",
                "newrdn": "uid=bar",
                "deleteoldrdn": 0,
            },
            None,
            [0x6C, 0x26]
            + [0x04]
            + [len(b"cn=foo,dc=example,dc=com")]
            + l(b"cn=foo,dc=example,dc=com")
            + [0x04]
            + [len(b"uid=bar")]
            + l(b"uid=bar")
            + [0x01, 0x01, 0x00],
        ),
        (
            pureldap.LDAPModifyDNRequest,
            [],
            {
                "entry": "cn=aoue,dc=example,dc=com",
                "newrdn": "uid=aoue",
                "deleteoldrdn": 0,
                "newSuperior": "ou=People,dc=example,dc=com",
            },
            None,
            [0x6C, 69]
            + [0x04]
            + [len(b"cn=aoue,dc=example,dc=com")]
            + l(b"cn=aoue,dc=example,dc=com")
            + [0x04]
            + [len(b"uid=aoue")]
            + l(b"uid=aoue")
            + [0x01, 0x01, 0x00]
            + [0x80]
            + [len(b"ou=People,dc=example,dc=com")]
            + l(b"ou=People,dc=example,dc=com"),
        ),
        (
            pureldap.LDAPSearchRequest,
            [],
            {
                "baseObject": "dc=yoja,dc=example,dc=com",
            },
            None,
            [0x63, 57]
            + [0x04]
            + [len(b"dc=yoja,dc=example,dc=com")]
            + l(b"dc=yoja,dc=example,dc=com")
            # scope
            + [0x0A, 1, 2]
            # derefAliases
            + [0x0A, 1, 0]
            # sizeLimit
            + [0x02, 1, 0]
            # timeLimit
            + [0x02, 1, 0]
            # typesOnly
            + [0x01, 1, 0]
            # filter
            + [135, 11] + l(b"objectClass")
            # attributes
            + [48, 0],
        ),
        (pureldap.LDAPUnbindRequest, [], {}, None, [0x42, 0x00]),
        (
            pureldap.LDAPSearchResultReference,
            [],
            {
                "uris": [
                    pureldap.LDAPString(b"ldap://example.com/dc=foo,dc=example,dc=com"),
                    pureldap.LDAPString(b"ldap://example.com/dc=bar,dc=example,dc=com"),
                ]
            },
            None,
            [0x73, 90]
            + [0x04]
            + [len(b"ldap://example.com/dc=foo,dc=example,dc=com")]
            + l(b"ldap://example.com/dc=foo,dc=example,dc=com")
            + [0x04]
            + [len(b"ldap://example.com/dc=bar,dc=example,dc=com")]
            + l(b"ldap://example.com/dc=bar,dc=example,dc=com"),
        ),
        (
            pureldap.LDAPSearchResultDone,
            [],
            {
                "resultCode": 0,
            },
            None,
            [0x65, 0x07]
            # resultCode
            + [0x0A, 0x01, 0x00]
            # matchedDN
            + [0x04] + [len(b"")] + l(b"")
            # errorMessage
            + [0x04] + [len(b"")] + l(b"")
            # referral, TODO
            + [],
        ),
        (
            pureldap.LDAPSearchResultDone,
            [],
            {
                "resultCode": 0,
                "matchedDN": "dc=foo,dc=example,dc=com",
            },
            None,
            [0x65, 31]
            # resultCode
            + [0x0A, 0x01, 0x00]
            # matchedDN
            + [0x04]
            + [len(b"dc=foo,dc=example,dc=com")]
            + l(b"dc=foo,dc=example,dc=com")
            # errorMessage
            + [0x04] + [len(b"")] + l(b"")
            # referral, TODO
            + [],
        ),
        (
            pureldap.LDAPSearchResultDone,
            [],
            {
                "resultCode": 0,
                "matchedDN": "dc=foo,dc=example,dc=com",
                "errorMessage": "the foobar was fubar",
            },
            None,
            [0x65, 51]
            # resultCode
            + [0x0A, 0x01, 0x00]
            # matchedDN
            + [0x04]
            + [len(b"dc=foo,dc=example,dc=com")]
            + l(b"dc=foo,dc=example,dc=com")
            # errorMessage
            + [0x04]
            + [len(b"the foobar was fubar")]
            + l(
                b"the foobar was fubar",
            )
            # referral, TODO
            + [],
        ),
        (
            pureldap.LDAPSearchResultDone,
            [],
            {
                "resultCode": 0,
                "errorMessage": "the foobar was fubar",
            },
            None,
            [0x65, 27]
            # resultCode
            + [0x0A, 0x01, 0x00]
            # matchedDN
            + [0x04] + [len(b"")] + l(b"")
            # errorMessage
            + [0x04]
            + [len(b"the foobar was fubar")]
            + l(
                b"the foobar was fubar",
            )
            # referral, TODO
            + [],
        ),
        (
            pureldap.LDAPMessage,
            [],
            {
                "id": 42,
                "value": pureldap.LDAPBindRequest(),
            },
            pureldap.LDAPBERDecoderContext_TopLevel(
                inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
                    fallback=pureldap.LDAPBERDecoderContext(
                        fallback=pureber.BERDecoderContext()
                    ),
                    inherit=pureldap.LDAPBERDecoderContext(
                        fallback=pureber.BERDecoderContext()
                    ),
                )
            ),
            [0x30, 12]
            # id
            + [0x02, 0x01, 42]
            # value
            + l(pureldap.LDAPBindRequest().toWire()),
        ),
        (
            pureldap.LDAPControl,
            [],
            {
                "controlType": "1.2.3.4",
            },
            None,
            [0x30, 9]
            # controlType
            + [0x04, 7] + l(b"1.2.3.4"),
        ),
        (
            pureldap.LDAPControl,
            [],
            {
                "controlType": "1.2.3.4",
                "criticality": True,
            },
            None,
            [0x30, 12]
            # controlType
            + [0x04, 7] + l(b"1.2.3.4")
            # criticality
            + [0x01, 1, 0xFF],
        ),
        (
            pureldap.LDAPControl,
            [],
            {
                "controlType": "1.2.3.4",
                "criticality": True,
                "controlValue": "silly",
            },
            None,
            [0x30, 19]
            # controlType
            + [0x04, 7] + l(b"1.2.3.4")
            # criticality
            + [0x01, 1, 0xFF]
            # controlValue
            + [0x04, len(b"silly")] + l(b"silly"),
        ),
        (
            pureldap.LDAPMessage,
            [],
            {
                "id": 42,
                "value": pureldap.LDAPBindRequest(),
                "controls": [
                    ("1.2.3.4", None, None),
                    ("2.3.4.5", False),
                    ("3.4.5.6", True, b"\x00\x01\x02\xFF"),
                    ("4.5.6.7", None, b"\x00\x01\x02\xFF"),
                ],
            },
            pureldap.LDAPBERDecoderContext_TopLevel(
                inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
                    fallback=pureldap.LDAPBERDecoderContext(
                        fallback=pureber.BERDecoderContext()
                    ),
                    inherit=pureldap.LDAPBERDecoderContext(
                        fallback=pureber.BERDecoderContext()
                    ),
                )
            ),
            [0x30, 76]
            # id
            + [0x02, 0x01, 42]
            # value
            + l(pureldap.LDAPBindRequest().toWire())
            # controls
            + l(
                pureldap.LDAPControls(
                    value=[
                        pureldap.LDAPControl(controlType="1.2.3.4"),
                        pureldap.LDAPControl(controlType="2.3.4.5", criticality=False),
                        pureldap.LDAPControl(
                            controlType="3.4.5.6",
                            criticality=True,
                            controlValue=b"\x00\x01\x02\xFF",
                        ),
                        pureldap.LDAPControl(
                            controlType="4.5.6.7",
                            criticality=None,
                            controlValue=b"\x00\x01\x02\xFF",
                        ),
                    ]
                ).toWire()
            ),
        ),
        (
            pureldap.LDAPFilter_equalityMatch,
            [],
            {
                "attributeDesc": pureldap.LDAPAttributeDescription("cn"),
                "assertionValue": pureldap.LDAPAssertionValue("foo"),
            },
            pureldap.LDAPBERDecoderContext_Filter(
                fallback=pureldap.LDAPBERDecoderContext(
                    fallback=pureber.BERDecoderContext()
                ),
                inherit=pureldap.LDAPBERDecoderContext(
                    fallback=pureber.BERDecoderContext()
                ),
            ),
            [0xA3, 9] + ([0x04, 2] + l(b"cn") + [0x04, 3] + l(b"foo")),
        ),
        (
            pureldap.LDAPFilter_or,
            [
                [
                    pureldap.LDAPFilter_equalityMatch(
                        attributeDesc=pureldap.LDAPAttributeDescription("cn"),
                        assertionValue=pureldap.LDAPAssertionValue("foo"),
                    ),
                    pureldap.LDAPFilter_equalityMatch(
                        attributeDesc=pureldap.LDAPAttributeDescription("uid"),
                        assertionValue=pureldap.LDAPAssertionValue("foo"),
                    ),
                    pureldap.LDAPFilter_equalityMatch(
                        attributeDesc=pureldap.LDAPAttributeDescription("mail"),
                        assertionValue=pureldap.LDAPAssertionValue("foo"),
                    ),
                    pureldap.LDAPFilter_substrings(
                        type="mail",
                        substrings=[pureldap.LDAPFilter_substrings_initial("foo@")],
                    ),
                ]
            ],
            {},
            pureldap.LDAPBERDecoderContext_Filter(
                fallback=pureldap.LDAPBERDecoderContext(
                    fallback=pureber.BERDecoderContext()
                ),
                inherit=pureldap.LDAPBERDecoderContext(
                    fallback=pureber.BERDecoderContext()
                ),
            ),
            [0xA1, 52]
            + (
                [0xA3, 9]
                + ([0x04, 2] + l(b"cn") + [0x04, 3] + l(b"foo"))
                + [0xA3, 10]
                + ([0x04, 3] + l(b"uid") + [0x04, 3] + l(b"foo"))
                + [0xA3, 11]
                + ([0x04, 4] + l(b"mail") + [0x04, 3] + l(b"foo"))
                + [0xA4, 14]
                + ([0x04, 4] + l(b"mail") + [0x30, 6] + ([0x80, 4] + l(b"foo@")))
            ),
        ),
        (
            pureldap.LDAPSearchRequest,
            [],
            {
                "baseObject": "dc=example,dc=com",
                "scope": pureldap.LDAP_SCOPE_wholeSubtree,
                "derefAliases": pureldap.LDAP_DEREF_neverDerefAliases,
                "sizeLimit": 1,
                "timeLimit": 0,
                "typesOnly": False,
                "filter": pureldap.LDAPFilter_or(
                    [
                        pureldap.LDAPFilter_equalityMatch(
                            attributeDesc=pureldap.LDAPAttributeDescription("cn"),
                            assertionValue=pureldap.LDAPAssertionValue("foo"),
                        ),
                        pureldap.LDAPFilter_equalityMatch(
                            attributeDesc=pureldap.LDAPAttributeDescription("uid"),
                            assertionValue=pureldap.LDAPAssertionValue("foo"),
                        ),
                        pureldap.LDAPFilter_equalityMatch(
                            attributeDesc=pureldap.LDAPAttributeDescription("mail"),
                            assertionValue=pureldap.LDAPAssertionValue("foo"),
                        ),
                        pureldap.LDAPFilter_substrings(
                            type="mail",
                            substrings=[pureldap.LDAPFilter_substrings_initial("foo@")],
                        ),
                    ]
                ),
                "attributes": [""],
            },
            pureldap.LDAPBERDecoderContext_LDAPMessage(
                fallback=pureldap.LDAPBERDecoderContext(
                    fallback=pureber.BERDecoderContext()
                ),
                inherit=pureldap.LDAPBERDecoderContext(
                    fallback=pureber.BERDecoderContext()
                ),
            ),
            [0x63, 92]
            + (
                [0x04, 17]
                + l(b"dc=example,dc=com")
                + [0x0A, 1, 0x02]
                + [0x0A, 1, 0x00]
                + [0x02, 1, 0x01]
                + [0x02, 1, 0x00]
                + [0x01, 1, 0x00]
                + [0xA1, 52]
                + (
                    [0xA3, 9]
                    + ([0x04, 2] + l(b"cn") + [0x04, 3] + l(b"foo"))
                    + [0xA3, 10]
                    + ([0x04, 3] + l(b"uid") + [0x04, 3] + l(b"foo"))
                    + [0xA3, 11]
                    + ([0x04, 4] + l(b"mail") + [0x04, 3] + l(b"foo"))
                    + [0xA4, 14]
                    + ([0x04, 4] + l(b"mail") + [0x30, 6] + ([0x80, 4] + l(b"foo@")))
                )
                + [0x30, 2]
                + ([0x04, 0])
            ),
        ),
        (
            pureldap.LDAPMessage,
            [],
            {
                "id": 1,
                "value": pureldap.LDAPSearchRequest(
                    baseObject="dc=example,dc=com",
                    scope=pureldap.LDAP_SCOPE_wholeSubtree,
                    derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
                    sizeLimit=1,
                    timeLimit=0,
                    typesOnly=False,
                    filter=pureldap.LDAPFilter_or(
                        [
                            pureldap.LDAPFilter_equalityMatch(
                                attributeDesc=pureldap.LDAPAttributeDescription("cn"),
                                assertionValue=pureldap.LDAPAssertionValue("foo"),
                            ),
                            pureldap.LDAPFilter_equalityMatch(
                                attributeDesc=pureldap.LDAPAttributeDescription("uid"),
                                assertionValue=pureldap.LDAPAssertionValue("foo"),
                            ),
                            pureldap.LDAPFilter_equalityMatch(
                                attributeDesc=pureldap.LDAPAttributeDescription("mail"),
                                assertionValue=pureldap.LDAPAssertionValue("foo"),
                            ),
                            pureldap.LDAPFilter_substrings(
                                type="mail",
                                substrings=[
                                    pureldap.LDAPFilter_substrings_initial("foo@")
                                ],
                            ),
                        ]
                    ),
                    attributes=[""],
                ),
            },
            pureldap.LDAPBERDecoderContext_TopLevel(
                inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
                    fallback=pureldap.LDAPBERDecoderContext(
                        fallback=pureber.BERDecoderContext()
                    ),
                    inherit=pureldap.LDAPBERDecoderContext(
                        fallback=pureber.BERDecoderContext()
                    ),
                )
            ),
            [0x30, 97]
            # id
            + [0x02, 1, 1]
            # value
            + [0x63, 92]
            + (
                [0x04, 17]
                + l(b"dc=example,dc=com")
                + [0x0A, 1, 0x02]
                + [0x0A, 1, 0x00]
                + [0x02, 1, 0x01]
                + [0x02, 1, 0x00]
                + [0x01, 1, 0x00]
                + [0xA1, 52]
                + (
                    [0xA3, 9]
                    + ([0x04, 2] + l(b"cn") + [0x04, 3] + l(b"foo"))
                    + [0xA3, 10]
                    + ([0x04, 3] + l(b"uid") + [0x04, 3] + l(b"foo"))
                    + [0xA3, 11]
                    + ([0x04, 4] + l(b"mail") + [0x04, 3] + l(b"foo"))
                    + [0xA4, 14]
                    + ([0x04, 4] + l(b"mail") + [0x30, 6] + ([0x80, 4] + l(b"foo@")))
                )
                + [0x30, 2]
                + ([0x04, 0])
            ),
        ),
        (
            pureldap.LDAPExtendedRequest,
            [],
            {
                "requestName": "42.42.42",
                "requestValue": "foo",
            },
            None,
            [0x40 | 0x20 | 23, 1 + 1 + 8 + 1 + 1 + 3]
            + ([0x80 | 0] + [len(b"42.42.42")] + l(b"42.42.42"))
            + ([0x80 | 1] + [len(b"foo")] + l(b"foo")),
        ),
        (
            pureldap.LDAPExtendedRequest,
            [],
            {
                "requestName": "42.42.42",
                "requestValue": None,
            },
            None,
            [0x40 | 0x20 | 23, 1 + 1 + 8]
            + ([0x80 | 0] + [len(b"42.42.42")] + l(b"42.42.42")),
        ),
        (
            pureldap.LDAPExtendedResponse,
            [],
            {
                "resultCode": 49,
                "matchedDN": "foo",
                "errorMessage": "bar",
                "responseName": None,
                "response": None,
            },
            None,
            [0x40 | 0x20 | 24, 3 + 2 + 3 + 2 + 3, 0x0A, 1, 49, 0x04, len(b"foo")]
            + l(b"foo")
            + [0x04, len(b"bar")]
            + l(b"bar"),
        ),
        (
            pureldap.LDAPExtendedResponse,
            [],
            {
                "resultCode": 49,
                "matchedDN": "foo",
                "errorMessage": "bar",
                "responseName": "1.2.3.4.5.6.7.8.9",
                "response": "baz",
            },
            None,
            [
                0x40 | 0x20 | 24,
                3 + 2 + 3 + 2 + 3 + 2 + len("1.2.3.4.5.6.7.8.9") + 2 + 3,
                0x0A,
                1,
                49,
                0x04,
                len(b"foo"),
            ]
            + l(b"foo")
            + [0x04, len(b"bar")]
            + l(b"bar")
            + [0x8A, len(b"1.2.3.4.5.6.7.8.9")]
            + l(b"1.2.3.4.5.6.7.8.9")
            + [0x8B, len(b"baz")]
            + l(b"baz"),
        ),
        (pureldap.LDAPAbandonRequest, [], {"id": 3}, None, [0x40 | 0x10, 0x01, 3]),
        (
            pureldap.LDAPBindRequest,
            [],
            {"auth": ("PLAIN", "test"), "sasl": True},
            pureldap.LDAPBERDecoderContext(
                fallback=pureldap.LDAPBERDecoderContext(
                    fallback=pureber.BERDecoderContext()
                ),
                inherit=pureldap.LDAPBERDecoderContext(
                    fallback=pureber.BERDecoderContext()
                ),
            ),
            l(pureldap.LDAPBindRequest(auth=("PLAIN", "test"), sasl=True).toWire()),
        ),
    )

    def testToLDAP(self):
        """LDAPClass(...).toWire() should give known result with known input"""
        for klass, args, kwargs, decoder, encoded in self.knownValues:
            result = klass(*args, **kwargs)
            result = result.toWire()
            result = l(result)

            message = "Class %s(*%r, **%r) doesn't encode properly: " "%r != %r" % (
                klass.__name__,
                args,
                kwargs,
                result,
                encoded,
            )
            self.assertEqual(encoded, result, message)

    def testFromLDAP(self):
        """LDAPClass(encoded="...") should give known result with known input"""
        for klass, args, kwargs, decoder, encoded in self.knownValues:
            if decoder is None:
                decoder = pureldap.LDAPBERDecoderContext(
                    fallback=pureber.BERDecoderContext()
                )
            m = s(*encoded)
            result, bytes = pureber.berDecodeObject(decoder, m)
            self.assertEqual(bytes, len(m))

            shouldBe = klass(*args, **kwargs)
            assert (
                result.toWire() == shouldBe.toWire()
            ), "Class %s(*%s, **%s) doesn't decode properly: " "%s != %s" % (
                klass.__name__,
                repr(args),
                repr(kwargs),
                repr(result),
                repr(shouldBe),
            )

    def testPartial(self):
        """LDAPClass(encoded="...") with too short input should throw BERExceptionInsufficientData"""
        for klass, args, kwargs, decoder, encoded in self.knownValues:
            if decoder is None:
                decoder = pureldap.LDAPBERDecoderContext(
                    fallback=pureber.BERDecoderContext()
                )
            for i in range(1, len(encoded)):
                m = s(*encoded)[:i]
                self.assertRaises(
                    pureber.BERExceptionInsufficientData,
                    pureber.berDecodeObject,
                    decoder,
                    m,
                )
            self.assertEqual((None, 0), pureber.berDecodeObject(decoder, ""))


class TestEquality(unittest.TestCase):
    valuesToTest = (
        (
            pureldap.LDAPFilter_equalityMatch,
            [
                pureldap.LDAPAttributeDescription(value="cn"),
                pureldap.LDAPAssertionValue(value="foo"),
            ],
        ),
        (
            pureldap.LDAPFilter_equalityMatch,
            [
                pureldap.LDAPAttributeDescription(value="cn"),
                pureldap.LDAPAssertionValue(value="bar"),
            ],
        ),
        (pureber.BERInteger, [0]),
    )

    def testEquality(self):
        """LDAP objects equal LDAP objects with same type and content"""
        for class_, args in self.valuesToTest:
            x = class_(*args)
            y = class_(*args)
            self.assertEqual(x, x)
            self.assertEqual(x, y)

    def testInEquality(self):
        """LDAP objects do not equal LDAP objects with different type or content"""
        for i in range(len(self.valuesToTest)):
            for j in range(len(self.valuesToTest)):
                if i != j:
                    i_class, i_args = self.valuesToTest[i]
                    j_class, j_args = self.valuesToTest[j]
                    x = i_class(*i_args)
                    y = j_class(*j_args)
                    self.assertNotEqual(x, y)


class Substrings(unittest.TestCase):
    def test_length(self):
        """LDAPFilter_substrings.substrings behaves like a proper list."""
        decoder = pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext())
        filt = pureldap.LDAPFilter_substrings.fromBER(
            tag=pureldap.LDAPFilter_substrings.tag,
            content=s(0x04, 4, b"mail", 0x30, 6, 0x80, 4, b"foo@"),
            berdecoder=decoder,
        )
        # The confusion that used to occur here was because
        # filt.substrings was left as a BERSequence, which under the
        # current str()-to-wire-protocol system had len() > 1 even
        # when empty, and that tripped e.g. entry.match()
        self.assertEqual(len(filt.substrings), 1)


class TestEscaping(unittest.TestCase):
    def test_escape(self):
        s = "\\*()\0"

        result = pureldap.escape(s)
        expected = "\\5c\\2a\\28\\29\\00"

        self.assertEqual(expected, result)

    def test_binary_escape(self):
        s = "HELLO"

        result = pureldap.binary_escape(s)
        expected = "\\48\\45\\4c\\4c\\4f"

        self.assertEqual(expected, result)

    def test_smart_escape_regular(self):
        s = "HELLO"

        result = pureldap.smart_escape(s)
        expected = "HELLO"

        self.assertEqual(expected, result)

    def test_smart_escape_binary(self):
        s = "\x10\x11\x12\x13\x14"

        result = pureldap.smart_escape(s)
        expected = "\\10\\11\\12\\13\\14"

        self.assertEqual(expected, result)

    def test_smart_escape_threshold(self):
        s = "\x10\x11ABC"

        result = pureldap.smart_escape(s, threshold=0.10)
        expected = "\\10\\11\\41\\42\\43"

        self.assertEqual(expected, result)

    def test_default_escaper(self):
        chars = "\\*()\0"
        escaped_chars = "\\5c\\2a\\28\\29\\00"

        filters = [
            (
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("key"),
                    assertionValue=pureldap.LDAPAttributeValue(chars),
                ),
                f"(key={escaped_chars})",
            ),
            (
                pureldap.LDAPFilter_substrings_initial(value=chars),
                f"{escaped_chars}",
            ),
            (
                pureldap.LDAPFilter_substrings_any(value=chars),
                f"{escaped_chars}",
            ),
            (
                pureldap.LDAPFilter_substrings_final(value=chars),
                f"{escaped_chars}",
            ),
            (
                pureldap.LDAPFilter_greaterOrEqual(
                    attributeDesc=pureldap.LDAPString("key"),
                    assertionValue=pureldap.LDAPString(chars),
                ),
                f"(key>={escaped_chars})",
            ),
            (
                pureldap.LDAPFilter_lessOrEqual(
                    attributeDesc=pureldap.LDAPString("key"),
                    assertionValue=pureldap.LDAPString(chars),
                ),
                f"(key<={escaped_chars})",
            ),
            (
                pureldap.LDAPFilter_approxMatch(
                    attributeDesc=pureldap.LDAPString("key"),
                    assertionValue=pureldap.LDAPString(chars),
                ),
                f"(key~={escaped_chars})",
            ),
        ]

        for filt, expected in filters:
            result = filt.asText()
            self.assertEqual(expected, result)

    def test_custom_escaper(self):
        chars = "HELLO"
        escaped_chars = "0b10010000b10001010b10011000b10011000b1001111"

        def custom_escaper(s):
            return "".join(bin(ord(c)) for c in s)

        filters = [
            (
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("key"),
                    assertionValue=pureldap.LDAPAttributeValue(chars),
                    escaper=custom_escaper,
                ),
                f"(key={escaped_chars})",
            ),
            (
                pureldap.LDAPFilter_substrings_initial(
                    value=chars, escaper=custom_escaper
                ),
                f"{escaped_chars}",
            ),
            (
                pureldap.LDAPFilter_substrings_any(value=chars, escaper=custom_escaper),
                f"{escaped_chars}",
            ),
            (
                pureldap.LDAPFilter_substrings_final(
                    value=chars, escaper=custom_escaper
                ),
                f"{escaped_chars}",
            ),
            (
                pureldap.LDAPFilter_greaterOrEqual(
                    attributeDesc=pureldap.LDAPString("key"),
                    assertionValue=pureldap.LDAPString(chars),
                    escaper=custom_escaper,
                ),
                f"(key>={escaped_chars})",
            ),
            (
                pureldap.LDAPFilter_lessOrEqual(
                    attributeDesc=pureldap.LDAPString("key"),
                    assertionValue=pureldap.LDAPString(chars),
                    escaper=custom_escaper,
                ),
                f"(key<={escaped_chars})",
            ),
            (
                pureldap.LDAPFilter_approxMatch(
                    attributeDesc=pureldap.LDAPString("key"),
                    assertionValue=pureldap.LDAPString(chars),
                    escaper=custom_escaper,
                ),
                f"(key~={escaped_chars})",
            ),
        ]

        for filt, expected in filters:
            result = filt.asText()
            self.assertEqual(expected, result)


class TestFilterSetEquality(unittest.TestCase):
    def test_basic_and_equal(self):
        filter1 = pureldap.LDAPFilter_and(
            [
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("foo"),
                    assertionValue=pureldap.LDAPAttributeValue("1"),
                ),
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("bar"),
                    assertionValue=pureldap.LDAPAttributeValue("2"),
                ),
            ]
        )
        filter2 = pureldap.LDAPFilter_and(
            [
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("bar"),
                    assertionValue=pureldap.LDAPAttributeValue("2"),
                ),
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("foo"),
                    assertionValue=pureldap.LDAPAttributeValue("1"),
                ),
            ]
        )

        self.assertEqual(filter1, filter2)

    def test_basic_and_not_equal(self):
        filter1 = pureldap.LDAPFilter_and(
            [
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("foo"),
                    assertionValue=pureldap.LDAPAttributeValue("1"),
                ),
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("bar"),
                    assertionValue=pureldap.LDAPAttributeValue("2"),
                ),
            ]
        )
        filter2 = pureldap.LDAPFilter_and(
            [
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("bar"),
                    assertionValue=pureldap.LDAPAttributeValue("1"),
                ),
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("foo"),
                    assertionValue=pureldap.LDAPAttributeValue("1"),
                ),
            ]
        )

        self.assertNotEqual(filter1, filter2)

    def test_basic_or_equal(self):
        filter1 = pureldap.LDAPFilter_or(
            [
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("foo"),
                    assertionValue=pureldap.LDAPAttributeValue("1"),
                ),
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("bar"),
                    assertionValue=pureldap.LDAPAttributeValue("2"),
                ),
            ]
        )
        filter2 = pureldap.LDAPFilter_or(
            [
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("bar"),
                    assertionValue=pureldap.LDAPAttributeValue("2"),
                ),
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("foo"),
                    assertionValue=pureldap.LDAPAttributeValue("1"),
                ),
            ]
        )

        self.assertEqual(filter1, filter2)

    def test_basic_or_not_equal(self):
        filter1 = pureldap.LDAPFilter_or(
            [
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("foo"),
                    assertionValue=pureldap.LDAPAttributeValue("1"),
                ),
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("bar"),
                    assertionValue=pureldap.LDAPAttributeValue("2"),
                ),
            ]
        )
        filter2 = pureldap.LDAPFilter_or(
            [
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("bar"),
                    assertionValue=pureldap.LDAPAttributeValue("1"),
                ),
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("foo"),
                    assertionValue=pureldap.LDAPAttributeValue("1"),
                ),
            ]
        )

        self.assertNotEqual(filter1, filter2)

    def test_nested_equal(self):
        filter1 = pureldap.LDAPFilter_or(
            [
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("foo"),
                    assertionValue=pureldap.LDAPAttributeValue("1"),
                ),
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("bar"),
                    assertionValue=pureldap.LDAPAttributeValue("2"),
                ),
                pureldap.LDAPFilter_and(
                    [
                        pureldap.LDAPFilter_equalityMatch(
                            attributeDesc=pureldap.LDAPAttributeDescription("baz"),
                            assertionValue=pureldap.LDAPAttributeValue("1"),
                        ),
                        pureldap.LDAPFilter_equalityMatch(
                            attributeDesc=pureldap.LDAPAttributeDescription("bob"),
                            assertionValue=pureldap.LDAPAttributeValue("2"),
                        ),
                    ]
                ),
            ]
        )
        filter2 = pureldap.LDAPFilter_or(
            [
                pureldap.LDAPFilter_and(
                    [
                        pureldap.LDAPFilter_equalityMatch(
                            attributeDesc=pureldap.LDAPAttributeDescription("bob"),
                            assertionValue=pureldap.LDAPAttributeValue("2"),
                        ),
                        pureldap.LDAPFilter_equalityMatch(
                            attributeDesc=pureldap.LDAPAttributeDescription("baz"),
                            assertionValue=pureldap.LDAPAttributeValue("1"),
                        ),
                    ]
                ),
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("bar"),
                    assertionValue=pureldap.LDAPAttributeValue("2"),
                ),
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("foo"),
                    assertionValue=pureldap.LDAPAttributeValue("1"),
                ),
            ]
        )

        self.assertEqual(filter1, filter2)

    def test_escape_and_equal(self):

        filter1 = pureldap.LDAPFilter_and(
            [
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("foo"),
                    assertionValue=pureldap.LDAPAttributeValue("1"),
                ),
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("foo"),
                    assertionValue=pureldap.LDAPAttributeValue("2"),
                ),
            ]
        )
        filter2 = pureldap.LDAPFilter_and(
            [
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("foo"),
                    assertionValue=pureldap.LDAPAttributeValue("1"),
                ),
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription("foo"),
                    assertionValue=pureldap.LDAPAttributeValue("2"),
                ),
            ]
        )

        self.assertEqual(filter1, filter2)


class Representations(unittest.TestCase):
    def test_message_repr(self):
        page_size = 10
        cookie = "xyzzy"
        control_value = pureber.BERSequence(
            [
                pureber.BERInteger(page_size),
                pureber.BEROctetString(cookie),
            ]
        )
        controls = [("1.2.840.113556.1.4.319", None, control_value)]
        search_request = pureldap.LDAPSearchRequest("cn=foo,ou=baz,dc=example,dc=org")
        ldap_msg = pureldap.LDAPMessage(
            id=1, value=search_request, controls=controls, tag=1
        )
        expected_value = "LDAPMessage(id=1, value=LDAPSearchRequest(baseObject='cn=foo,ou=baz,dc=example,dc=org', scope=2, derefAliases=0, sizeLimit=0, timeLimit=0, typesOnly=0, filter=LDAPFilter_present(value='objectClass'), attributes=[]), controls=[('1.2.840.113556.1.4.319', None, BERSequence(value=[BERInteger(value=10), BEROctetString(value='xyzzy')]))], tag=1)"
        self.assertEqual(expected_value, repr(ldap_msg))


class TestRepresentations(unittest.TestCase):
    """
    Test representations of common LDAP opbjects.
    """

    def test_bind_request_repr(self):
        """LDAPBindRequest.__repr__"""
        self.assertEqual(
            repr(pureldap.LDAPBindRequest(dn=b"uid=user,ou=users,dc=example,dc=org")),
            (
                "LDAPBindRequest(version=3, dn=b'uid=user,ou=users,dc=example,dc=org', "
                "auth='', sasl=False)"
            ),
        )
        self.assertEqual(
            repr(pureldap.LDAPBindRequest(dn="uid=user,ou=users,dc=example,dc=org")),
            (
                "LDAPBindRequest(version=3, dn='uid=user,ou=users,dc=example,dc=org', "
                "auth='', sasl=False)"
            ),
        )

    def test_bind_request_with_tag_repr(self):
        """LDAPBindRequest.__repr__ with custom tag attribute"""
        self.assertEqual(
            repr(
                pureldap.LDAPBindRequest(
                    dn=b"uid=user,ou=users,dc=example,dc=org", auth=b"pass", tag=42
                )
            ),
            (
                "LDAPBindRequest(version=3, dn=b'uid=user,ou=users,dc=example,dc=org', "
                "auth='****', tag=42, sasl=False)"
            ),
        )
        self.assertEqual(
            repr(
                pureldap.LDAPBindRequest(
                    dn="uid=user,ou=users,dc=example,dc=org", auth="pass", tag=42
                )
            ),
            (
                "LDAPBindRequest(version=3, dn='uid=user,ou=users,dc=example,dc=org', "
                "auth='****', tag=42, sasl=False)"
            ),
        )

    def test_bind_response_repr(self):
        """LDAPBindResponse.__repr__"""
        self.assertEqual(
            repr(
                pureldap.LDAPBindResponse(
                    resultCode=0, matchedDN=b"uid=user,ou=users,dc=example,dc=org"
                )
            ),
            "LDAPBindResponse(resultCode=0, matchedDN=b'uid=user,ou=users,dc=example,dc=org')",
        )
        self.assertEqual(
            repr(
                pureldap.LDAPBindResponse(
                    resultCode=0, matchedDN="uid=user,ou=users,dc=example,dc=org"
                )
            ),
            "LDAPBindResponse(resultCode=0, matchedDN='uid=user,ou=users,dc=example,dc=org')",
        )

    def test_result_with_matched_dn_repr(self):
        """LDAPResult.__repr__ with matchedDN attribute"""
        self.assertEqual(
            repr(
                pureldap.LDAPResult(
                    resultCode=0, matchedDN=b"uid=user,ou=users,dc=example,dc=org"
                )
            ),
            "LDAPResult(resultCode=0, matchedDN=b'uid=user,ou=users,dc=example,dc=org')",
        )
        self.assertEqual(
            repr(
                pureldap.LDAPResult(
                    resultCode=0, matchedDN="uid=user,ou=users,dc=example,dc=org"
                )
            ),
            "LDAPResult(resultCode=0, matchedDN='uid=user,ou=users,dc=example,dc=org')",
        )

    def test_result_with_error_message_repr(self):
        """LDAPResult.__repr__ with errorMessage attribute"""
        self.assertEqual(
            repr(pureldap.LDAPResult(resultCode=1, errorMessage=b"error_message")),
            "LDAPResult(resultCode=1, errorMessage=b'error_message')",
        )
        self.assertEqual(
            repr(pureldap.LDAPResult(resultCode=1, errorMessage="error_message")),
            "LDAPResult(resultCode=1, errorMessage='error_message')",
        )

    def test_result_with_tag_repr(self):
        """LDAPResult.__repr__ with custom tag attribute"""
        res = pureldap.LDAPResult(resultCode=0, tag=42)
        res_repr = "LDAPResult(resultCode=0, tag=42)"
        self.assertEqual(repr(res), res_repr)

    def test_search_request_repr(self):
        """LDAPSearchRequest.__repr__"""
        self.assertEqual(
            repr(
                pureldap.LDAPSearchRequest(
                    baseObject=b"ou=users,dc=example,dc=org",
                    filter=pureldap.LDAPFilter_equalityMatch(
                        attributeDesc=pureber.BEROctetString(b"key"),
                        assertionValue=pureber.BEROctetString(b"value"),
                    ),
                )
            ),
            (
                "LDAPSearchRequest(baseObject=b'ou=users,dc=example,dc=org', scope=2, derefAliases=0, "
                "sizeLimit=0, timeLimit=0, typesOnly=0, filter=LDAPFilter_equalityMatch("
                "attributeDesc=BEROctetString(value=b'key'), assertionValue=BEROctetString(value=b'value')), "
                "attributes=[])"
            ),
        )
        self.assertEqual(
            repr(
                pureldap.LDAPSearchRequest(
                    baseObject="ou=users,dc=example,dc=org",
                    filter=pureldap.LDAPFilter_equalityMatch(
                        attributeDesc=pureber.BEROctetString("key"),
                        assertionValue=pureber.BEROctetString("value"),
                    ),
                )
            ),
            (
                "LDAPSearchRequest(baseObject='ou=users,dc=example,dc=org', scope=2, derefAliases=0, "
                "sizeLimit=0, timeLimit=0, typesOnly=0, filter=LDAPFilter_equalityMatch("
                "attributeDesc=BEROctetString(value='key'), assertionValue=BEROctetString(value='value')), "
                "attributes=[])"
            ),
        )

    def test_search_request_with_tag_repr(self):
        """LDAPSearchRequest.__repr__ with custom tag attribute"""
        self.assertEqual(
            repr(
                pureldap.LDAPSearchRequest(
                    baseObject=b"ou=users,dc=example,dc=org",
                    filter=pureldap.LDAPFilter_equalityMatch(
                        attributeDesc=pureber.BEROctetString(b"key"),
                        assertionValue=pureber.BEROctetString(b"value"),
                    ),
                    tag=42,
                )
            ),
            (
                "LDAPSearchRequest(baseObject=b'ou=users,dc=example,dc=org', scope=2, derefAliases=0, "
                "sizeLimit=0, timeLimit=0, typesOnly=0, filter=LDAPFilter_equalityMatch("
                "attributeDesc=BEROctetString(value=b'key'), assertionValue=BEROctetString(value=b'value')), "
                "attributes=[], tag=42)"
            ),
        )
        self.assertEqual(
            repr(
                pureldap.LDAPSearchRequest(
                    baseObject="ou=users,dc=example,dc=org",
                    filter=pureldap.LDAPFilter_equalityMatch(
                        attributeDesc=pureber.BEROctetString("key"),
                        assertionValue=pureber.BEROctetString("value"),
                    ),
                    tag=42,
                )
            ),
            (
                "LDAPSearchRequest(baseObject='ou=users,dc=example,dc=org', scope=2, derefAliases=0, "
                "sizeLimit=0, timeLimit=0, typesOnly=0, filter=LDAPFilter_equalityMatch("
                "attributeDesc=BEROctetString(value='key'), assertionValue=BEROctetString(value='value')), "
                "attributes=[], tag=42)"
            ),
        )

    def test_search_result_entry_repr(self):
        """LDAPSearchResultEntry.__repr__"""
        self.assertEqual(
            repr(
                pureldap.LDAPSearchResultEntry(
                    objectName=b"uid=mohamed,ou=people,dc=example,dc=fr",
                    attributes=[(b"uid", [b"mohamed"])],
                )
            ),
            (
                "LDAPSearchResultEntry(objectName=b'uid=mohamed,ou=people,dc=example,dc=fr', "
                "attributes=[(b'uid', [b'mohamed'])])"
            ),
        )
        self.assertEqual(
            repr(
                pureldap.LDAPSearchResultEntry(
                    objectName="uid=mohamed,ou=people,dc=example,dc=fr",
                    attributes=[("uid", ["mohamed"])],
                )
            ),
            (
                "LDAPSearchResultEntry(objectName='uid=mohamed,ou=people,dc=example,dc=fr', "
                "attributes=[('uid', ['mohamed'])])"
            ),
        )

    def test_search_result_entry_with_tag_repr(self):
        """LDAPSearchResultEntry.__repr__ with custom tag attribute"""
        self.assertEqual(
            repr(
                pureldap.LDAPSearchResultEntry(
                    objectName=b"uid=mohamed,ou=people,dc=example,dc=fr",
                    attributes=[(b"uid", [b"mohamed"])],
                    tag=42,
                )
            ),
            (
                "LDAPSearchResultEntry(objectName=b'uid=mohamed,ou=people,dc=example,dc=fr', "
                "attributes=[(b'uid', [b'mohamed'])], tag=42)"
            ),
        )
        self.assertEqual(
            repr(
                pureldap.LDAPSearchResultEntry(
                    objectName="uid=mohamed,ou=people,dc=example,dc=fr",
                    attributes=[("uid", ["mohamed"])],
                    tag=42,
                )
            ),
            (
                "LDAPSearchResultEntry(objectName='uid=mohamed,ou=people,dc=example,dc=fr', "
                "attributes=[('uid', ['mohamed'])], tag=42)"
            ),
        )

    def test_search_result_reference_repr(self):
        """LDAPSearchResultReference.__repr__"""
        self.assertEqual(
            repr(
                pureldap.LDAPSearchResultReference(
                    uris=[
                        b"ldap://example.com/dc=foo,dc=example,dc=com",
                        b"ldap://example.com/dc=foo,dc=example,dc=com",
                    ]
                )
            ),
            "LDAPSearchResultReference(uris=[b'ldap://example.com/dc=foo,dc=example,dc=com', "
            "b'ldap://example.com/dc=foo,dc=example,dc=com'])",
        )
        self.assertEqual(
            repr(
                pureldap.LDAPSearchResultReference(
                    uris=[
                        "ldap://example.com/dc=foo,dc=example,dc=com",
                        "ldap://example.com/dc=foo,dc=example,dc=com",
                    ]
                )
            ),
            "LDAPSearchResultReference(uris=['ldap://example.com/dc=foo,dc=example,dc=com', "
            "'ldap://example.com/dc=foo,dc=example,dc=com'])",
        )

    def test_search_result_reference_with_tag_repr(self):
        """LDAPSearchResultReference.__repr__ with custom tag attribute"""
        self.assertEqual(
            repr(
                pureldap.LDAPSearchResultReference(
                    uris=[
                        b"ldap://example.com/dc=foo,dc=example,dc=com",
                        b"ldap://example.com/dc=foo,dc=example,dc=com",
                    ],
                    tag=42,
                )
            ),
            "LDAPSearchResultReference(uris=[b'ldap://example.com/dc=foo,dc=example,dc=com', "
            "b'ldap://example.com/dc=foo,dc=example,dc=com'], tag=42)",
        )
        self.assertEqual(
            repr(
                pureldap.LDAPSearchResultReference(
                    uris=[
                        "ldap://example.com/dc=foo,dc=example,dc=com",
                        "ldap://example.com/dc=foo,dc=example,dc=com",
                    ],
                    tag=42,
                )
            ),
            "LDAPSearchResultReference(uris=['ldap://example.com/dc=foo,dc=example,dc=com', "
            "'ldap://example.com/dc=foo,dc=example,dc=com'], tag=42)",
        )

    def test_modify_request_repr(self):
        """LDAPModifyRequest.__repr__"""
        self.assertEqual(
            repr(
                pureldap.LDAPModifyRequest(
                    object=b"uid=user,ou=users,dc=example,dc=org",
                    modification=pureber.BERSequence(
                        [
                            pureber.BEREnumerated(0),
                            pureber.BERSequence(
                                [
                                    pureldap.LDAPAttributeDescription(b"key"),
                                    pureber.BERSet([pureldap.LDAPString(b"value")]),
                                ]
                            ),
                        ]
                    ),
                )
            ),
            (
                "LDAPModifyRequest(object=b'uid=user,ou=users,dc=example,dc=org', "
                "modification=BERSequence(value=[BEREnumerated(value=0), "
                "BERSequence(value=[LDAPAttributeDescription(value=b'key'), "
                "BERSet(value=[LDAPString(value=b'value')])])]))"
            ),
        )
        self.assertEqual(
            repr(
                pureldap.LDAPModifyRequest(
                    object="uid=user,ou=users,dc=example,dc=org",
                    modification=pureber.BERSequence(
                        [
                            pureber.BEREnumerated(0),
                            pureber.BERSequence(
                                [
                                    pureldap.LDAPAttributeDescription("key"),
                                    pureber.BERSet([pureldap.LDAPString("value")]),
                                ]
                            ),
                        ]
                    ),
                )
            ),
            (
                "LDAPModifyRequest(object='uid=user,ou=users,dc=example,dc=org', "
                "modification=BERSequence(value=[BEREnumerated(value=0), "
                "BERSequence(value=[LDAPAttributeDescription(value='key'), "
                "BERSet(value=[LDAPString(value='value')])])]))"
            ),
        )

    def test_modify_request_with_tag_repr(self):
        """LDAPModifyRequest.__repr__ with custom tag attribute"""
        self.assertEqual(
            repr(
                pureldap.LDAPModifyRequest(
                    object=b"uid=user,ou=users,dc=example,dc=org",
                    modification=pureber.BERSequence(
                        [
                            pureber.BEREnumerated(0),
                            pureber.BERSequence(
                                [
                                    pureldap.LDAPAttributeDescription(b"key"),
                                    pureber.BERSet([pureldap.LDAPString(b"value")]),
                                ]
                            ),
                        ]
                    ),
                    tag=42,
                )
            ),
            (
                "LDAPModifyRequest(object=b'uid=user,ou=users,dc=example,dc=org', "
                "modification=BERSequence(value=[BEREnumerated(value=0), "
                "BERSequence(value=[LDAPAttributeDescription(value=b'key'), "
                "BERSet(value=[LDAPString(value=b'value')])])]), tag=42)"
            ),
        )
        self.assertEqual(
            repr(
                pureldap.LDAPModifyRequest(
                    object="uid=user,ou=users,dc=example,dc=org",
                    modification=pureber.BERSequence(
                        [
                            pureber.BEREnumerated(0),
                            pureber.BERSequence(
                                [
                                    pureldap.LDAPAttributeDescription("key"),
                                    pureber.BERSet([pureldap.LDAPString("value")]),
                                ]
                            ),
                        ]
                    ),
                    tag=42,
                )
            ),
            (
                "LDAPModifyRequest(object='uid=user,ou=users,dc=example,dc=org', "
                "modification=BERSequence(value=[BEREnumerated(value=0), "
                "BERSequence(value=[LDAPAttributeDescription(value='key'), "
                "BERSet(value=[LDAPString(value='value')])])]), tag=42)"
            ),
        )

    def test_add_request_repr(self):
        """LDAPAddRequest.__repr__"""
        self.assertEqual(
            repr(
                pureldap.LDAPAddRequest(
                    entry=b"uid=user,ou=users,dc=example,dc=org",
                    attributes=[
                        (
                            pureldap.LDAPAttributeDescription(b"key"),
                            pureber.BERSet([pureldap.LDAPAttributeValue(b"value")]),
                        ),
                    ],
                )
            ),
            (
                "LDAPAddRequest(entry=b'uid=user,ou=users,dc=example,dc=org', "
                "attributes=[(LDAPAttributeDescription(value=b'key'), "
                "BERSet(value=[LDAPAttributeValue(value=b'value')]))])"
            ),
        )
        self.assertEqual(
            repr(
                pureldap.LDAPAddRequest(
                    entry="uid=user,ou=users,dc=example,dc=org",
                    attributes=[
                        (
                            pureldap.LDAPAttributeDescription("key"),
                            pureber.BERSet([pureldap.LDAPAttributeValue("value")]),
                        ),
                    ],
                )
            ),
            (
                "LDAPAddRequest(entry='uid=user,ou=users,dc=example,dc=org', "
                "attributes=[(LDAPAttributeDescription(value='key'), "
                "BERSet(value=[LDAPAttributeValue(value='value')]))])"
            ),
        )

    def test_add_request_with_tag_repr(self):
        """LDAPAddRequest.__repr__ with custom tag attribute"""
        self.assertEqual(
            repr(
                pureldap.LDAPAddRequest(
                    entry=b"uid=user,ou=users,dc=example,dc=org",
                    attributes=[
                        (
                            pureldap.LDAPAttributeDescription(b"key"),
                            pureber.BERSet([pureldap.LDAPAttributeValue(b"value")]),
                        ),
                    ],
                    tag=42,
                )
            ),
            (
                "LDAPAddRequest(entry=b'uid=user,ou=users,dc=example,dc=org', "
                "attributes=[(LDAPAttributeDescription(value=b'key'), "
                "BERSet(value=[LDAPAttributeValue(value=b'value')]))], tag=42)"
            ),
        )
        self.assertEqual(
            repr(
                pureldap.LDAPAddRequest(
                    entry="uid=user,ou=users,dc=example,dc=org",
                    attributes=[
                        (
                            pureldap.LDAPAttributeDescription("key"),
                            pureber.BERSet([pureldap.LDAPAttributeValue("value")]),
                        ),
                    ],
                    tag=42,
                )
            ),
            (
                "LDAPAddRequest(entry='uid=user,ou=users,dc=example,dc=org', "
                "attributes=[(LDAPAttributeDescription(value='key'), "
                "BERSet(value=[LDAPAttributeValue(value='value')]))], tag=42)"
            ),
        )

    def test_del_request_repr(self):
        """LDAPDelRequest.__repr__"""
        self.assertEqual(
            repr(pureldap.LDAPDelRequest(entry=b"uid=user,ou=users,dc=example,dc=org")),
            "LDAPDelRequest(entry=b'uid=user,ou=users,dc=example,dc=org')",
        )
        self.assertEqual(
            repr(pureldap.LDAPDelRequest(entry="uid=user,ou=users,dc=example,dc=org")),
            "LDAPDelRequest(entry='uid=user,ou=users,dc=example,dc=org')",
        )

    def test_del_request_with_tag_repr(self):
        """LDAPDelRequest.__repr__ with custom tag attribute"""
        self.assertEqual(
            repr(
                pureldap.LDAPDelRequest(
                    entry=b"uid=user,ou=users,dc=example,dc=org", tag=42
                )
            ),
            "LDAPDelRequest(entry=b'uid=user,ou=users,dc=example,dc=org', tag=42)",
        )
        self.assertEqual(
            repr(
                pureldap.LDAPDelRequest(
                    entry="uid=user,ou=users,dc=example,dc=org", tag=42
                )
            ),
            "LDAPDelRequest(entry='uid=user,ou=users,dc=example,dc=org', tag=42)",
        )

    def test_modify_dn_request_repr(self):
        """LDAPModifyDNRequest.__repr__"""
        self.assertEqual(
            repr(
                pureldap.LDAPModifyDNRequest(
                    entry=b"uid=user,ou=users,dc=example,dc=org",
                    newrdn=b"uid=newuser",
                    deleteoldrdn=True,
                )
            ),
            (
                "LDAPModifyDNRequest(entry=b'uid=user,ou=users,dc=example,dc=org', "
                "newrdn=b'uid=newuser', deleteoldrdn=True)"
            ),
        )
        self.assertEqual(
            repr(
                pureldap.LDAPModifyDNRequest(
                    entry="uid=user,ou=users,dc=example,dc=org",
                    newrdn="uid=newuser",
                    deleteoldrdn=True,
                )
            ),
            (
                "LDAPModifyDNRequest(entry='uid=user,ou=users,dc=example,dc=org', "
                "newrdn='uid=newuser', deleteoldrdn=True)"
            ),
        )

    def test_modify_dn_request_with_new_superior_repr(self):
        """LDAPModifyDNRequest.__repr__ with newSuperior attribute"""
        self.assertEqual(
            repr(
                pureldap.LDAPModifyDNRequest(
                    entry=b"uid=user,ou=users,dc=example,dc=org",
                    newrdn=b"uid=newuser",
                    deleteoldrdn=False,
                    newSuperior=b"ou=newusers,dc=example,dc=org",
                )
            ),
            (
                "LDAPModifyDNRequest(entry=b'uid=user,ou=users,dc=example,dc=org', "
                "newrdn=b'uid=newuser', deleteoldrdn=False, "
                "newSuperior=b'ou=newusers,dc=example,dc=org')"
            ),
        )
        self.assertEqual(
            repr(
                pureldap.LDAPModifyDNRequest(
                    entry="uid=user,ou=users,dc=example,dc=org",
                    newrdn="uid=newuser",
                    deleteoldrdn=False,
                    newSuperior="ou=newusers,dc=example,dc=org",
                )
            ),
            (
                "LDAPModifyDNRequest(entry='uid=user,ou=users,dc=example,dc=org', "
                "newrdn='uid=newuser', deleteoldrdn=False, "
                "newSuperior='ou=newusers,dc=example,dc=org')"
            ),
        )

    def test_modify_dn_request_with_tag_repr(self):
        """LDAPModifyDNRequest.__repr__ with custom tag attribute"""
        self.assertEqual(
            repr(
                pureldap.LDAPModifyDNRequest(
                    entry=b"uid=user,ou=users,dc=example,dc=org",
                    newrdn=b"uid=newuser",
                    deleteoldrdn=True,
                    tag=42,
                )
            ),
            (
                "LDAPModifyDNRequest(entry=b'uid=user,ou=users,dc=example,dc=org', "
                "newrdn=b'uid=newuser', deleteoldrdn=True, tag=42)"
            ),
        )
        self.assertEqual(
            repr(
                pureldap.LDAPModifyDNRequest(
                    entry="uid=user,ou=users,dc=example,dc=org",
                    newrdn="uid=newuser",
                    deleteoldrdn=True,
                    tag=42,
                )
            ),
            (
                "LDAPModifyDNRequest(entry='uid=user,ou=users,dc=example,dc=org', "
                "newrdn='uid=newuser', deleteoldrdn=True, tag=42)"
            ),
        )

    def test_compare_request_repr(self):
        """LDAPCompareRequest.__repr__"""
        self.assertEqual(
            repr(
                pureldap.LDAPCompareRequest(
                    entry=b"uid=user,ou=users,dc=example,dc=org",
                    ava=pureldap.LDAPAttributeValueAssertion(
                        pureber.BEROctetString(b"key"),
                        pureber.BEROctetString(b"value"),
                    ),
                )
            ),
            (
                "LDAPCompareRequest(entry=b'uid=user,ou=users,dc=example,dc=org', "
                "ava=LDAPAttributeValueAssertion(attributeDesc=BEROctetString(value=b'key'), "
                "assertionValue=BEROctetString(value=b'value')))"
            ),
        )
        self.assertEqual(
            repr(
                pureldap.LDAPCompareRequest(
                    entry="uid=user,ou=users,dc=example,dc=org",
                    ava=pureldap.LDAPAttributeValueAssertion(
                        pureber.BEROctetString("key"),
                        pureber.BEROctetString("value"),
                    ),
                )
            ),
            (
                "LDAPCompareRequest(entry='uid=user,ou=users,dc=example,dc=org', "
                "ava=LDAPAttributeValueAssertion(attributeDesc=BEROctetString(value='key'), "
                "assertionValue=BEROctetString(value='value')))"
            ),
        )

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
        self.assertEqual(
            repr(
                pureldap.LDAPPasswordModifyRequest(
                    userIdentity=b"uid=user,ou=users,dc=example,dc=org",
                    oldPasswd=b"qwerty",
                    newPasswd=b"asdfgh",
                )
            ),
            (
                "LDAPPasswordModifyRequest(userIdentity=LDAPPasswordModifyRequest_userIdentity("
                "value=b'uid=user,ou=users,dc=example,dc=org'), "
                "oldPasswd=LDAPPasswordModifyRequest_oldPasswd(value='******'), "
                "newPasswd=LDAPPasswordModifyRequest_newPasswd(value='******'))"
            ),
        )
        self.assertEqual(
            repr(
                pureldap.LDAPPasswordModifyRequest(
                    userIdentity="uid=user,ou=users,dc=example,dc=org",
                    oldPasswd="qwerty",
                    newPasswd="asdfgh",
                )
            ),
            (
                "LDAPPasswordModifyRequest(userIdentity=LDAPPasswordModifyRequest_userIdentity("
                "value='uid=user,ou=users,dc=example,dc=org'), "
                "oldPasswd=LDAPPasswordModifyRequest_oldPasswd(value='******'), "
                "newPasswd=LDAPPasswordModifyRequest_newPasswd(value='******'))"
            ),
        )

    def test_password_modify_request_with_tag_repr(self):
        """LDAPPasswordModifyRequest.__repr__ with custom tag attribute"""
        self.assertEqual(
            repr(
                pureldap.LDAPPasswordModifyRequest(
                    userIdentity=b"uid=user,ou=users,dc=example,dc=org",
                    oldPasswd=b"qwerty",
                    newPasswd=b"asdfgh",
                    tag=42,
                )
            ),
            (
                "LDAPPasswordModifyRequest(userIdentity=LDAPPasswordModifyRequest_userIdentity("
                "value=b'uid=user,ou=users,dc=example,dc=org'), "
                "oldPasswd=LDAPPasswordModifyRequest_oldPasswd(value='******'), "
                "newPasswd=LDAPPasswordModifyRequest_newPasswd(value='******'), tag=42)"
            ),
        )
        self.assertEqual(
            repr(
                pureldap.LDAPPasswordModifyRequest(
                    userIdentity="uid=user,ou=users,dc=example,dc=org",
                    oldPasswd="qwerty",
                    newPasswd="asdfgh",
                    tag=42,
                )
            ),
            (
                "LDAPPasswordModifyRequest(userIdentity=LDAPPasswordModifyRequest_userIdentity("
                "value='uid=user,ou=users,dc=example,dc=org'), "
                "oldPasswd=LDAPPasswordModifyRequest_oldPasswd(value='******'), "
                "newPasswd=LDAPPasswordModifyRequest_newPasswd(value='******'), tag=42)"
            ),
        )

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
        self.assertEqual(
            repr(
                pureldap.LDAPAttributeValueAssertion(
                    pureber.BEROctetString(b"key"),
                    pureber.BEROctetString(b"value"),
                )
            ),
            (
                "LDAPAttributeValueAssertion(attributeDesc=BEROctetString(value=b'key'), "
                "assertionValue=BEROctetString(value=b'value'))"
            ),
        )
        self.assertEqual(
            repr(
                pureldap.LDAPAttributeValueAssertion(
                    pureber.BEROctetString("key"),
                    pureber.BEROctetString("value"),
                )
            ),
            (
                "LDAPAttributeValueAssertion(attributeDesc=BEROctetString(value='key'), "
                "assertionValue=BEROctetString(value='value'))"
            ),
        )

    def test_attribute_value_assertion_with_tag_repr(self):
        """LDAPAttributeValueAssertion.__repr__ with custom tag attribute"""
        self.assertEqual(
            repr(
                pureldap.LDAPAttributeValueAssertion(
                    pureber.BEROctetString(b"key"),
                    pureber.BEROctetString(b"value"),
                    tag=42,
                )
            ),
            (
                "LDAPAttributeValueAssertion(attributeDesc=BEROctetString(value=b'key'), "
                "assertionValue=BEROctetString(value=b'value'), tag=42)"
            ),
        )
        self.assertEqual(
            repr(
                pureldap.LDAPAttributeValueAssertion(
                    pureber.BEROctetString("key"),
                    pureber.BEROctetString("value"),
                    tag=42,
                )
            ),
            (
                "LDAPAttributeValueAssertion(attributeDesc=BEROctetString(value='key'), "
                "assertionValue=BEROctetString(value='value'), tag=42)"
            ),
        )

    def test_ldapfilter_not_repr(self):
        """LDAPFilter_not.__repr__"""
        self.assertEqual(
            repr(pureldap.LDAPFilter_not(pureber.BEROctetString(b"value"))),
            "LDAPFilter_not(value=BEROctetString(value=b'value'))",
        )
        self.assertEqual(
            repr(pureldap.LDAPFilter_not(pureber.BEROctetString("value"))),
            "LDAPFilter_not(value=BEROctetString(value='value'))",
        )

    def test_ldapfilter_not_with_tag_repr(self):
        """LDAPFilter_not.__repr__ with custom tag attribute"""
        self.assertEqual(
            repr(pureldap.LDAPFilter_not(pureber.BEROctetString(b"value"), tag=42)),
            "LDAPFilter_not(value=BEROctetString(value=b'value'), tag=42)",
        )
        self.assertEqual(
            repr(pureldap.LDAPFilter_not(pureber.BEROctetString("value"), tag=42)),
            "LDAPFilter_not(value=BEROctetString(value='value'), tag=42)",
        )

    def test_ldapfilter_substrings_repr(self):
        """LDAPFilter_substrings.__repr__"""
        self.assertEqual(
            repr(
                pureldap.LDAPFilter_substrings(
                    type=b"cn",
                    substrings=[pureldap.LDAPFilter_substrings_initial(value=b"value")],
                )
            ),
            (
                "LDAPFilter_substrings(type=b'cn', "
                "substrings=[LDAPFilter_substrings_initial(value=b'value')])"
            ),
        )
        self.assertEqual(
            repr(
                pureldap.LDAPFilter_substrings(
                    type="cn",
                    substrings=[pureldap.LDAPFilter_substrings_initial(value="value")],
                )
            ),
            (
                "LDAPFilter_substrings(type='cn', "
                "substrings=[LDAPFilter_substrings_initial(value='value')])"
            ),
        )

    def test_ldapfilter_substrings_with_tag_repr(self):
        """LDAPFilter_substrings.__repr__ with custom tag attribute"""
        self.assertEqual(
            repr(
                pureldap.LDAPFilter_substrings(
                    type=b"cn",
                    substrings=[pureldap.LDAPFilter_substrings_initial(value=b"value")],
                    tag=42,
                )
            ),
            (
                "LDAPFilter_substrings(type=b'cn', "
                "substrings=[LDAPFilter_substrings_initial(value=b'value')], tag=42)"
            ),
        )
        self.assertEqual(
            repr(
                pureldap.LDAPFilter_substrings(
                    type="cn",
                    substrings=[pureldap.LDAPFilter_substrings_initial(value="value")],
                    tag=42,
                )
            ),
            (
                "LDAPFilter_substrings(type='cn', "
                "substrings=[LDAPFilter_substrings_initial(value='value')], tag=42)"
            ),
        )

    def test_matching_rule_assertion_repr(self):
        """LDAPMatchingRuleAssertion.__repr__"""
        self.assertEqual(
            repr(pureldap.LDAPMatchingRuleAssertion(b"rule", b"type", b"value")),
            (
                "LDAPMatchingRuleAssertion(matchingRule=LDAPMatchingRuleAssertion_matchingRule("
                "value=b'rule'), type=LDAPMatchingRuleAssertion_type(value=b'type'), matchValue="
                "LDAPMatchingRuleAssertion_matchValue(value=b'value'), dnAttributes=None)"
            ),
        )
        self.assertEqual(
            repr(pureldap.LDAPMatchingRuleAssertion("rule", "type", "value")),
            (
                "LDAPMatchingRuleAssertion(matchingRule=LDAPMatchingRuleAssertion_matchingRule("
                "value='rule'), type=LDAPMatchingRuleAssertion_type(value='type'), matchValue="
                "LDAPMatchingRuleAssertion_matchValue(value='value'), dnAttributes=None)"
            ),
        )

    def test_matching_rule_assertion_with_tag_repr(self):
        """LDAPMatchingRuleAssertion.__repr__ with custom tag attribute"""
        self.assertEqual(
            repr(
                pureldap.LDAPMatchingRuleAssertion(b"rule", b"type", b"value", tag=42)
            ),
            (
                "LDAPMatchingRuleAssertion(matchingRule=LDAPMatchingRuleAssertion_matchingRule("
                "value=b'rule'), type=LDAPMatchingRuleAssertion_type(value=b'type'), matchValue="
                "LDAPMatchingRuleAssertion_matchValue(value=b'value'), dnAttributes=None, tag=42)"
            ),
        )
        self.assertEqual(
            repr(pureldap.LDAPMatchingRuleAssertion("rule", "type", "value", tag=42)),
            (
                "LDAPMatchingRuleAssertion(matchingRule=LDAPMatchingRuleAssertion_matchingRule("
                "value='rule'), type=LDAPMatchingRuleAssertion_type(value='type'), matchValue="
                "LDAPMatchingRuleAssertion_matchValue(value='value'), dnAttributes=None, tag=42)"
            ),
        )

    def test_ldap_bind_response_server_sasl_creds_repr(self):
        """ServerSaslCreds will often have binary data. A custom repr is needed because
        it cannot be turned into a unicode string like most BEROctetString objects.
        """
        sasl_creds = pureldap.LDAPBindResponse_serverSaslCreds(value=b"NTLMSSP\xbe")
        expected_repr = r"LDAPBindResponse_serverSaslCreds(value=b'NTLMSSP\xbe')"

        actual_repr = repr(sasl_creds)
        self.assertEqual(actual_repr, expected_repr)

    def test_ldap_bind_response_server_sasl_creds_with_tag_repr(self):
        """An LDAPBindResponse_serverSaslCreds with a non-standard tag will have that
        tag show up in the text representation.
        """
        sasl_creds = pureldap.LDAPBindResponse_serverSaslCreds(
            value=b"NTLMSSP\xbe", tag=12
        )
        expected_repr = (
            r"LDAPBindResponse_serverSaslCreds(value=b'NTLMSSP\xbe', tag=12)"
        )

        actual_repr = repr(sasl_creds)
        self.assertEqual(actual_repr, expected_repr)
