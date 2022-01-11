"""
Test cases for ldaptor.protocols.ldap.ldapserver module.
"""
import re

import attr
from twisted.trial import unittest
from ldaptor import inmemory
from ldaptor.protocols import pureldap, pureber
from ldaptor.protocols.ldap import ldapsyntax


class TestEntryMatch(unittest.TestCase):
    def test_matchAll(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(pureldap.LDAPFilterMatchAll)
        self.assertEqual(result, True)

    def test_present_match(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(pureldap.LDAPFilter_present("aValue"))
        self.assertEqual(result, True)

    def test_present_noMatch(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(pureldap.LDAPFilter_present("noSuchValue"))
        self.assertEqual(result, False)

    def test_and_match(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_and(
                [
                    pureldap.LDAPFilter_present("aValue"),
                    pureldap.LDAPFilter_present("bValue"),
                ]
            )
        )
        self.assertEqual(result, True)

    def test_and_noMatch(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_and(
                [
                    pureldap.LDAPFilter_present("cValue"),
                    pureldap.LDAPFilter_present("dValue"),
                ]
            )
        )
        self.assertEqual(result, False)

    def test_or_match(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_or(
                [
                    pureldap.LDAPFilter_present("cValue"),
                    pureldap.LDAPFilter_present("bValue"),
                ]
            )
        )
        self.assertEqual(result, True)

    def test_or_noMatch(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_or(
                [
                    pureldap.LDAPFilter_present("cValue"),
                    pureldap.LDAPFilter_present("dValue"),
                ]
            )
        )
        self.assertEqual(result, False)

    def test_not(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_not(
                pureldap.LDAPFilter_or(
                    [
                        pureldap.LDAPFilter_present("cValue"),
                        pureldap.LDAPFilter_present("dValue"),
                    ]
                )
            )
        )
        self.assertEqual(result, True)

    def test_equality_match(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureber.BEROctetString("aValue"),
                assertionValue=pureber.BEROctetString("a"),
            )
        )
        self.assertEqual(result, True)

    def test_equality_match_caseInsensitive(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureber.BEROctetString("avaLUe"),
                assertionValue=pureber.BEROctetString("A"),
            )
        )
        self.assertEqual(result, True)

    def test_equality_noMatch(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureber.BEROctetString("aValue"),
                assertionValue=pureber.BEROctetString("b"),
            )
        )
        self.assertEqual(result, False)

    def test_substrings_match(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_substrings(
                type="aValue",
                substrings=[
                    pureldap.LDAPFilter_substrings_initial("a"),
                ],
            )
        )
        self.assertEqual(result, True)

    def test_substrings_match2(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["abcde"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_substrings(
                type="aValue",
                substrings=[
                    pureldap.LDAPFilter_substrings_initial("a"),
                    pureldap.LDAPFilter_substrings_final("e"),
                ],
            )
        )
        self.assertEqual(result, True)

    def test_substrings_match3(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["abcde"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_substrings(
                type="aValue",
                substrings=[
                    pureldap.LDAPFilter_substrings_initial("a"),
                    pureldap.LDAPFilter_substrings_any("c"),
                    pureldap.LDAPFilter_substrings_final("e"),
                ],
            )
        )
        self.assertEqual(result, True)

    def test_substrings_match4(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["abcde"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_substrings(
                type="aValue",
                substrings=[
                    pureldap.LDAPFilter_substrings_initial("a"),
                    pureldap.LDAPFilter_substrings_any("b"),
                    pureldap.LDAPFilter_substrings_any("c"),
                    pureldap.LDAPFilter_substrings_any("d"),
                    pureldap.LDAPFilter_substrings_final("e"),
                ],
            )
        )
        self.assertEqual(result, True)

    def test_substrings_match5(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["aoeuboeucoeudoeue"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_substrings(
                type="aValue",
                substrings=[
                    pureldap.LDAPFilter_substrings_initial("a"),
                    pureldap.LDAPFilter_substrings_any("b"),
                    pureldap.LDAPFilter_substrings_any("c"),
                    pureldap.LDAPFilter_substrings_any("d"),
                    pureldap.LDAPFilter_substrings_final("e"),
                ],
            )
        )
        self.assertEqual(result, True)

    def test_substrings_match6(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["aBCdE"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_substrings(
                type="aValue",
                substrings=[
                    pureldap.LDAPFilter_substrings_initial("A"),
                    pureldap.LDAPFilter_substrings_any("b"),
                    pureldap.LDAPFilter_substrings_any("C"),
                    pureldap.LDAPFilter_substrings_any("D"),
                    pureldap.LDAPFilter_substrings_final("e"),
                ],
            )
        )
        self.assertEqual(result, True)

    def test_substrings_match7(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["Foo"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_substrings(
                type="aValue",
                substrings=[
                    pureldap.LDAPFilter_substrings_initial("f"),
                ],
            )
        )
        self.assertEqual(result, True)

    def test_substrings_noMatch(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_substrings(
                type="aValue",
                substrings=[
                    pureldap.LDAPFilter_substrings_initial("bad"),
                    pureldap.LDAPFilter_substrings_any("dog"),
                    pureldap.LDAPFilter_substrings_any("no"),
                    pureldap.LDAPFilter_substrings_final("bone"),
                ],
            )
        )
        self.assertEqual(result, False)

    def test_substrings_noMatch2(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["aoeuboeucoeudoeue"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_substrings(
                type="aValue",
                substrings=[
                    pureldap.LDAPFilter_substrings_initial("a"),
                    pureldap.LDAPFilter_substrings_any("b"),
                    pureldap.LDAPFilter_substrings_any("Z"),
                    pureldap.LDAPFilter_substrings_any("d"),
                    pureldap.LDAPFilter_substrings_final("e"),
                ],
            )
        )
        self.assertEqual(result, False)

    def test_greaterOrEqual_noMatch_nosuchattr(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "num": [4],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_greaterOrEqual(
                pureber.BEROctetString("foo"), pureber.BERInteger(42)
            )
        )
        self.assertEqual(result, False)

    def test_greaterOrEqual_match_greater(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "num": [4],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_greaterOrEqual(
                pureber.BEROctetString("num"), pureber.BERInteger(3)
            )
        )
        self.assertEqual(result, True)

    def test_greaterOrEqual_match_equal(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "num": [4],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_greaterOrEqual(
                pureber.BEROctetString("num"), pureber.BERInteger(4)
            )
        )
        self.assertEqual(result, True)

    def test_greaterOrEqual_noMatch(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "bValue": [4],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_greaterOrEqual(
                pureber.BEROctetString("num"), pureber.BERInteger(5)
            )
        )
        self.assertEqual(result, False)

    def test_lessOrEqual_noMatch_nosuchattr(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "num": [4],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_lessOrEqual(
                pureber.BEROctetString("foo"), pureber.BERInteger(42)
            )
        )
        self.assertEqual(result, False)

    def test_lessOrEqual_match_less(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "num": [4],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_lessOrEqual(
                pureber.BEROctetString("num"), pureber.BERInteger(5)
            )
        )
        self.assertEqual(result, True)

    def test_lessOrEqual_match_equal(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "num": [4],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_lessOrEqual(
                pureber.BEROctetString("num"), pureber.BERInteger(4)
            )
        )
        self.assertEqual(result, True)

    def test_lessOrEqual_noMatch(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "num": [4],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_lessOrEqual(
                pureber.BEROctetString("num"), pureber.BERInteger(3)
            )
        )
        self.assertEqual(result, False)

    def test_extensibleMatch4(self):
        """
        An extensibleMatch filter that uses DN attributes matches an entry
        based on its OU.
        See RFC4511 section 4.5.1.
        """
        m = pureldap.LDAPFilter_extensibleMatch(
            matchingRule=None,
            type=pureldap.LDAPMatchingRuleAssertion_type(value="ou"),
            matchValue=pureldap.LDAPMatchingRuleAssertion_matchValue(value="fings"),
            dnAttributes=pureldap.LDAPMatchingRuleAssertion_dnAttributes(value=255),
        )
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,ou=fings,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "num": [4],
            },
        )
        result = o.match(m)
        self.assertEqual(result, True)

    def test_extensibleMatch4_noMatch(self):
        """
        An extensibleMatch filter that uses DN attributes does not match an entry
        based on its OU.
        See RFC4511 section 4.5.1.
        """
        m = pureldap.LDAPFilter_extensibleMatch(
            matchingRule=None,
            type=pureldap.LDAPMatchingRuleAssertion_type(value="ou"),
            matchValue=pureldap.LDAPMatchingRuleAssertion_matchValue(value="fings"),
            dnAttributes=pureldap.LDAPMatchingRuleAssertion_dnAttributes(value=255),
        )
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,ou=uvvers,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "num": [4],
            },
        )
        result = o.match(m)
        self.assertEqual(result, False)

    def test_notImplemented(self):
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "num": [4],
            },
        )

        @attr.s
        class UnknownMatch:
            pass

        unknownMatch = UnknownMatch()
        self.assertRaisesRegex(
            ldapsyntax.MatchNotImplemented,
            re.escape("Match type not implemented: UnknownMatch()"),
            o.match,
            unknownMatch,
        )


# TODO LDAPFilter_approxMatch
# TODO LDAPFilter_extensibleMatch
