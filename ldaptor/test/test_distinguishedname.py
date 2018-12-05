"""
Test cases for ldaptor.protocols.ldap.distinguishedname module.
"""

from twisted.trial import unittest
from ldaptor.protocols.ldap import distinguishedname as dn


class TestCaseWithKnownValues(unittest.TestCase):
    knownValues = ()

    def testKnownValues(self):
        for s, l in self.knownValues:
            fromString = dn.DistinguishedName(s)
            listOfRDNs = []
            for av in l:
                listOfAttributeTypesAndValues = []
                for a,v in av:
                    listOfAttributeTypesAndValues.append(dn.LDAPAttributeTypeAndValue(attributeType=a, value=v))
                r=dn.RelativeDistinguishedName(listOfAttributeTypesAndValues)
                listOfRDNs.append(r)
            fromList = dn.DistinguishedName(listOfRDNs)

            self.assertEqual(fromString, fromList)

            fromStringToText = fromString.getText()
            fromListToText = fromList.getText()

            assert fromStringToText == fromListToText

            canon = fromStringToText
            # DNs equal their byte string representation. Note this does
            # not mean they equal all the possible string
            # representations -- just the canonical one.
            self.assertEqual(fromString, canon)
            self.assertEqual(fromList, canon)
            self.assertEqual(canon, fromString)
            self.assertEqual(canon, fromList)

            # DNs can be used interchangeably with their canonical
            # string representation as hash keys.
            self.assertEqual(hash(fromString), hash(canon))
            self.assertEqual(hash(fromList), hash(canon))
            self.assertEqual(hash(canon), hash(fromString))
            self.assertEqual(hash(canon), hash(fromList))


class LDAPDistinguishedName_Escaping(TestCaseWithKnownValues):
    knownValues = (

        ('', []),

        ('cn=foo', [[('cn', 'foo')]]),

        (r'cn=\,bar', [[('cn', r',bar')]]),
        (r'cn=foo\,bar', [[('cn', r'foo,bar')]]),
        (r'cn=foo\,', [[('cn', r'foo,')]]),

        (r'cn=\+bar', [[('cn', r'+bar')]]),
        (r'cn=foo\+bar', [[('cn', r'foo+bar')]]),
        (r'cn=foo\+', [[('cn', r'foo+')]]),

        (r'cn=\"bar', [[('cn', r'"bar')]]),
        (r'cn=foo\"bar', [[('cn', r'foo"bar')]]),
        (r'cn=foo\"', [[('cn', r'foo"')]]),

        (r'cn=\\bar', [[('cn', r'\bar')]]),
        (r'cn=foo\\bar', [[('cn', r'foo\bar')]]),
        (r'cn=foo\\', [[('cn', 'foo\\')]]),

        (r'cn=\<bar', [[('cn', r'<bar')]]),
        (r'cn=foo\<bar', [[('cn', r'foo<bar')]]),
        (r'cn=foo\<', [[('cn', r'foo<')]]),

        (r'cn=\>bar', [[('cn', r'>bar')]]),
        (r'cn=foo\>bar', [[('cn', r'foo>bar')]]),
        (r'cn=foo\>', [[('cn', r'foo>')]]),

        (r'cn=\;bar', [[('cn', r';bar')]]),
        (r'cn=foo\;bar', [[('cn', r'foo;bar')]]),
        (r'cn=foo\;', [[('cn', r'foo;')]]),

        (r'cn=\#bar', [[('cn', r'#bar')]]),

        (r'cn=\ bar', [[('cn', r' bar')]]),

        (r'cn=bar\ ', [[('cn', r'bar ')]]),

        (r'cn=test+owner=uid\=foo\,ou\=depar'
         +r'tment\,dc\=example\,dc\=com,dc=ex'
         +r'ample,dc=com', [[('cn', r'test'),
                             ('owner', r'uid=foo,ou=depart'
                              +r'ment,dc=example,dc=com'),
                             ],
                            [('dc', r'example')],
                            [('dc', r'com')]]),

        (r'cn=bar,dc=example,dc=com', [[('cn', 'bar')],
                                       [('dc', 'example')],
                                       [('dc', 'com')]]),
        (r'cn=bar, dc=example, dc=com', [[('cn', 'bar')],
                                         [('dc', 'example')],
                                         [('dc', 'com')]]),
        (r'cn=bar,  dc=example,dc=com', [[('cn', 'bar')],
                                         [('dc', 'example')],
                                         [('dc', 'com')]]),

        )

    def testOpenLDAPEqualsEscape(self):
        """Slapd wants = to be escaped in RDN attributeValues."""
        got = dn.DistinguishedName(listOfRDNs=[
            dn.RelativeDistinguishedName(
            attributeTypesAndValues=[
            dn.LDAPAttributeTypeAndValue(attributeType='cn', value=r'test'),
            dn.LDAPAttributeTypeAndValue(attributeType='owner', value=r'uid=foo,ou=depart'
                                         +r'ment,dc=example,dc=com'),
                                     ]),

            dn.RelativeDistinguishedName('dc=example'),
            dn.RelativeDistinguishedName('dc=com'),
            ])
        got = got.getText()
        self.assertEqual(got,
                          'cn=test+owner=uid\=foo\,ou\=depar'
                          +'tment\,dc\=example\,dc\=com,dc=ex'
                          +'ample,dc=com')


class LDAPDistinguishedName_RFC2253_ExamplesBytes(TestCaseWithKnownValues):
    """
    It can be initialized from text/Unicode input as long as they contain
    ASCII only characters.
    """
    knownValues = (

        ('CN=Steve Kille,O=Isode Limited,C=GB',
         [[('CN', 'Steve Kille')],
          [('O', 'Isode Limited')],
          [('C', 'GB')]]),


        ('OU=Sales+CN=J. Smith,O=Widget Inc.,C=US',
         [[('OU', 'Sales'),
           ('CN', 'J. Smith')],
          [('O', 'Widget Inc.')],
          [('C', 'US')]]),

        (r'CN=L. Eagle,O=Sue\, Grabbit and Runn,C=GB',
         [[('CN', 'L. Eagle')],
          [('O', 'Sue, Grabbit and Runn')],
          [('C', 'GB')]]),

        (r'CN=Before\0DAfter,O=Test,C=GB',
         [[('CN', 'Before\x0dAfter')],
          [('O', 'Test')],
          [('C', 'GB')]]),

        (r'1.3.6.1.4.1.1466.0=#04024869,O=Test,C=GB',
         [[('1.3.6.1.4.1.1466.0', '#04024869')],
          [('O', 'Test')],
          [('C', 'GB')]]),
        )


class LDAPDistinguishedName_UTF8_Init(TestCaseWithKnownValues):
    """
    It can be initialized from an UTF-8 encoded data and it will
    keep the representation as UTF-8.
    """
    knownValues = (
        (u'SN=Lu\u010di\u0107'.encode('utf-8'),
         [[(b'SN', u'Lu\u010di\u0107'.encode('utf-8'))]]),
        )



class LDAPDistinguishedName_InitialSpaces(TestCaseWithKnownValues):
    """
    The spaces which are not escapes are stripped.
    """
    knownValues = (

        ('cn=foo, ou=bar,  dc=quux, \ attributeThatStartsWithSpace=Value',
         [[('cn', 'foo')],
          [('ou', 'bar')],
          [('dc', 'quux')],
          [(' attributeThatStartsWithSpace', 'Value')]]),

        )

class LDAPDistinguishedName_DomainName(unittest.TestCase):
    def testNonDc(self):
        d=dn.DistinguishedName('cn=foo,o=bar,c=us')
        assert d.getDomainName() is None

    def testNonTrailingDc(self):
        d=dn.DistinguishedName('cn=foo,o=bar,dc=foo,c=us')
        assert d.getDomainName() is None

    def testSimple_ExampleCom(self):
        d=dn.DistinguishedName('dc=example,dc=com')
        assert d.getDomainName() == 'example.com'

    def testSimple_SubExampleCom(self):
        d=dn.DistinguishedName('dc=sub,dc=example,dc=com')
        assert d.getDomainName() == 'sub.example.com'

    def testSimple_HostSubExampleCom(self):
        d=dn.DistinguishedName('cn=host,dc=sub,dc=example,dc=com')
        assert d.getDomainName() == 'sub.example.com'

    def testInterleaved_SubHostSubExampleCom(self):
        d=dn.DistinguishedName('dc=sub2,cn=host,dc=sub,dc=example,dc=com')
        assert d.getDomainName() == 'sub.example.com'

class LDAPDistinguishedName_contains(unittest.TestCase):
    shsec=dn.DistinguishedName('dc=sub2,cn=host,dc=sub,dc=example,dc=com')
    hsec=dn.DistinguishedName('cn=host,dc=sub,dc=example,dc=com')
    sec=dn.DistinguishedName('dc=sub,dc=example,dc=com')
    ec=dn.DistinguishedName('dc=example,dc=com')
    c=dn.DistinguishedName('dc=com')

    soc=dn.DistinguishedName('dc=sub,dc=other,dc=com')
    oc=dn.DistinguishedName('dc=other,dc=com')

    other=dn.DistinguishedName('o=foo,c=US')

    root=dn.DistinguishedName('')

    def test_selfContainment(self):
        assert self.c.contains(self.c)
        assert self.ec.contains(self.ec)
        assert self.sec.contains(self.sec)
        assert self.hsec.contains(self.hsec)
        assert self.shsec.contains(self.shsec)

        assert self.soc.contains(self.soc)
        assert self.oc.contains(self.oc)

        assert self.root.contains(self.root)

        assert self.other.contains(self.other)

    def test_realContainment(self):
        assert self.c.contains(self.ec)
        assert self.c.contains(self.sec)
        assert self.c.contains(self.hsec)
        assert self.c.contains(self.shsec)

        assert self.ec.contains(self.sec)
        assert self.ec.contains(self.hsec)
        assert self.ec.contains(self.shsec)

        assert self.sec.contains(self.hsec)
        assert self.sec.contains(self.shsec)

        assert self.hsec.contains(self.shsec)

        assert self.c.contains(self.oc)
        assert self.c.contains(self.soc)
        assert self.oc.contains(self.soc)

        for x in (self.shsec, self.hsec, self.sec, self.ec, self.c,
                  self.soc, self.oc, self.other):
            assert self.root.contains(x)

    def test_nonContainment_parents(self):
        assert not self.shsec.contains(self.hsec)
        assert not self.shsec.contains(self.sec)
        assert not self.shsec.contains(self.ec)
        assert not self.shsec.contains(self.c)

        assert not self.hsec.contains(self.sec)
        assert not self.hsec.contains(self.ec)
        assert not self.hsec.contains(self.c)

        assert not self.sec.contains(self.ec)
        assert not self.sec.contains(self.c)

        assert not self.ec.contains(self.c)
        assert not self.soc.contains(self.oc)

        for x in (self.shsec, self.hsec, self.sec, self.ec, self.c,
                  self.soc, self.oc, self.other):
            assert not x.contains(self.root)

    def test_nonContainment_nonParents(self):
        groups=([self.shsec, self.hsec, self.sec, self.ec],
                [self.soc, self.oc],
                [self.other])
        for g1 in groups:
            for g2 in groups:
                if g1!=g2:
                    for i1 in g1:
                        for i2 in g2:
                            assert not i1.contains(i2)
        assert not self.c.contains(self.other)
        assert not self.other.contains(self.c)

class LDAPDistinguishedName_Malformed(unittest.TestCase):
    def testMalformed(self):
        self.assertRaises(dn.InvalidRelativeDistinguishedName,
                          dn.DistinguishedName,
                          'foo')
        self.assertRaises(dn.InvalidRelativeDistinguishedName,
                          dn.DistinguishedName,
                          'foo,dc=com')
        self.assertRaises(dn.InvalidRelativeDistinguishedName,
                          dn.DistinguishedName,
                          'ou=something,foo')
        self.assertRaises(dn.InvalidRelativeDistinguishedName,
                          dn.DistinguishedName,
                          'foo,foo')

class LDAPDistinguishedName_Prettify(unittest.TestCase):
    def testPrettifySpaces(self):
        """DistinguishedName(...).getText() prettifies the DN by removing extra whitespace."""
        d=dn.DistinguishedName('cn=foo, o=bar,  c=us')
        assert d.getText() == u'cn=foo,o=bar,c=us'

class DistinguishedName_Init(unittest.TestCase):
    def testGetText(self):
        d=dn.DistinguishedName('dc=example,dc=com')
        self.assertEqual(d.getText(), u'dc=example,dc=com')

    def testDN(self):
        proto=dn.DistinguishedName('dc=example,dc=com')
        d=dn.DistinguishedName(proto)
        self.assertEqual(d.getText(), u'dc=example,dc=com')

    def testEqualToByteString(self):
        """
        DistinguishedName is equal to its bytes representation
        """
        d = dn.DistinguishedName('dc=example,dc=com')
        self.assertEqual(d, b'dc=example,dc=com')

    def testEqualToString(self):
        """
        DistinguishedName is equal to its unicode representation
        """
        d = dn.DistinguishedName('dc=example,dc=com')
        self.assertEqual(d, u'dc=example,dc=com')


class RelativeDistinguishedName_Init(unittest.TestCase):
    def testGetText(self):
        rdn=dn.RelativeDistinguishedName('dc=example')
        self.assertEqual(rdn.getText(), u'dc=example')

    def testRDN(self):
        proto=dn.RelativeDistinguishedName('dc=example')
        rdn=dn.RelativeDistinguishedName(proto)
        self.assertEqual(rdn.getText(), u'dc=example')

class DistinguishedName_Comparison(unittest.TestCase):
    """
    Tests for comparing DistinguishedName.
    """

    def test_parent_child(self):
        """
        The parent is greater than the child.
        """
        dn1=dn.DistinguishedName('dc=example,dc=com')
        dn2=dn.DistinguishedName('dc=and,dc=example,dc=com')

        self.assertLess(dn2, dn1)
        self.assertGreater(dn1, dn2)
