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

	    self.assertEquals(fromString, fromList)

	    fromStringToString = str(fromString)
	    fromListToString = str(fromList)

	    assert fromStringToString == fromListToString

            canon = fromStringToString
            # DNs equal their string representation. Note this does
            # not mean they equal all the possible string
            # representations -- just the canonical one.
	    self.assertEquals(fromString, canon)
	    self.assertEquals(fromList, canon)
	    self.assertEquals(canon, fromString)
	    self.assertEquals(canon, fromList)
            
            # DNs can be used interchangeably with their canonical
            # string representation as hash keys.
	    self.assertEquals(hash(fromString), hash(canon))
	    self.assertEquals(hash(fromList), hash(canon))
	    self.assertEquals(hash(canon), hash(fromString))
	    self.assertEquals(hash(canon), hash(fromList))


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
        got = str(got)
        self.assertEquals(got,
                          r'cn=test+owner=uid\=foo\,ou\=depar'
                          +r'tment\,dc\=example\,dc\=com,dc=ex'
                          +r'ample,dc=com')

class LDAPDistinguishedName_RFC2253_Examples(TestCaseWithKnownValues):
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

	(u'SN=Lu\u010di\u0107'.encode('utf-8'),
	 [[('SN', u'Lu\u010di\u0107'.encode('utf-8'))]])

	)

class LDAPDistinguishedName_InitialSpaces(TestCaseWithKnownValues):
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
        """str(DistinguishedName(...)) prettifies the DN by removing extra whitespace."""
	d=dn.DistinguishedName('cn=foo, o=bar,  c=us')
	assert str(d) == 'cn=foo,o=bar,c=us'

class DistinguishedName_Init(unittest.TestCase):
    def testString(self):
	d=dn.DistinguishedName('dc=example,dc=com')
	self.assertEquals(str(d), 'dc=example,dc=com')

    def testDN(self):
	proto=dn.DistinguishedName('dc=example,dc=com')
	d=dn.DistinguishedName(proto)
	self.assertEquals(str(d), 'dc=example,dc=com')

class RelativeDistinguishedName_Init(unittest.TestCase):
    def testString(self):
	rdn=dn.RelativeDistinguishedName('dc=example')
	self.assertEquals(str(rdn), 'dc=example')

    def testRDN(self):
	proto=dn.RelativeDistinguishedName('dc=example')
	rdn=dn.RelativeDistinguishedName(proto)
	self.assertEquals(str(rdn), 'dc=example')

class DistinguishedName_Comparison(unittest.TestCase):
    # TODO test more carefully
    def testGT(self):
	dn1=dn.DistinguishedName('dc=example,dc=com')
	dn2=dn.DistinguishedName('dc=bar,dc=example,dc=com')
        self.failUnless(dn1 > dn2)
