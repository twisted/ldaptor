#!/usr/bin/python

"""
Test cases for ldaptor.protocols.ldap.distinguishedname module.
"""

import unittest
from ldaptor.protocols.ldap import distinguishedname as dn

class TestCaseWithKnownValues(unittest.TestCase):
    knownValues = ()

    def testKnownValues(self):
	for s, l in self.knownValues:
	    fromString = dn.DistinguishedName(stringValue=s)
	    fromList = dn.DistinguishedName(
		listOfRDNs=[dn.RelativeDistinguishedName(attributeTypesAndValues=x)
			    for x in l])

	    assert fromString == fromList

	    fromStringToString = str(fromString)
	    fromListToString = str(fromList)

	    assert fromStringToString == fromListToString


class LDAPDistinguishedName_Escaping(TestCaseWithKnownValues):
    knownValues = (

	('', []),

	('foo', [['foo']]),

	(r'\,bar', [[r',bar']]),
	(r'foo\,bar', [[r'foo,bar']]),
	(r'foo\,', [[r'foo,']]),

	(r'\+bar', [[r'+bar']]),
	(r'foo\+bar', [[r'foo+bar']]),
	(r'foo\+', [[r'foo+']]),

	(r'\"bar', [[r'"bar']]),
	(r'foo\"bar', [[r'foo"bar']]),
	(r'foo\"', [[r'foo"']]),

	(r'\\bar', [[r'\bar']]),
	(r'foo\\bar', [[r'foo\bar']]),
	(r'foo\\', [['foo\\']]),

	(r'\<bar', [[r'<bar']]),
	(r'foo\<bar', [[r'foo<bar']]),
	(r'foo\<', [[r'foo<']]),

	(r'\>bar', [[r'>bar']]),
	(r'foo\>bar', [[r'foo>bar']]),
	(r'foo\>', [[r'foo>']]),

	(r'\;bar', [[r';bar']]),
	(r'foo\;bar', [[r'foo;bar']]),
	(r'foo\;', [[r'foo;']]),

	(r'\#bar', [[r'#bar']]),

	(r'\ bar', [[r' bar']]),

	(r'bar\ ', [[r'bar ']]),

	)

class LDAPDistinguishedName_RFC2253_Examples(TestCaseWithKnownValues):
    knownValues = (

	('CN=Steve Kille,O=Isode Limited,C=GB',
	 [['CN=Steve Kille'], ['O=Isode Limited'], ['C=GB']]),


	('OU=Sales+CN=J. Smith,O=Widget Inc.,C=US',
	 [['OU=Sales', 'CN=J. Smith'], ['O=Widget Inc.'], ['C=US']]),

	(r'CN=L. Eagle,O=Sue\, Grabbit and Runn,C=GB',
	 [['CN=L. Eagle'], ['O=Sue, Grabbit and Runn'], ['C=GB']]),

	(r'CN=Before\0DAfter,O=Test,C=GB',
	 [['CN=Before\x0dAfter'], ['O=Test'], ['C=GB']]),

	(r'1.3.6.1.4.1.1466.0=#04024869,O=Test,C=GB',
	 [['1.3.6.1.4.1.1466.0=#04024869'], ['O=Test'], ['C=GB']]),

	(u'SN=Lu\u010di\u0107'.encode('utf-8'),
	 [[u'SN=Lu\u010di\u0107'.encode('utf-8')]])

	)

class LDAPDistinguishedName_InitialSpaces(TestCaseWithKnownValues):
    knownValues = (

	('cn=foo, ou=bar,  dc=quux, \ attributeThatStartsWithSpace=Value',
	 [['cn=foo'],
	  ['ou=bar'],
	  ['dc=quux'],
	  [' attributeThatStartsWithSpace=Value']]),

	)

class LDAPDistinguishedName_DomainName(unittest.TestCase):
    def testNonDc(self):
	d=dn.DistinguishedName(stringValue='cn=foo,o=bar,c=us')
	assert d.getDomainName() is None

    def testNonTrailingDc(self):
	d=dn.DistinguishedName(stringValue='cn=foo,o=bar,dc=foo,c=us')
	assert d.getDomainName() is None

    def testSimple_ExampleCom(self):
	d=dn.DistinguishedName(stringValue='dc=example,dc=com')
	assert d.getDomainName() == 'example.com'

    def testSimple_SubExampleCom(self):
	d=dn.DistinguishedName(stringValue='dc=sub,dc=example,dc=com')
	assert d.getDomainName() == 'sub.example.com'

    def testSimple_HostSubExampleCom(self):
	d=dn.DistinguishedName(stringValue='cn=host,dc=sub,dc=example,dc=com')
	assert d.getDomainName() == 'sub.example.com'

    def testInterleaved_SubHostSubExampleCom(self):
	d=dn.DistinguishedName(stringValue='dc=sub2,cn=host,dc=sub,dc=example,dc=com')
	assert d.getDomainName() == 'sub.example.com'

class LDAPDistinguishedName_contains(unittest.TestCase):
    shsec=dn.DistinguishedName(stringValue='dc=sub2,cn=host,dc=sub,dc=example,dc=com')
    hsec=dn.DistinguishedName(stringValue='cn=host,dc=sub,dc=example,dc=com')
    sec=dn.DistinguishedName(stringValue='dc=sub,dc=example,dc=com')
    ec=dn.DistinguishedName(stringValue='dc=example,dc=com')
    c=dn.DistinguishedName(stringValue='dc=com')

    soc=dn.DistinguishedName(stringValue='dc=sub,dc=other,dc=com')
    oc=dn.DistinguishedName(stringValue='dc=other,dc=com')

    other=dn.DistinguishedName(stringValue='o=foo,c=US')

    root=dn.DistinguishedName(stringValue='')

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

if __name__ == '__main__':
    unittest.main()
