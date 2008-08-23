"""
Test cases for ldaptor.schema module.
"""

from twisted.trial import unittest
from ldaptor import schema

OBJECTCLASSES = {
    'organization': """( 2.5.6.4 NAME 'organization'
	DESC 'RFC2256: an organization'
	SUP top STRUCTURAL
	MUST o
	MAY ( userPassword $ searchGuide $ seeAlso $ businessCategory $
		x121Address $ registeredAddress $ destinationIndicator $
		preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $
		telephoneNumber $ internationaliSDNNumber $
		facsimileTelephoneNumber $ street $ postOfficeBox $ postalCode $
		postalAddress $ physicalDeliveryOfficeName $ st $ l $ description ) )""",

    'organizationalUnit': """( 2.5.6.5 NAME 'organizationalUnit'
	DESC 'RFC2256: an organizational unit'
	SUP top STRUCTURAL
	MUST ou
	MAY ( userPassword $ searchGuide $ seeAlso $ businessCategory $
		x121Address $ registeredAddress $ destinationIndicator $
		preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $
		telephoneNumber $ internationaliSDNNumber $
		facsimileTelephoneNumber $ street $ postOfficeBox $ postalCode $
		postalAddress $ physicalDeliveryOfficeName $ st $ l $ description ) )""",

    'country': """( 2.5.6.2 NAME 'country'
	DESC 'RFC2256: a country'
	SUP top STRUCTURAL
	MUST c
	MAY ( searchGuide $ description ) )""",
    }

class AttributeType_KnownValues(unittest.TestCase):
    knownValues = [

        ("""( 2.5.4.4 NAME ( 'sn' 'surname' )
        DESC 'RFC2256: last (family) name(s) for which the entity is known by'
        SUP name )""",
         { 'oid': '2.5.4.4',
           'name': ('sn', 'surname',),
           'desc': 'RFC2256: last (family) name(s) for which the entity is known by',
           'sup': 'name',
           }),

        ("""( 2.5.4.2 NAME 'knowledgeInformation'
        DESC 'RFC2256: knowledge information'
        EQUALITY caseIgnoreMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )""",
         { 'oid': '2.5.4.2',
           'name': ('knowledgeInformation',),
           'desc': 'RFC2256: knowledge information',
           'equality': 'caseIgnoreMatch',
           'syntax': '1.3.6.1.4.1.1466.115.121.1.15{32768}',
        }),

        ("""( 2.5.4.5 NAME 'serialNumber'
        DESC 'RFC2256: serial number of the entity'
        EQUALITY caseIgnoreMatch
	SUBSTR caseIgnoreSubstringsMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.44{64} )""",
         { 'oid': '2.5.4.5',
           'name': ('serialNumber',),
           'desc': 'RFC2256: serial number of the entity',
           'equality': 'caseIgnoreMatch',
           'substr': 'caseIgnoreSubstringsMatch',
           'syntax': '1.3.6.1.4.1.1466.115.121.1.44{64}',
           }),


        ("""( 2.5.4.6 NAME ( 'c' 'countryName' )
	DESC 'RFC2256: ISO-3166 country 2-letter code'
	SUP name SINGLE-VALUE )""",
         { 'oid': '2.5.4.6',
           'name': ('c', 'countryName',),
           'desc': 'RFC2256: ISO-3166 country 2-letter code',
           'sup': 'name',
           'single_value': 1,
           }),

        ("""( 1.2.840.113549.1.9.1
	NAME ( 'email' 'emailAddress' 'pkcs9email' )
	DESC 'RFC2459: legacy attribute for email addresses in DNs'
	EQUALITY caseIgnoreIA5Match
	SUBSTR caseIgnoreIA5SubstringsMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{128} )""",
         { 'oid': '1.2.840.113549.1.9.1',
           'name': ('email', 'emailAddress', 'pkcs9email', ),
           'desc': 'RFC2459: legacy attribute for email addresses in DNs',
           'equality': 'caseIgnoreIA5Match',
           'substr': 'caseIgnoreIA5SubstringsMatch',
           'syntax': '1.3.6.1.4.1.1466.115.121.1.26{128}',
           }),

        ("""( 1.2.840.113549.1.9.1
        NAME ( 'email' 'emailAddress' 'pkcs9email' )
        DESC 'RFC2459: legacy attribute for email addresses in DNs'
        EQUALITY caseIgnoreIA5Match
        SUBSTR caseIgnoreIA5SubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{128}
        X-ORDERED 'VALUES' )""",
         { 'oid': '1.2.840.113549.1.9.1',
           'name': ('email', 'emailAddress', 'pkcs9email', ),
           'desc': 'RFC2459: legacy attribute for email addresses in DNs',
           'equality': 'caseIgnoreIA5Match',
           'substr': 'caseIgnoreIA5SubstringsMatch',
           'syntax': '1.3.6.1.4.1.1466.115.121.1.26{128}',
           'x_attrs': [('X-ORDERED', 'VALUES'),],
           }),

        ("""( 1.3.6.1.3.42.1 NAME 'olcDatabase'
        EQUALITY caseIgnoreMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
        SINGLE-VALUE X-ORDERED 'SIBLINGS' )""",
         { 'oid': '1.3.6.1.3.42.1',
           'name': ('olcDatabase',),
           'equality': 'caseIgnoreMatch',
           'syntax': '1.3.6.1.4.1.1466.115.121.1.15',
           'single_value': 1,
           'x_attrs': [('X-ORDERED', 'SIBLINGS')],
           }),

        ("""( 1.3.6.1.3.42.2
        NAME 'olcSuffix'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
        X-ORDERED 'VALUES' )""",
         { 'oid': '1.3.6.1.3.42.2',
           'name': ('olcSuffix',),
           'equality': 'distinguishedNameMatch',
           'syntax': '1.3.6.1.4.1.1466.115.121.1.12',
           'x_attrs': [('X-ORDERED', 'VALUES')],
           }),

        ("""( 1.3.6.1.3.42.3
        NAME 'experimentalWithQdstrings'
        X-FOO ( 'one' 'two' ) )""",
         { 'oid': '1.3.6.1.3.42.3',
           'name': ('experimentalWithQdstrings',),
           'x_attrs': [('X-FOO', ('one', 'two'))],
           }),

        ]

    def testParse(self):
        defaults = {
            'name': None,
            'desc': None,
            'obsolete': 0,
            'sup': [],
            'equality': None,
            'ordering': None,
            'substr': None,
            'syntax': None,
            'single_value': 0,
            'collective': 0,
            'no_user_modification': 0,
            'usage': None,
            }
        for text, expected in self.knownValues:
            a=schema.AttributeTypeDescription(text)
            self.failIfEqual(a.oid, None)
            for key, want in expected.items():
                if key in defaults:
                    del defaults[key]
                got = getattr(a, key)
                self.assertEquals(got, want)

            for key, want in defaults.items():
                got = getattr(a, key)
                self.assertEquals(got, want)

    def testStringification(self):
        for want, values in self.knownValues:
            a=schema.AttributeTypeDescription(None)
            for key, val in values.items():
                setattr(a, key, val)

            want = ' '.join(want.split(None))
            got = ' '.join(str(a).split(None))
            self.assertEquals(got, want)

class ObjectClass_KnownValues(unittest.TestCase):
    knownValues = [

        (OBJECTCLASSES['organization'],
         { 'oid': '2.5.6.4',
           'name': ('organization',),
           'desc': 'RFC2256: an organization',
           'sup': ['top'],
           'type': 'STRUCTURAL',
           'must': ['o'],
           'may': ['userPassword', 'searchGuide', 'seeAlso',
                   'businessCategory', 'x121Address', 'registeredAddress',
                   'destinationIndicator', 'preferredDeliveryMethod',
                   'telexNumber', 'teletexTerminalIdentifier',
                   'telephoneNumber', 'internationaliSDNNumber',
                   'facsimileTelephoneNumber', 'street', 'postOfficeBox',
                   'postalCode', 'postalAddress',
                   'physicalDeliveryOfficeName', 'st', 'l', 'description'],
           }),

        (OBJECTCLASSES['organizationalUnit'],
         { 'oid': '2.5.6.5',
           'name': ('organizationalUnit',),
           'desc': 'RFC2256: an organizational unit',
           'sup': ['top'],
           'type': 'STRUCTURAL',
           'must': ['ou'],
           'may': [ 'userPassword', 'searchGuide', 'seeAlso',
		'businessCategory', 'x121Address', 'registeredAddress',
		'destinationIndicator', 'preferredDeliveryMethod',
		'telexNumber', 'teletexTerminalIdentifier',
		'telephoneNumber', 'internationaliSDNNumber',
		'facsimileTelephoneNumber', 'street', 'postOfficeBox',
		'postalCode', 'postalAddress', 'physicalDeliveryOfficeName',
		'st', 'l', 'description', ],
           }),


        ]

    def testParse(self):
        defaults = {
            'name': None,
            'desc': None,
            'obsolete': 0,
            'sup': None,
            'type': 'STRUCTURAL',
            'must': [],
            'may': [],
            }
        for text, expected in self.knownValues:
            a=schema.ObjectClassDescription(text)
            self.failIfEqual(a.oid, None)
            for key, want in expected.items():
                if key in defaults:
                    del defaults[key]
                got = getattr(a, key)
                self.assertEquals(got, want)

            for key, want in defaults.items():
                got = getattr(a, key)
                self.assertEquals(got, want)

    def testStringification(self):
        for want, values in self.knownValues:
            a=schema.ObjectClassDescription(None)
            for key, val in values.items():
                setattr(a, key, val)

            want = ' '.join(want.split(None))
            got = ' '.join(str(a).split(None))
            self.assertEquals(got, want)


class TestComparison(unittest.TestCase):
    ORDER = [
        'country',
        'organization',
        'organizationalUnit',
        ]
    def setUp(self):
        data = {}
        for oc,text in OBJECTCLASSES.items():
            data[oc] = schema.ObjectClassDescription(text)
        self.data = data

    def test_eq(self):
        for k1 in self.data:
            for k2 in self.data:
                if k1 == k2:
                    self.failUnless(self.data[k1] == self.data[k2])
                else:
                    self.failIf(self.data[k1] == self.data[k2])

    def test_ne(self):
        for k1 in self.data:
            for k2 in self.data:
                if k1 == k2:
                    self.failIf(self.data[k1] != self.data[k2])
                else:
                    self.failUnless(self.data[k1] != self.data[k2])

    def test_order(self):
        for i,base in enumerate(self.ORDER):
            self.failUnless(self.data[base] <= self.data[base])
            self.failUnless(self.data[base] >= self.data[base])
            self.failIf(self.data[base] < self.data[base])
            self.failIf(self.data[base] > self.data[base])
            for lower in self.ORDER[:i]:
                self.failUnless(self.data[lower] < self.data[base])
                self.failUnless(self.data[lower] <= self.data[base])
                self.failIf(self.data[base] < self.data[lower])
                self.failIf(self.data[base] <= self.data[lower])
            for higher in self.ORDER[i+1:]:
                self.failUnless(self.data[higher] > self.data[base])
                self.failUnless(self.data[higher] >= self.data[base])
                self.failIf(self.data[base] > self.data[higher])
                self.failIf(self.data[base] >= self.data[higher])

"""


attributetype ( 2.5.4.7 NAME ( 'l' 'localityName' )
	DESC 'RFC2256: locality which this object resides in'
	SUP name )

attributetype ( 2.5.4.8 NAME ( 'st' 'stateOrProvinceName' )
	DESC 'RFC2256: state or province which this object resides in'
	SUP name )

attributetype ( 2.5.4.9 NAME ( 'street' 'streetAddress' )
	DESC 'RFC2256: street address of this object'
	EQUALITY caseIgnoreMatch
	SUBSTR caseIgnoreSubstringsMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{128} )

attributetype ( 2.5.4.10 NAME ( 'o' 'organizationName' )
	DESC 'RFC2256: organization this object belongs to'
	SUP name )

attributetype ( 2.5.4.11 NAME ( 'ou' 'organizationalUnitName' )
	DESC 'RFC2256: organizational unit this object belongs to'
	SUP name )

attributetype ( 2.5.4.12 NAME 'title'
	DESC 'RFC2256: title associated with the entity'
	SUP name )

attributetype ( 2.5.4.13 NAME 'description'
	DESC 'RFC2256: descriptive information'
	EQUALITY caseIgnoreMatch
	SUBSTR caseIgnoreSubstringsMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{1024} )

attributetype ( 2.5.4.14 NAME 'searchGuide'
	DESC 'RFC2256: search guide, obsoleted by enhancedSearchGuide'
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.25 )

attributetype ( 2.5.4.15 NAME 'businessCategory'
	DESC 'RFC2256: business category'
	EQUALITY caseIgnoreMatch
	SUBSTR caseIgnoreSubstringsMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{128} )

attributetype ( 2.5.4.16 NAME 'postalAddress'
	DESC 'RFC2256: postal address'
	EQUALITY caseIgnoreListMatch
	SUBSTR caseIgnoreListSubstringsMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )

attributetype ( 2.5.4.17 NAME 'postalCode'
	DESC 'RFC2256: postal code'
	EQUALITY caseIgnoreMatch
	SUBSTR caseIgnoreSubstringsMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{40} )

attributetype ( 2.5.4.18 NAME 'postOfficeBox'
	DESC 'RFC2256: Post Office Box'
	EQUALITY caseIgnoreMatch
	SUBSTR caseIgnoreSubstringsMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{40} )

attributetype ( 2.5.4.19 NAME 'physicalDeliveryOfficeName'
	DESC 'RFC2256: Physical Delivery Office Name'
	EQUALITY caseIgnoreMatch
	SUBSTR caseIgnoreSubstringsMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{128} )

attributetype ( 2.5.4.20 NAME 'telephoneNumber'
	DESC 'RFC2256: Telephone Number'
	EQUALITY telephoneNumberMatch
	SUBSTR telephoneNumberSubstringsMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.50{32} )

attributetype ( 2.5.4.21 NAME 'telexNumber'
	DESC 'RFC2256: Telex Number'
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.52 )

attributetype ( 2.5.4.22 NAME 'teletexTerminalIdentifier'
	DESC 'RFC2256: Teletex Terminal Identifier'
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.51 )

attributetype ( 2.5.4.23 NAME ( 'facsimileTelephoneNumber' 'fax' )
	DESC 'RFC2256: Facsimile (Fax) Telephone Number'
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.22 )

attributetype ( 2.5.4.24 NAME 'x121Address'
	DESC 'RFC2256: X.121 Address'
	EQUALITY numericStringMatch
	SUBSTR numericStringSubstringsMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.36{15} )

attributetype ( 2.5.4.25 NAME 'internationaliSDNNumber'
	DESC 'RFC2256: international ISDN number'
	EQUALITY numericStringMatch
	SUBSTR numericStringSubstringsMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.36{16} )

attributetype ( 2.5.4.26 NAME 'registeredAddress'
	DESC 'RFC2256: registered postal address'
	SUP postalAddress
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )

attributetype ( 2.5.4.27 NAME 'destinationIndicator'
	DESC 'RFC2256: destination indicator'
	EQUALITY caseIgnoreMatch
	SUBSTR caseIgnoreSubstringsMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.44{128} )

attributetype ( 2.5.4.28 NAME 'preferredDeliveryMethod'
	DESC 'RFC2256: preferred delivery method'
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.14
	SINGLE-VALUE )

attributetype ( 2.5.4.29 NAME 'presentationAddress'
	DESC 'RFC2256: presentation address'
	EQUALITY presentationAddressMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.43
	SINGLE-VALUE )

attributetype ( 2.5.4.30 NAME 'supportedApplicationContext'
	DESC 'RFC2256: supported application context'
	EQUALITY objectIdentifierMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )

attributetype ( 2.5.4.31 NAME 'member'
	DESC 'RFC2256: member of a group'
	SUP distinguishedName )

attributetype ( 2.5.4.32 NAME 'owner'
	DESC 'RFC2256: owner (of the object)'
	SUP distinguishedName )

attributetype ( 2.5.4.33 NAME 'roleOccupant'
	DESC 'RFC2256: occupant of role'
	SUP distinguishedName )

attributetype ( 2.5.4.34 NAME 'seeAlso'
	DESC 'RFC2256: DN of related object'
	SUP distinguishedName )

attributetype ( 2.5.4.36 NAME 'userCertificate'
	DESC 'RFC2256: X.509 user certificate, use ;binary'
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.8 )

attributetype ( 2.5.4.37 NAME 'cACertificate'
	DESC 'RFC2256: X.509 CA certificate, use ;binary'
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.8 )

attributetype ( 2.5.4.38 NAME 'authorityRevocationList'
	DESC 'RFC2256: X.509 authority revocation list, use ;binary'
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.9 )

attributetype ( 2.5.4.39 NAME 'certificateRevocationList'
	DESC 'RFC2256: X.509 certificate revocation list, use ;binary'
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.9 )

attributetype ( 2.5.4.40 NAME 'crossCertificatePair'
	DESC 'RFC2256: X.509 cross certificate pair, use ;binary'
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.10 )

attributetype ( 2.5.4.42 NAME ( 'givenName' 'gn' )
	DESC 'RFC2256: first name(s) for which the entity is known by'
	SUP name )

attributetype ( 2.5.4.43 NAME 'initials'
	DESC 'RFC2256: initials of some or all of names, but not the surname(s).'
	SUP name )

attributetype ( 2.5.4.44 NAME 'generationQualifier'
	DESC 'RFC2256: name qualifier indicating a generation'
	SUP name )

attributetype ( 2.5.4.45 NAME 'x500UniqueIdentifier'
	DESC 'RFC2256: X.500 unique identifier'
	EQUALITY bitStringMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.6 )

attributetype ( 2.5.4.46 NAME 'dnQualifier'
	DESC 'RFC2256: DN qualifier'
	EQUALITY caseIgnoreMatch
	ORDERING caseIgnoreOrderingMatch
	SUBSTR caseIgnoreSubstringsMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )

attributetype ( 2.5.4.47 NAME 'enhancedSearchGuide'
	DESC 'RFC2256: enhanced search guide'
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.21 )

attributetype ( 2.5.4.48 NAME 'protocolInformation'
	DESC 'RFC2256: protocol information'
	EQUALITY protocolInformationMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.42 )

attributetype ( 2.5.4.50 NAME 'uniqueMember'
	DESC 'RFC2256: unique member of a group'
	EQUALITY uniqueMemberMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.34 )

attributetype ( 2.5.4.51 NAME 'houseIdentifier'
	DESC 'RFC2256: house identifier'
	EQUALITY caseIgnoreMatch
	SUBSTR caseIgnoreSubstringsMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )

attributetype ( 2.5.4.52 NAME 'supportedAlgorithms'
	DESC 'RFC2256: supported algorithms'
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.49 )

attributetype ( 2.5.4.53 NAME 'deltaRevocationList'
	DESC 'RFC2256: delta revocation list; use ;binary'
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.9 )

attributetype ( 2.5.4.54 NAME 'dmdName'
	DESC 'RFC2256: name of DMD'
	SUP name )




objectclass ( 2.5.6.3 NAME 'locality'
	DESC 'RFC2256: a locality'
	SUP top STRUCTURAL
	MAY ( street $ seeAlso $ searchGuide $ st $ l $ description ) )


objectclass ( 2.5.6.6 NAME 'person'
	DESC 'RFC2256: a person'
	SUP top STRUCTURAL
	MUST ( sn $ cn )
	MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )

objectclass ( 2.5.6.7 NAME 'organizationalPerson'
	DESC 'RFC2256: an organizational person'
	SUP person STRUCTURAL
	MAY ( title $ x121Address $ registeredAddress $ destinationIndicator $
		preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $
		telephoneNumber $ internationaliSDNNumber $
		facsimileTelephoneNumber $ street $ postOfficeBox $ postalCode $
		postalAddress $ physicalDeliveryOfficeName $ ou $ st $ l ) )

objectclass ( 2.5.6.8 NAME 'organizationalRole'
	DESC 'RFC2256: an organizational role'
	SUP top STRUCTURAL
	MUST cn
	MAY ( x121Address $ registeredAddress $ destinationIndicator $
		preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $
		telephoneNumber $ internationaliSDNNumber $ facsimileTelephoneNumber $
		seeAlso $ roleOccupant $ preferredDeliveryMethod $ street $
		postOfficeBox $ postalCode $ postalAddress $
		physicalDeliveryOfficeName $ ou $ st $ l $ description ) )

objectclass ( 2.5.6.9 NAME 'groupOfNames'
	DESC 'RFC2256: a group of names (DNs)'
	SUP top STRUCTURAL
	MUST ( member $ cn )
	MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description ) )

objectclass ( 2.5.6.10 NAME 'residentialPerson'
	DESC 'RFC2256: an residential person'
	SUP person STRUCTURAL
	MUST l
	MAY ( businessCategory $ x121Address $ registeredAddress $
		destinationIndicator $ preferredDeliveryMethod $ telexNumber $
		teletexTerminalIdentifier $ telephoneNumber $ internationaliSDNNumber $
		facsimileTelephoneNumber $ preferredDeliveryMethod $ street $
		postOfficeBox $ postalCode $ postalAddress $
		physicalDeliveryOfficeName $ st $ l ) )

objectclass ( 2.5.6.11 NAME 'applicationProcess'
	DESC 'RFC2256: an application process'
	SUP top STRUCTURAL
	MUST cn
	MAY ( seeAlso $ ou $ l $ description ) )

objectclass ( 2.5.6.12 NAME 'applicationEntity'
	DESC 'RFC2256: an application entity'
	SUP top STRUCTURAL
	MUST ( presentationAddress $ cn )
	MAY ( supportedApplicationContext $ seeAlso $ ou $ o $ l $
	description ) )

objectclass ( 2.5.6.13 NAME 'dSA'
	DESC 'RFC2256: a directory system agent (a server)'
	SUP applicationEntity STRUCTURAL
	MAY knowledgeInformation )

objectclass ( 2.5.6.14 NAME 'device'
	DESC 'RFC2256: a device'
	SUP top STRUCTURAL
	MUST cn
	MAY ( serialNumber $ seeAlso $ owner $ ou $ o $ l $ description ) )

objectclass ( 2.5.6.15 NAME 'strongAuthenticationUser'
	DESC 'RFC2256: a strong authentication user'
	SUP top AUXILIARY
	MUST userCertificate )

objectclass ( 2.5.6.16 NAME 'certificationAuthority'
	DESC 'RFC2256: a certificate authority'
	SUP top AUXILIARY
	MUST ( authorityRevocationList $ certificateRevocationList $
		cACertificate ) MAY crossCertificatePair )

objectclass ( 2.5.6.17 NAME 'groupOfUniqueNames'
	DESC 'RFC2256: a group of unique names (DN and Unique Identifier)'
	SUP top STRUCTURAL
	MUST ( uniqueMember $ cn )
	MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description ) )

objectclass ( 2.5.6.18 NAME 'userSecurityInformation'
	DESC 'RFC2256: a user security information'
	SUP top AUXILIARY
	MAY ( supportedAlgorithms ) )

objectclass ( 2.5.6.16.2 NAME 'certificationAuthority-V2'
	SUP certificationAuthority
	AUXILIARY MAY ( deltaRevocationList ) )

objectclass ( 2.5.6.19 NAME 'cRLDistributionPoint'
	SUP top STRUCTURAL
	MUST ( cn )
	MAY ( certificateRevocationList $ authorityRevocationList $
		deltaRevocationList ) )

objectclass ( 2.5.6.20 NAME 'dmd'
	SUP top STRUCTURAL
	MUST ( dmdName )
	MAY ( userPassword $ searchGuide $ seeAlso $ businessCategory $
		x121Address $ registeredAddress $ destinationIndicator $
		preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $
		telephoneNumber $ internationaliSDNNumber $ facsimileTelephoneNumber $
		street $ postOfficeBox $ postalCode $ postalAddress $
		physicalDeliveryOfficeName $ st $ l $ description ) )

objectclass ( 2.5.6.21 NAME 'pkiUser'
	DESC 'RFC2587: a PKI user'
	SUP top AUXILIARY
	MAY userCertificate )

objectclass ( 2.5.6.22 NAME 'pkiCA'
	DESC 'RFC2587: PKI certificate authority'
	SUP top AUXILIARY
	MAY ( authorityRevocationList $ certificateRevocationList $
		cACertificate $ crossCertificatePair ) )

objectclass ( 2.5.6.23 NAME 'deltaCRL'
	DESC 'RFC2587: PKI user'
	SUP top AUXILIARY
	MAY deltaRevocationList )

attributetype ( 1.3.6.1.4.1.250.1.57 NAME 'labeledURI'
	DESC 'RFC2079: Uniform Resource Identifier with optional label'
	EQUALITY caseExactMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )

objectclass ( 1.3.6.1.4.1.250.3.15 NAME 'labeledURIObject'
	DESC 'RFC2079: object that contains the URI attribute type'
	MAY ( labeledURI )
	SUP top AUXILIARY )

attributetype ( 0.9.2342.19200300.100.1.1
	NAME ( 'uid' 'userid' )
	DESC 'RFC1274: user identifier'
	EQUALITY caseIgnoreMatch
	SUBSTR caseIgnoreSubstringsMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )

attributetype ( 0.9.2342.19200300.100.1.3
	NAME ( 'mail' 'rfc822Mailbox' )
	DESC 'RFC1274: RFC822 Mailbox'
    EQUALITY caseIgnoreIA5Match
    SUBSTR caseIgnoreIA5SubstringsMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{256} )

objectclass ( 0.9.2342.19200300.100.4.19 NAME 'simpleSecurityObject'
	DESC 'RFC1274: simple security object'
	SUP top AUXILIARY
	MUST userPassword )

attributetype ( 0.9.2342.19200300.100.1.25
	NAME ( 'dc' 'domainComponent' )
	DESC 'RFC1274/2247: domain component'
	EQUALITY caseIgnoreIA5Match
	SUBSTR caseIgnoreIA5SubstringsMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )

objectclass ( 1.3.6.1.4.1.1466.344 NAME 'dcObject'
	DESC 'RFC2247: domain component object'
	SUP top AUXILIARY MUST dc )

objectclass ( 1.3.6.1.1.3.1 NAME 'uidObject'
	DESC 'RFC2377: uid object'
	SUP top AUXILIARY MUST uid )

attributetype ( 0.9.2342.19200300.100.1.37
	NAME 'associatedDomain'
	DESC 'RFC1274: domain associated with object'
	EQUALITY caseIgnoreIA5Match
	SUBSTR caseIgnoreIA5SubstringsMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )

"""
