# Twisted, the Framework of Your Internet
# Copyright (C) 2001 Matthew W. Lefkowitz
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

"""LDAP protocol message conversion; no application logic here."""

from pureber import *

next_ldap_message_id=1
def alloc_ldap_message_id():
    global next_ldap_message_id
    r=next_ldap_message_id
    next_ldap_message_id=next_ldap_message_id+1
    return r

def escape(s):
    s = s.replace('\\', r'\5c')
    s = s.replace('*', r'\2a')
    s = s.replace('(', r'\28')
    s = s.replace(')', r'\29')
    s = s.replace('\0', r'\00')
    return s

class LDAPString(BEROctetString):
    pass

class LDAPAttributeValue(BEROctetString):
    pass

class LDAPMessage(BERSequence):
    def decode(self, encoded, berdecoder):
	BERSequence.decode(self, encoded, berdecoder)
	self.id=self.data[0].value
	self.value=self.data[1]
        if self.data[2:]:
            self.controls = []
            for c in self.data[2]:
                self.controls.append((
                    c.controlType,
                    c.criticality,
                    c.controlValue,
                    ))
        else:
            self.controls = None
        assert not self.data[3:]

    def __init__(self, value=None, controls=None, encoded=None, id=None, berdecoder=None):
	BERSequence.__init__(self, value=[], encoded=None)
	if value is not None:
	    assert encoded is None
	    self.id=id
	    if self.id is None:
		self.id=alloc_ldap_message_id()
	    self.value=value
            self.controls = controls
	elif encoded is not None:
	    assert value is None
	    assert controls is None
	    assert berdecoder
	    self.decode(encoded, berdecoder)
	else:
	    raise "You must give either value or encoded"

    def __str__(self):
        l = [BERInteger(self.id), self.value]
        if self.controls is not None:
            l.append(LDAPControls([LDAPControl(*a) for a in self.controls]))
	return str(BERSequence(l))

    def __repr__(self):
	if self.tag==self.__class__.tag:
	    return self.__class__.__name__+"(id=%d, value=%s)"\
		   %(self.id, repr(self.value))
	else:
	    return self.__class__.__name__+"(id=%d, value=%s, tag=%d)" \
		   %(self.id, repr(self.value), self.tag)

class LDAPProtocolOp:
    def __init__(self):
	pass

    def __str__(self):
	raise NotImplementedError

class LDAPProtocolRequest(LDAPProtocolOp):
    needs_answer=1
    pass

class LDAPProtocolResponse(LDAPProtocolOp):
    pass

class LDAPBERDecoderContext_LDAPBindRequest(BERDecoderContext):
    Identities = {
        CLASS_CONTEXT|0x00: BEROctetString,
        }

class LDAPBindRequest(LDAPProtocolRequest, BERSequence):
    tag=CLASS_APPLICATION|0x00

    def decode(self, encoded, berdecoder):
	BERSequence.decode(self, encoded, LDAPBERDecoderContext_LDAPBindRequest(fallback=berdecoder))
	self.version=self.data[0].value
	self.dn=self.data[1].value
	self.auth=self.data[2].value

    def __init__(self, version=None, dn=None, auth=None, encoded=None, berdecoder=None, tag=None):
	LDAPProtocolRequest.__init__(self)
	BERSequence.__init__(self, [], tag=tag)
	if encoded is not None:
	    assert version is None
	    assert dn is None
	    assert auth is None
	    assert berdecoder
	    self.decode(encoded, berdecoder)
	else:
	    self.version=version
	    if self.version is None:
		self.version=3
	    self.dn=dn
	    if self.dn is None:
		self.dn=''
	    self.auth=auth
	    if self.auth is None:
		self.auth=''

    def __str__(self):
	return str(BERSequence([
	    BERInteger(self.version),
	    BEROctetString(self.dn),
	    BEROctetString(self.auth, tag=CLASS_CONTEXT|0),
	    ], tag=self.tag))

    def __repr__(self):
	l=[]
	l.append('version=%d' % self.version)
	l.append('dn=%s' % repr(self.dn))
	l.append('auth=%s' % repr(self.auth))
	if self.tag!=self.__class__.tag:
	    l.append('tag=%d' % self.tag)
	return self.__class__.__name__+'('+', '.join(l)+')'



class LDAPReferral(BERSequence):
    tag = CLASS_CONTEXT | 0x03

class LDAPResult(LDAPProtocolResponse, BERSequence):
    def decode(self, encoded, berdecoder):
	BERSequence.decode(self, encoded, berdecoder)
        assert 3<=len(self.data)<=4
	self.resultCode=self.data[0].value
	self.matchedDN=self.data[1].value
	self.errorMessage=self.data[2].value
	del self.data[0:3]
	try:
	    x=self.data[0]
	except IndexError:
	    self.referral=None
	else:
	    if isinstance(x, LDAPReferral):
		#TODO support referrals
		#self.referral=self.data[0]
		self.referral=None
		del self.data[0]
	    else:
		self.referral=None

    def __init__(self, resultCode=None, matchedDN=None, errorMessage=None, referral=None, serverSaslCreds=None, encoded=None, berdecoder=None):
	LDAPProtocolResponse.__init__(self)
	BERSequence.__init__(self, value=[])
	if resultCode is not None:
	    assert encoded is None
	    self.resultCode=resultCode
            if matchedDN is None:
                matchedDN=''
	    self.matchedDN=matchedDN
            if errorMessage is None:
                errorMessage=''
	    self.errorMessage=errorMessage
	    self.referral=referral
	    self.serverSaslCreds=serverSaslCreds
	elif encoded is not None:
	    assert resultCode is None
	    assert matchedDN is None
	    assert errorMessage is None
	    assert referral is None
	    assert serverSaslCreds is None
	    assert berdecoder
	    self.decode(encoded, berdecoder)
	else:
	    raise "You must give either value or encoded"

    def __str__(self):
	assert self.referral is None #TODO
	return str(BERSequence([
	    BEREnumerated(self.resultCode),
	    BEROctetString(self.matchedDN),
	    BEROctetString(self.errorMessage),
	    #TODO referral [3] Referral OPTIONAL
	    ], tag=self.tag))

    def __repr__(self):
	l=[]
	l.append('resultCode=%d' % self.resultCode)
	if self.matchedDN:
	    l.append('matchedDN=%s' % repr(str(self.matchedDN)))
	if self.errorMessage:
	    l.append('errorMessage=%s' % repr(str(self.errorMessage)))
	if self.referral:
	    l.append('referral=%d' % repr(self.referral))
	if self.tag!=self.__class__.tag:
	    l.append('tag=%d' % self.tag)
	return self.__class__.__name__+'('+', '.join(l)+')'

class LDAPBindResponse_serverSaslCreds(BERSequence):
    tag = CLASS_CONTEXT|0x03

    pass

class LDAPBERDecoderContext_BindResponse(BERDecoderContext):
    Identities = {
	LDAPBindResponse_serverSaslCreds.tag: LDAPBindResponse_serverSaslCreds,
	}

class LDAPBindResponse(LDAPResult):
    tag=CLASS_APPLICATION|0x01

    def decode(self, encoded, berdecoder):
	LDAPResult.decode(self, encoded, LDAPBERDecoderContext_BindResponse(fallback=berdecoder))
	try:
	    if isinstance(self.data[0], LDAPBindResponse_serverSaslCreds):
		self.serverSaslCreds=self.data[0]
		del self.data[0]
	    else:
		self.serverSaslCreds=None
	except IndexError:
	    self.serverSaslCreds=None

    def __init__(self, resultCode=None, matchedDN=None, errorMessage=None, referral=None, serverSaslCreds=None, encoded=None, berdecoder=None):
	assert serverSaslCreds is None #TODO
	LDAPResult.__init__(self, resultCode=resultCode, matchedDN=matchedDN, errorMessage=errorMessage, referral=referral, encoded=encoded, berdecoder=berdecoder)

    def __str__(self):
	assert self.serverSaslCreds is None #TODO
	return LDAPResult.__str__(self)

    def __repr__(self):
	assert self.serverSaslCreds is None #TODO
	return LDAPResult.__repr__(self)

class LDAPUnbindRequest(LDAPProtocolRequest, BERNull):
    tag=CLASS_APPLICATION|0x02
    needs_answer=0

    def __init__(self, *args, **kwargs):
	LDAPProtocolRequest.__init__(self)
        BERNull.__init__(self, *args, **kwargs)

    def __str__(self):
        return BERNull.__str__(self)

class LDAPAttributeDescription(BEROctetString):
    pass

class LDAPAttributeValueAssertion(BERSequence):
    def decode(self, encoded, berdecoder):
	BERSequence.decode(self, encoded, berdecoder)
	self.attributeDesc=self.data[0]
	self.assertionValue=self.data[1]
	assert len(self.data)==2

    def __init__(self, attributeDesc=None, assertionValue=None,
		 encoded=None, berdecoder=None):
	BERSequence.__init__(self, value=[])
	if attributeDesc is not None:
	    assert encoded is None
	    self.attributeDesc=attributeDesc
	    self.assertionValue=assertionValue
	elif encoded is not None:
	    assert attributeDesc is None
	    assert assertionValue is None
	    assert berdecoder
	    self.decode(encoded, berdecoder)
	else:
	    raise "You must give either value or encoded"

    def __str__(self):
	return str(BERSequence([self.attributeDesc,
				self.assertionValue],
			       tag=self.tag))

    def __repr__(self):
	if self.tag==self.__class__.tag:
	    return self.__class__.__name__+"(attributeDesc=%s, assertionValue=%s)"\
		   %(repr(self.attributeDesc), repr(self.assertionValue))
	else:
	    return self.__class__.__name__+"(attributeDesc=%s, assertionValue=%s, tag=%d)"\
		   %(repr(self.attributeDesc), repr(self.assertionValue), self.tag)


class LDAPFilter(BERStructured):
    def __init__(self, tag=None):
        BERStructured.__init__(self, tag=tag)

class LDAPFilterSet(BERSet):
    def decode(self, encoded, berdecoder):
	BERSet.decode(self, encoded, LDAPBERDecoderContext_Filter(fallback=berdecoder))

class LDAPFilter_and(LDAPFilterSet):
    tag = CLASS_CONTEXT|0x00

    def asText(self):
	return '(&'+''.join([x.asText() for x in self])+')'

class LDAPFilter_or(LDAPFilterSet):
    tag = CLASS_CONTEXT|0x01

    def asText(self):
	return '(|'+''.join([x.asText() for x in self])+')'

class LDAPFilter_not(LDAPFilter):
    tag = CLASS_CONTEXT|0x02

    def decode(self, encoded, berdecoder):
	e2=MutableString(encoded)
	need(e2, 2)
	self.tag=ber2int(e2[0], signed=0)&(CLASS_MASK|TAG_MASK)
	del e2[0]
	l=berlen2int(e2)
	assert l>=0
	need(e2, l)
	encoded.set(e2)

	self.value=ber2object(LDAPBERDecoderContext_Filter(fallback=berdecoder, inherit=berdecoder), encoded)
	assert self.value

    def __init__(self, value=None, encoded=None, berdecoder=None):
        LDAPFilter.__init__(self)
	if encoded is not None:
	    assert berdecoder
	    self.decode(encoded, berdecoder)
	elif value is not None:
	    self.value=value
	else:
	    raise "You must give either value or encoded"

    def __repr__(self):
	if self.tag==self.__class__.tag:
	    return self.__class__.__name__\
		   +"(value=%s)"\
		   %repr(self.value)
	else:
	    return self.__class__.__name__\
		   +"(value=%s, tag=%d)"\
		   %(repr(self.value), self.tag)

    def __str__(self):
	r=str(self.value)
	return chr(self.identification())+int2berlen(len(r))+r

    def asText(self):
	return '(!'+self.value.asText()+')'

class LDAPFilter_equalityMatch(LDAPAttributeValueAssertion):
    tag = CLASS_CONTEXT|0x03

    def asText(self):
	return '('+self.attributeDesc.value+'=' \
	       +escape(self.assertionValue.value)+')'

class LDAPFilter_substrings_initial(LDAPString):
    tag = CLASS_CONTEXT|0x00

    def asText(self):
	return escape(self.value)


class LDAPFilter_substrings_any(LDAPString):
    tag = CLASS_CONTEXT|0x01

    def asText(self):
	return escape(self.value)

class LDAPFilter_substrings_final(LDAPString):
    tag = CLASS_CONTEXT|0x02

    def asText(self):
	return escape(self.value)

class LDAPBERDecoderContext_Filter_substrings(BERDecoderContext):
    Identities = {
	LDAPFilter_substrings_initial.tag: LDAPFilter_substrings_initial,
	LDAPFilter_substrings_any.tag: LDAPFilter_substrings_any,
	LDAPFilter_substrings_final.tag: LDAPFilter_substrings_final,
	}

class LDAPFilter_substrings(BERSequence):
    tag = CLASS_CONTEXT|0x04

    def decode(self, encoded, berdecoder):
	BERSequence.decode(self, encoded, LDAPBERDecoderContext_Filter_substrings(fallback=berdecoder))
	assert len(self.data)==2
	self.type=self.data[0]
	assert len(self.data[1])>=1
	self.substrings=self.data[1]

    def __init__(self, type=None, substrings=None, encoded=None, berdecoder=None, tag=None):
	BERSequence.__init__(self, value=[], tag=tag)
	if type is not None and substrings is not None:
	    assert encoded is None
	    self.type=type
	    self.substrings=substrings
	elif encoded is not None:
	    assert berdecoder
	    self.decode(encoded, berdecoder)
	else:
	    raise "You must give either value or encoded"

    def __str__(self):
	return str(BERSequence([
	    LDAPString(self.type),
	    BERSequence(self.substrings)], tag=self.tag))

    def __repr__(self):
	if self.tag==self.__class__.tag:
	    return self.__class__.__name__\
		   +"(type=%s, substrings=%s)"\
		   %(repr(self.type), repr(self.substrings))
	else:
	    return self.__class__.__name__\
		   +"(type=%s, substrings=%s, tag=%d)"\
		   %(repr(self.type), repr(self.substrings), self.tag)

    def asText(self):
	initial=None
	final=None
	any=[]

	for s in self.substrings:
	    assert s is not None
	    if isinstance(s, LDAPFilter_substrings_initial):
		assert initial is None
		assert not any
		assert final is None
		initial=s.asText()
	    elif isinstance(s, LDAPFilter_substrings_final):
		assert final is None
		final=s.asText()
	    elif isinstance(s, LDAPFilter_substrings_any):
		assert final is None
		any.append(s.asText())
	    else:
		raise 'TODO'

	if initial is None:
	    initial=''
	if final is None:
	    final=''


	return '('+self.type+'=' \
	       +'*'.join([initial]+any+[final])+')'

class LDAPFilter_greaterOrEqual(LDAPAttributeValueAssertion):
    tag = CLASS_CONTEXT|0x05

    def asText(self):
	return '('+self.attributeDesc.value+'>=' \
	       +escape(self.assertionValue.value)+')'

class LDAPFilter_lessOrEqual(LDAPAttributeValueAssertion):
    tag = CLASS_CONTEXT|0x06

    def asText(self):
	return '('+self.attributeDesc.value+'<=' \
	       +escape(self.assertionValue.value)+')'

class LDAPFilter_present(LDAPAttributeDescription):
    tag = CLASS_CONTEXT|0x07

    def asText(self):
	return '(%s=*)' % self.value

class LDAPFilter_approxMatch(LDAPAttributeValueAssertion):
    tag = CLASS_CONTEXT|0x08


    def asText(self):
	return '('+self.attributeDesc.value+'~=' \
	       +escape(self.assertionValue.value)+')'

class LDAPMatchingRuleId(LDAPString):
    pass

class LDAPAssertionValue(BEROctetString):
    pass

class LDAPMatchingRuleAssertion_matchingRule(LDAPMatchingRuleId):
    tag = CLASS_CONTEXT|0x01
    pass

class LDAPMatchingRuleAssertion_type(LDAPAttributeDescription):
    tag = CLASS_CONTEXT|0x02
    pass

class LDAPMatchingRuleAssertion_matchValue(LDAPAssertionValue):
    tag = CLASS_CONTEXT|0x03
    pass

class LDAPMatchingRuleAssertion_dnAttributes(BERBoolean):
    tag = CLASS_CONTEXT|0x04
    pass

class LDAPBERDecoderContext_MatchingRuleAssertion(BERDecoderContext):
    Identities = {
	LDAPMatchingRuleAssertion_matchingRule.tag: LDAPMatchingRuleAssertion_matchingRule,
	LDAPMatchingRuleAssertion_type.tag: LDAPMatchingRuleAssertion_type,
	LDAPMatchingRuleAssertion_matchValue.tag: LDAPMatchingRuleAssertion_matchValue,
	LDAPMatchingRuleAssertion_dnAttributes.tag: LDAPMatchingRuleAssertion_dnAttributes,
	}

class LDAPMatchingRuleAssertion(BERSequence):
    def decode(self, encoded, berdecoder):
	BERSequence.decode(self, encoded, LDAPBERDecoderContext_MatchingRuleAssertion(fallback=berdecoder, inherit=berdecoder))
	assert 1<=len(self.data)<=4
	self.matchingRule=None
	self.type=None
	self.matchValue=None
	self.dnAttributes=None
	if isinstance(self.data[0], LDAPMatchingRuleAssertion_matchingRule):
	    self.matchingRule=self.data[0]
	    del self.data[0]
	if len(self.data)>1 \
	   and isinstance(self.data[0], LDAPMatchingRuleAssertion_type):
	    self.type=self.data[0]
	    del self.data[0]
	if len(self.data)>1 \
	   and isinstance(self.data[0], LDAPMatchingRuleAssertion_matchValue):
	    self.matchValue=self.data[0]
	    del self.data[0]
	if len(self.data)>1 \
	   and isinstance(self.data[0], LDAPMatchingRuleAssertion_dnAttributes):
	    self.dnAttributes=self.data[0]
	    del self.data[0]
	assert self.matchValue
	if not self.dnAttributes:
	    self.dnAttributes=None

    def __init__(self, matchingRule=None, type=None,
		 matchValue=None, dnAttributes=None,
		 encoded=None, berdecoder=None, tag=None):
	BERSequence.__init__(self, value=[], tag=tag)
	if matchValue is not None:
	    assert encoded is None
	    self.matchingRule=matchingRule
	    self.type=type
	    self.matchValue=matchValue
	    self.dnAttributes=dnAttributes
	    if not self.dnAttributes:
		self.dnAttributes=None
	elif encoded is not None:
	    assert matchingRule is None
	    assert type is None
	    assert matchValue is None
	    assert dnAttributes is None
	    assert berdecoder
	    self.decode(encoded, berdecoder)
	else:
	    raise "You must give either value or encoded"

    def __str__(self):
	return str(BERSequence(
	    filter(lambda x: x is not None, [self.matchingRule, self.type, self.matchValue, self.dnAttributes]), tag=self.tag))

    def __repr__(self):
	l=[]
	l.append('matchingRule=%s' % repr(self.matchingRule))
	l.append('type=%s' % repr(self.type))
	l.append('matchValue=%s' % repr(self.matchValue))
	l.append('dnAttributes=%s' % repr(self.dnAttributes))
	if self.tag!=self.__class__.tag:
	    l.append('tag=%d' % self.tag)
	return self.__class__.__name__+'('+', '.join(l)+')'

class LDAPFilter_extensibleMatch(LDAPMatchingRuleAssertion):
    tag = CLASS_CONTEXT|0x09
    pass


class LDAPBERDecoderContext_Filter(BERDecoderContext):
    Identities = {
	LDAPFilter_and.tag: LDAPFilter_and,
	LDAPFilter_or.tag: LDAPFilter_or,
	LDAPFilter_not.tag: LDAPFilter_not,
	LDAPFilter_equalityMatch.tag: LDAPFilter_equalityMatch,
	LDAPFilter_substrings.tag: LDAPFilter_substrings,
	LDAPFilter_greaterOrEqual.tag: LDAPFilter_greaterOrEqual,
	LDAPFilter_lessOrEqual.tag: LDAPFilter_lessOrEqual,
	LDAPFilter_present.tag: LDAPFilter_present,
	LDAPFilter_approxMatch.tag: LDAPFilter_approxMatch,
	LDAPFilter_extensibleMatch.tag: LDAPFilter_extensibleMatch,
	}

LDAP_SCOPE_baseObject=0
LDAP_SCOPE_singleLevel=1
LDAP_SCOPE_wholeSubtree=2

LDAP_DEREF_neverDerefAliases=0
LDAP_DEREF_derefInSearching=1
LDAP_DEREF_derefFindingBaseObj=2
LDAP_DEREF_derefAlways=3

LDAPFilterMatchAll = LDAPFilter_present('objectClass')

class LDAPSearchRequest(LDAPProtocolRequest, BERSequence):
    tag=CLASS_APPLICATION|0x03

    #TODO decode

    def decode(self, encoded, berdecoder):
	BERSequence.decode(self, encoded, LDAPBERDecoderContext_Filter(fallback=berdecoder, inherit=berdecoder))
	assert 8<=len(self.data)<=8
	self.baseObject=self.data[0].value
	self.scope=self.data[1].value
	self.derefAliases=self.data[2].value
	self.sizeLimit=self.data[3].value
	self.timeLimit=self.data[4].value
	self.typesOnly=self.data[5].value
	self.filter=self.data[6]
	self.attributes=self.data[7]
        del self.data[:]

    def __init__(self,
		 baseObject=None,
		 scope=None,
		 derefAliases=None,
		 sizeLimit=None,
		 timeLimit=None,
		 typesOnly=None,
		 filter=None,
		 attributes=None,
                 encoded=None,
                 berdecoder=None,
                 tag=None):
	LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)

        if encoded is None:
            if baseObject is None:
                baseObject=''
            self.baseObject=baseObject
            if scope is None:
                scope=LDAP_SCOPE_wholeSubtree
            self.scope=scope
            if derefAliases is None:
                derefAliases=LDAP_DEREF_neverDerefAliases
            self.derefAliases=derefAliases
            if sizeLimit is None:
                sizeLimit=0
            self.sizeLimit=sizeLimit
            if timeLimit is None:
                timeLimit=0
            self.timeLimit=timeLimit
            if typesOnly is None:
                typesOnly=0
            self.typesOnly=typesOnly
            if filter is None:
                filter=LDAPFilterMatchAll
            self.filter=filter
            if attributes is None:
                attributes=[] #TODO AttributeDescriptionList
            self.attributes=attributes

            assert berdecoder is None
            assert tag is None

        else:
            assert scope is None
            assert derefAliases is None
            assert sizeLimit is None
            assert timeLimit is None
            assert typesOnly is None
            assert filter is None
            assert attributes is None

            assert berdecoder is not None

            self.decode(encoded, berdecoder)

    def __str__(self):
	return str(BERSequence([
	    BEROctetString(self.baseObject),
	    BEREnumerated(self.scope),
	    BEREnumerated(self.derefAliases),
	    BERInteger(self.sizeLimit),
	    BERInteger(self.timeLimit),
	    BERBoolean(self.typesOnly),
	    self.filter,
	    BERSequenceOf(map(BEROctetString, self.attributes)),
	    ], tag=self.tag))

    def __repr__(self):
	if self.tag==self.__class__.tag:
	    return self.__class__.__name__\
		   +("(baseObject=%s, scope=%s, derefAliases=%s, " \
		     +"sizeLimit=%s, timeLimit=%s, typesOnly=%s, " \
		     "filter=%s, attributes=%s)") \
		     %(repr(self.baseObject), self.scope,
		       self.derefAliases, self.sizeLimit,
		       self.timeLimit, self.typesOnly,
		       repr(self.filter), self.attributes)

	else:
	    return self.__class__.__name__\
		   +("(baseObject=%s, scope=%s, derefAliases=%s, " \
		     +"sizeLimit=%s, timeLimit=%s, typesOnly=%s, " \
		     "filter=%s, attributes=%s, tag=%d)") \
		     %(repr(self.baseObject), self.scope,
		       self.derefAliases, self.sizeLimit,
		       self.timeLimit, self.typesOnly,
		       self.filter, self.attributes, self.tag)

class LDAPSearchResultEntry(LDAPProtocolResponse, BERSequence):
    tag=CLASS_APPLICATION|0x04

    def decode(self, encoded, berdecoder):
	BERSequence.decode(self, encoded, berdecoder)
	self.objectName=self.data[0].value
	self.attributes=[]
	for attr, li in self.data[1].data:
	    self.attributes.append((attr.value, map(lambda x: x.value, li)))

    def __init__(self, objectName=None, attributes=None, encoded=None, berdecoder=None):
	LDAPProtocolResponse.__init__(self)
	BERSequence.__init__(self, [])
	if objectName is not None and attributes is not None:
	    assert encoded is None
	    self.objectName=objectName
	    self.attributes=attributes
	elif encoded is not None:
	    assert objectName is None
	    assert attributes is None
	    assert berdecoder
	    self.decode(encoded, berdecoder)
	else:
	    raise "You must give either value or encoded"

    def __str__(self):
	return str(BERSequence([
	    BEROctetString(self.objectName),
	    BERSequence(map(lambda (attr,li):
			    BERSequence([BEROctetString(attr),
					 BERSet(map(BEROctetString,
						    li))]),
			    self.attributes)),
	    ], tag=self.tag))

    def __repr__(self):
	if self.tag==self.__class__.tag:
	    return self.__class__.__name__\
		   +"(objectName=%s, attributes=%s"\
		   %(repr(str(self.objectName)),
		     repr(map(lambda (a,l):
			      (str(a),
			       map(lambda i, l=l: str(i), l)),
			      self.attributes)))
	else:
	    return self.__class__.__name__\
		   +"(objectName=%s, attributes=%s, tag=%d"\
		   %(repr(str(self.objectName)),
		     repr(map(lambda (a,l):
			      (str(a),
			       map(lambda i, l=l: str(i), l)),
			      self.attributes)),
		     self.tag)


class LDAPSearchResultDone(LDAPResult):
    tag=CLASS_APPLICATION|0x05

    pass


class LDAPModification(BERSequence):
    op = None

    def decode(self, encoded, berdecoder):
	BERSequence.decode(self, encoded, berdecoder)
        assert len(self.data) == 2
	self.op=self.data[0].value
        assert len(list(self.data[1])) == 2
	self.type=self.data[1][0].value
	self.vals=map(lambda x: x.value, self.data[1][1])
        del self.data

    def __init__(self, attributeType=None, vals=None, op=None, encoded=None, berdecoder=None, tag=None):
	BERSequence.__init__(self, [], tag=tag)
	if encoded is not None:
	    assert attributeType is None
	    assert vals is None
	    assert op is None
	    assert berdecoder
	    self.decode(encoded, berdecoder)
	elif attributeType is not None:
            if vals is None:
                vals = []
	    self.type=attributeType
	    self.vals=vals
	    if op:
		self.op=op
	else:
	    raise "You must give either value or encoded"


    def __str__(self):
	assert self.op is not None
	return str(BERSequence([ BEREnumerated(self.op),
                                 BERSequence([ LDAPAttributeDescription(self.type),
                                               BERSet(map(LDAPString, self.vals)),
                                               ]),
                                 ]))


    def __repr__(self):
        l=[]
        l.append('attributeType=%r' % self.type)
        l.append('vals=%r' % self.vals)
        l.append('op=%d' % self.op)
	if self.tag!=self.__class__.tag:
            l.append('tag=%d' % self.tag)
        return self.__class__.__name__+'('+', '.join(l)+')'



class LDAPModification_add(LDAPModification):
    op = 0

class LDAPModification_delete(LDAPModification):
    op = 1

class LDAPModification_replace(LDAPModification):
    op = 2

class LDAPControls(BERSequence):
    tag = CLASS_CONTEXT|0x00

    def decode(self, encoded, berdecoder):
        BERSequence.decode(self,
                           encoded,
                           berdecoder=LDAPBERDecoderContext_LDAPControls(
            inherit=berdecoder))

class LDAPControl(BERSequence):
    def decode(self, encoded, berdecoder):
        BERSequence.decode(self, encoded, berdecoder)
        self.controlType = self.data[0].value
        if self.data[1:]:
            self.criticality = self.data[1].value
        else:
            self.criticality = None
        if self.data[2:]:
            self.controlValue = self.data[2].value
        else:
            self.controlValue = None
        # TODO is controlType, controlValue allowed without criticality?
        assert not self.data[3:]

    def __init__(self,
                 controlType=None, criticality=None, controlValue=None,
                 encoded=None, id=None, berdecoder=None):
	BERSequence.__init__(self, value=[], encoded=None)
	if controlType is not None:
	    assert encoded is None
	    self.controlType = controlType
            self.criticality = criticality
            self.controlValue = controlValue
	elif encoded is not None:
	    assert controlType is None
	    assert criticality is None
	    assert controlValue is None
	    assert berdecoder
	    self.decode(encoded, berdecoder)
	else:
	    raise "You must give either value or encoded"

    def __str__(self):
        self.data=[LDAPOID(self.controlType)]
        if self.criticality is not None:
            self.data.append(BERBoolean(self.criticality))
        if self.controlValue is not None:
            self.data.append(BEROctetString(self.controlValue))
	return BERSequence.__str__(self)

class LDAPBERDecoderContext_LDAPControls(BERDecoderContext):
    Identities = {
        LDAPControl.tag: LDAPControl,
        }

class LDAPBERDecoderContext_LDAPMessage(BERDecoderContext):
    Identities = {
	LDAPControls.tag: LDAPControls,
	}

class LDAPBERDecoderContext_TopLevel(BERDecoderContext):
    Identities = {
	BERSequence.tag: LDAPMessage,
        }

class LDAPModifyRequest(LDAPProtocolRequest, BERSequence):
    tag=CLASS_APPLICATION|0x06

    def decode(self, encoded, berdecoder):
	BERSequence.decode(self, encoded, berdecoder) #TODO use special decoder with LDAPModification_*.
        assert len(self.data) == 2
	self.object=self.data[0].value
        self.modification=self.data[1].data

    def __init__(self, object=None, modification=None, encoded=None, berdecoder=None, tag=None):
	"""
	Initialize the object

	Example usage::

		l=LDAPModifyRequest(object='cn=foo,dc=example,dc=com',
		    modification=[LDAPModification_add('attr1', ['value1', 'value2']),
				  LDAPModification_delete('attr2')])
        """

	LDAPProtocolRequest.__init__(self)
	BERSequence.__init__(self, [], tag=tag)
	if encoded is not None:
	    assert object is None
	    assert modification is None
	    assert berdecoder
	    self.decode(encoded, berdecoder)
	else:
	    self.object=object
	    self.modification=modification

    def __str__(self):
	l=[LDAPString(self.object)]
	if self.modification is not None:
	    l.append(BERSequence(self.modification))
	return str(BERSequence(l, tag=self.tag))

    def __repr__(self):
	if self.tag==self.__class__.tag:
	    return self.__class__.__name__+"(object=%s, modification=%s)"\
		   %(repr(self.object), repr(self.modification))
	else:
	    return self.__class__.__name__+"(object=%s, modification=%s, tag=%d)" \
		   %(repr(self.object), repr(self.modification), self.tag)


class LDAPModifyResponse(LDAPResult):
    tag = CLASS_APPLICATION|0x07

class LDAPAddRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION|0x08

    def decode(self, encoded, berdecoder):
	BERSequence.decode(self, encoded, berdecoder)
	self.entry=self.data[0].value
	self.attributes=self.data[1]

    def __init__(self, entry=None, attributes=None, encoded=None, berdecoder=None, tag=None):
	"""
	Initialize the object

	Example usage::

		l=LDAPAddRequest(entry='cn=foo,dc=example,dc=com',
			attributes=(LDAPAttributeDescription("attrFoo"),
			     BERSet(value=(
				 LDAPAttributeValue("value1"),
				 LDAPAttributeValue("value2"),
			     )),
			     LDAPAttributeDescription("attrBar"),
			     BERSet(value=(
				 LDAPAttributeValue("value1"),
				 LDAPAttributeValue("value2"),
			     )),
			     ))
"""

	LDAPProtocolRequest.__init__(self)
	BERSequence.__init__(self, [], tag=tag)
	if encoded is not None:
	    assert entry is None
	    assert attributes is None
	    assert berdecoder
	    self.decode(encoded, berdecoder)
	else:
	    self.entry=entry
	    self.attributes=attributes

    def __str__(self):
	return str(BERSequence([
	    LDAPString(self.entry),
	    BERSequence(map(BERSequence, self.attributes)),
	    ], tag=self.tag))

    def __repr__(self):
	if self.tag==self.__class__.tag:
	    return self.__class__.__name__+"(entry=%s, attributes=%s)"\
		   %(repr(self.entry), repr(self.attributes))
	else:
	    return self.__class__.__name__+"(entry=%s, attributes=%s, tag=%d)" \
		   %(repr(self.entry), repr(self.attributes), self.tag)



class LDAPAddResponse(LDAPResult):
    tag = CLASS_APPLICATION|0x09

class LDAPDelRequest(LDAPProtocolRequest, LDAPString):
    tag = CLASS_APPLICATION|0x0a

    def __init__(self, entry=None, encoded=None, berdecoder=None, tag=None):
	"""
	Initialize the object

	l=LDAPDelRequest(entry='cn=foo,dc=example,dc=com')
	"""

	LDAPProtocolRequest.__init__(self)
	LDAPString.__init__(self, value=entry, encoded=encoded, berdecoder=berdecoder, tag=tag)

    def __str__(self):
	return LDAPString.__str__(self)

    def __repr__(self):
	if self.tag==self.__class__.tag:
	    return self.__class__.__name__+"(entry=%s)" \
		   %repr(self.value)
	else:
	    return self.__class__.__name__ \
		   +"(entry=%s, tag=%d)" \
		   %(repr(self.value), self.tag)


class LDAPDelResponse(LDAPResult):
    tag = CLASS_APPLICATION|0x0b
    pass


class LDAPModifyDNResponse_newSuperior(LDAPString):
    tag = CLASS_CONTEXT|0x00

    pass

class LDAPBERDecoderContext_ModifyDNRequest(BERDecoderContext):
    Identities = {
	LDAPModifyDNResponse_newSuperior.tag: LDAPModifyDNResponse_newSuperior,
	}

class LDAPModifyDNRequest(LDAPProtocolRequest, BERSequence):
    tag=CLASS_APPLICATION|12

    def decode(self, encoded, berdecoder):
	BERSequence.decode(self, encoded, LDAPBERDecoderContext_ModifyDNRequest(fallback=berdecoder))
	self.entry=str(self.data[0].value)
	self.newrdn=str(self.data[1].value)
	self.deleteoldrdn=self.data[2].value
	try:
	    self.newSuperior=str(self.data[3].value)
	except IndexError:
	    self.newSuperior=None

    def __init__(self, entry=None, newrdn=None, deleteoldrdn=None, newSuperior=None,
		 encoded=None, berdecoder=None, tag=None):
	"""
	Initialize the object

	Example usage::

		l=LDAPModifyDNRequest(entry='cn=foo,dc=example,dc=com',
				      newrdn='someAttr=value',
				      deleteoldrdn=0)
	"""

	LDAPProtocolRequest.__init__(self)
	BERSequence.__init__(self, [], tag=tag)
	if encoded is not None:
	    assert entry is None
	    assert newrdn is None
	    assert deleteoldrdn is None
	    assert newSuperior is None
	    assert berdecoder
	    self.decode(encoded, berdecoder)
	else:
	    assert entry is not None
	    assert newrdn is not None
	    assert deleteoldrdn is not None
	    self.entry=entry
	    self.newrdn=newrdn
	    self.deleteoldrdn=deleteoldrdn
	    self.newSuperior=newSuperior

    def __str__(self):
	l=[
	    LDAPString(self.entry),
	    LDAPString(self.newrdn),
	    BERBoolean(self.deleteoldrdn),
	    ]
	if self.newSuperior is not None:
	    l.append(LDAPString(self.newSuperior, tag=CLASS_CONTEXT|0))
	return str(BERSequence(l, tag=self.tag))

    def __repr__(self):
	l = [
	    "entry=%s" % repr(self.entry),
	    "newrdn=%s" % repr(self.newrdn),
	    "deleteoldrdn=%s" % repr(self.deleteoldrdn),
	    ]
	if self.newSuperior is not None:
	    l.append("newSuperior=%s" % repr(self.newSuperior))
	if self.tag!=self.__class__.tag:
	    l.append("tag=%d" % self.tag)
	return self.__class__.__name__ + "(" + ', '.join(l) + ")"

class LDAPModifyDNResponse(LDAPResult):
    tag=CLASS_APPLICATION|13

#class LDAPCompareResponse(LDAPProtocolResponse):
#class LDAPCompareRequest(LDAPProtocolRequest):
#class LDAPAbandonRequest(LDAPProtocolRequest):
#    needs_answer=0


class LDAPOID(BEROctetString):
    pass

class LDAPResponseName(LDAPOID):
    tag = CLASS_CONTEXT|10

class LDAPResponse(BEROctetString):
    tag = CLASS_CONTEXT|11


class LDAPExtendedRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION|23

    def decode(self, encoded, berdecoder):
	BERSequence.decode(self, encoded, berdecoder)
	self.requestName = self.data[0].value
	del self.data[0]
	try:
	    self.requestValue=self.data[0]
	except IndexError:
	    self.requestValue=None

    def __init__(self, requestName=None, requestValue=None,
		 encoded=None, berdecoder=None, tag=None):
	LDAPProtocolRequest.__init__(self)
	BERSequence.__init__(self, [], tag=tag)
	if encoded is not None:
	    assert requestName is None
	    assert requestValue is None
	    assert berdecoder
	    self.decode(encoded, berdecoder)
	else:
	    assert requestName is not None
	    self.requestName=requestName
	    self.requestValue=requestValue

    def __str__(self):
	l=[self.requestName]
	if self.requestValue is not None:
	    l.append(self.requestValue)
	return str(BERSequence(l, tag=self.tag))

class LDAPPasswordModifyRequest_userIdentity(BEROctetString):
    tag=CLASS_CONTEXT|0
class LDAPPasswordModifyRequest_oldPasswd(BEROctetString):
    tag=CLASS_CONTEXT|1
class LDAPPasswordModifyRequest_newPasswd(BEROctetString):
    tag=CLASS_CONTEXT|2

class LDAPBERDecoderContext_LDAPPasswordModifyRequest(BERDecoderContext):
    Identities = {
	LDAPPasswordModifyRequest_userIdentity.tag:
	LDAPPasswordModifyRequest_userIdentity,

	LDAPPasswordModifyRequest_oldPasswd.tag:
	LDAPPasswordModifyRequest_oldPasswd,

	LDAPPasswordModifyRequest_newPasswd.tag:
	LDAPPasswordModifyRequest_newPasswd,
	}

class LDAPPasswordModifyRequest(LDAPExtendedRequest):
    oid = LDAPOID('1.3.6.1.4.1.4203.1.11.1', tag=CLASS_CONTEXT|0)
    def decode(self, encoded, berdecoder):
	LDAPExtendedRequest.decode(self, encoded, berdecoder)
	assert self.requestName == self.oid, \
	       '%s requestName was %s instead of %s' \
	       % (self.__class__.__name__, self.requestName, self.oid)
	#TODO genPasswd

    def __init__(self, userIdentity=None, oldPasswd=None, newPasswd=None,
		 encoded=None, berdecoder=None, tag=None):
	if encoded is not None:
	    assert userIdentity is None
	    assert oldPasswd is None
	    assert newPasswd is None
	    assert berdecoder
	    assert tag is None
	    LDAPExtendedRequest.__init__(self, encoded=encoded, berdecoder=berdecoder)
	else:
	    l=[]
	    if userIdentity is not None:
		l.append(LDAPPasswordModifyRequest_userIdentity(userIdentity))
	    if oldPasswd is not None:
		l.append(LDAPPasswordModifyRequest_oldPasswd(oldPasswd))
	    if newPasswd is not None:
		l.append(LDAPPasswordModifyRequest_newPasswd(newPasswd))
	    LDAPExtendedRequest.__init__(
		self,
		requestName=self.oid,
		requestValue=BEROctetString(str(BERSequence(l)),
					    tag=CLASS_CONTEXT|1),
		tag=tag)

    def __repr__(self):
	l=[]
	# TODO userIdentity, oldPasswd, newPasswd
	if self.tag!=self.__class__.tag:
	    l.append('tag=%d' % self.tag)
	return self.__class__.__name__+'('+', '.join(l)+')'

class LDAPBERDecoderContext_LDAPExtendedResponse(BERDecoderContext):
    Identities = {
	LDAPResponseName.tag: LDAPResponseName,
	LDAPResponse.tag: LDAPResponse,
	}

class LDAPExtendedResponse(LDAPResult):
    tag = CLASS_APPLICATION|0x18

    responseName = None
    response = None

    def decode(self, encoded, berdecoder):
	LDAPResult.decode(self, encoded, LDAPBERDecoderContext_LDAPExtendedResponse(fallback=berdecoder))

    def __init__(self, resultCode=None, matchedDN=None, errorMessage=None,
                 referral=None, serverSaslCreds=None,
                 responseName=None, response=None,
                 encoded=None, berdecoder=None):
        if encoded is not None:
            assert resultCode is None
            assert matchedDN is None
            assert errorMessage is None
            assert referral is None
            assert serverSaslCreds is None
            assert responseName is None
            assert response is None

            assert berdecoder is not None
            LDAPResult.__init__(self, encoded=encoded, berdecoder=berdecoder)
        else:
            assert berdecoder is None

            LDAPResult.__init__(self,
                                resultCode=resultCode,
                                matchedDN=matchedDN,
                                errorMessage=errorMessage,
                                referral=referral,
                                serverSaslCreds=serverSaslCreds)
            self.responseName=responseName
            self.response=response

    def __str__(self):
	assert self.referral is None #TODO
        l=[BEREnumerated(self.resultCode),
           BEROctetString(self.matchedDN),
           BEROctetString(self.errorMessage),
           #TODO referral [3] Referral OPTIONAL
           ]
        if self.responseName is not None:
            l.append(LDAPOID(self.responseName, tag=CLASS_CONTEXT|0x0a))
        if self.response is not None:
            l.append(BEROctetString(self.response, tag=CLASS_CONTEXT|0x0b))
	return str(BERSequence(l, tag=self.tag))

class LDAPBERDecoderContext(BERDecoderContext):
    Identities = {
	LDAPBindResponse.tag: LDAPBindResponse,
	LDAPBindRequest.tag: LDAPBindRequest,
        LDAPUnbindRequest.tag: LDAPUnbindRequest,
        LDAPSearchRequest.tag: LDAPSearchRequest,
	LDAPSearchResultEntry.tag: LDAPSearchResultEntry,
	LDAPSearchResultDone.tag: LDAPSearchResultDone,
	LDAPReferral.tag: LDAPReferral,
	LDAPModifyRequest.tag: LDAPModifyRequest,
	LDAPModifyResponse.tag: LDAPModifyResponse,
	LDAPAddRequest.tag: LDAPAddRequest,
	LDAPAddResponse.tag: LDAPAddResponse,
	LDAPDelRequest.tag: LDAPDelRequest,
	LDAPDelResponse.tag: LDAPDelResponse,
	LDAPExtendedResponse.tag: LDAPExtendedResponse,
	LDAPModifyDNRequest.tag: LDAPModifyDNRequest,
	LDAPModifyDNResponse.tag: LDAPModifyDNResponse,
    }
