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

"""LDAP protocol message conversion; no application logic here."""

import string

from pureber import (

    BERBoolean, BERDecoderContext, BEREnumerated, BERInteger, BERNull,
    BEROctetString, BERSequence, BERSequenceOf, BERSet, BERStructured,

    CLASS_APPLICATION, CLASS_CONTEXT,

    berDecodeMultiple, berDecodeObject, int2berlen,
    )

next_ldap_message_id = 1


def alloc_ldap_message_id():
    global next_ldap_message_id
    r = next_ldap_message_id
    next_ldap_message_id = next_ldap_message_id + 1
    return r


def escape(s):
    s = s.replace('\\', r'\5c')
    s = s.replace('*', r'\2a')
    s = s.replace('(', r'\28')
    s = s.replace(')', r'\29')
    s = s.replace('\0', r'\00')
    return s

def binary_escape(s):
    return ''.join('\\{0:02x}'.format(ord(c)) for c in s)

def smart_escape(s, threshold=0.30):
    binary_count = sum(c not in string.printable for c in s)
    if float(binary_count) / float(len(s)) > threshold:
        return binary_escape(s)

    return escape(s)

class LDAPInteger(BERInteger):
    pass


class LDAPString(BEROctetString):
    def __init__(self, *args, **kwargs):
        self.escaper = kwargs.pop('escaper', escape)
        super(LDAPString, self).__init__(*args, **kwargs)

class LDAPAttributeValue(BEROctetString):
    pass


class LDAPMessage(BERSequence):
    id = None
    value = None

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(content, berdecoder)

        id_ = l[0].value
        value = l[1]
        if l[2:]:
            controls = []
            for c in l[2]:
                controls.append((
                    c.controlType,
                    c.criticality,
                    c.controlValue,
                    ))
        else:
            controls = None
        assert not l[3:]

        r = klass(id=id_,
                  value=value,
                  controls=controls,
                  tag=tag)
        return r

    def __init__(self, value=None, controls=None, id=None, tag=None):
        BERSequence.__init__(self, value=[], tag=tag)
        assert value is not None
        self.id = id
        if self.id is None:
            self.id = alloc_ldap_message_id()
        self.value = value
        self.controls = controls

    def __str__(self):
        l = [BERInteger(self.id), self.value]
        if self.controls is not None:
            l.append(LDAPControls([LDAPControl(*a) for a in self.controls]))
        return str(BERSequence(l))

    def __repr__(self):
        l = []
        l.append('id=%r' % self.id)
        l.append('value=%r' % self.value)
        if self.tag != self.__class__.tag:
            l.append('tag=%d' % self.tag)
        return self.__class__.__name__ + '(' + ', '.join(l) + ')'


class LDAPProtocolOp:
    def __init__(self):
        pass

    def __str__(self):
        raise NotImplementedError()



class LDAPProtocolRequest(LDAPProtocolOp):
    needs_answer = 1
    pass


class LDAPProtocolResponse(LDAPProtocolOp):
    pass


class LDAPBERDecoderContext_LDAPBindRequest(BERDecoderContext):
    Identities = {
        CLASS_CONTEXT | 0x00: BEROctetString,
        CLASS_CONTEXT | 0x03: BERSequence,
    }


class LDAPBindRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 0x00

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(content,
                              LDAPBERDecoderContext_LDAPBindRequest(
                                  fallback=berdecoder))

        sasl = False
        auth = None
        if isinstance(l[2], BEROctetString):
            auth = l[2].value
        elif isinstance(l[2], BERSequence):
            auth = (l[2][0].value, l[2][1].value)
            sasl = True

        r = klass(version=l[0].value,
                  dn=l[1].value,
                  auth=auth,
                  tag=tag,
                  sasl=sasl)
        return r

    def __init__(self, version=None, dn=None, auth=None, tag=None, sasl=False):
        """Constructor for LDAP Bind Request

        For sasl=False, pass a string password for 'auth'
        For sasl=True, pass a tuple of (mechanism, credentials) for 'auth'"""

        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        self.version = version
        if self.version is None:
            self.version = 3
        self.dn = dn
        if self.dn is None:
            self.dn = ''
        self.auth = auth
        if self.auth is None:
            self.auth = ''
            assert (not sasl)
        self.sasl = sasl

    def __str__(self):
        if not self.sasl:
            auth_ber = BEROctetString(self.auth, tag=CLASS_CONTEXT | 0)
        else:
            auth_ber = BERSequence([BEROctetString(self.auth[0]), BEROctetString(self.auth[1])],
                                   tag=CLASS_CONTEXT | 3)
        return str(BERSequence([
            BERInteger(self.version),
            BEROctetString(self.dn),
            auth_ber,
            ], tag=self.tag))

    def __repr__(self):
        l = []
        l.append('version=%d' % self.version)
        l.append('dn=%s' % repr(self.dn))
        l.append('auth=%s' % repr(self.auth))
        if self.tag != self.__class__.tag:
            l.append('tag=%d' % self.tag)
        l.append('sasl=%s' % repr(self.sasl))
        return self.__class__.__name__ + '(' + ', '.join(l) + ')'


class LDAPReferral(BERSequence):
    tag = CLASS_CONTEXT | 0x03


# This is currently just a stub and implements no real functionality.
class LDAPSearchResultReference(LDAPProtocolResponse):
    tag = CLASS_APPLICATION | 0x13

    def __init__(self):
        LDAPProtocolResponse.__init__(self)

    @classmethod
    def fromBER(cls, tag, content, berdecoder=None):
        r = cls()
        return r

    def __str__(self):
        return object.__str__(self)

    def __repr__(self):
        return object.__repr__(self)


class LDAPResult(LDAPProtocolResponse, BERSequence):
    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(content, LDAPBERDecoderContext_LDAPBindRequest(
            fallback=berdecoder))

        assert 3 <= len(l) <= 4

        referral = None
        # if (l[3:] and isinstance(l[3], LDAPReferral)):
            # TODO support referrals
            # self.referral=self.data[0]

        r = klass(resultCode=l[0].value,
                  matchedDN=l[1].value,
                  errorMessage=l[2].value,
                  referral=referral,
                  tag=tag)
        return r

    def __init__(self, resultCode=None, matchedDN=None, errorMessage=None, referral=None, serverSaslCreds=None, tag=None):
        LDAPProtocolResponse.__init__(self)
        BERSequence.__init__(self, value=[], tag=tag)
        assert resultCode is not None
        self.resultCode = resultCode
        if matchedDN is None:
            matchedDN = ''
        self.matchedDN = matchedDN
        if errorMessage is None:
            errorMessage = ''
        self.errorMessage = errorMessage
        self.referral = referral
        self.serverSaslCreds = serverSaslCreds

    def __str__(self):
        assert self.referral is None  # TODO
        return str(BERSequence([
            BEREnumerated(self.resultCode),
            BEROctetString(self.matchedDN),
            BEROctetString(self.errorMessage),
            #TODO referral [3] Referral OPTIONAL
            ], tag=self.tag))

    def __repr__(self):
        l = []
        l.append('resultCode=%r' % self.resultCode)
        if self.matchedDN:
            l.append('matchedDN=%r' % str(self.matchedDN))
        if self.errorMessage:
            l.append('errorMessage=%r' % str(self.errorMessage))
        if self.referral:
            l.append('referral=%r' % self.referral)
        if self.tag != self.__class__.tag:
            l.append('tag=%d' % self.tag)
        return self.__class__.__name__ + '(' + ', '.join(l) + ')'


class LDAPBindResponse_serverSaslCreds(BEROctetString):
    tag = CLASS_CONTEXT | 0x07

    pass


class LDAPBERDecoderContext_BindResponse(BERDecoderContext):
    Identities = {
        LDAPBindResponse_serverSaslCreds.tag: LDAPBindResponse_serverSaslCreds,
        }


class LDAPBindResponse(LDAPResult):
    tag = CLASS_APPLICATION | 0x01

    resultCode = None
    matchedDN = None
    errorMessage = None
    referral = None
    serverSaslCreds = None

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(content, LDAPBERDecoderContext_BindResponse(
                fallback=berdecoder))

        assert 3 <= len(l) <= 4

        try:
            if isinstance(l[3], LDAPBindResponse_serverSaslCreds):
                serverSaslCreds = l[3]
            else:
                serverSaslCreds = None
        except IndexError:
            serverSaslCreds = None

        referral = None
        #if (l[3:] and isinstance(l[3], LDAPReferral)):
            #TODO support referrals
            #self.referral=self.data[0]

        r = klass(resultCode=l[0].value,
                  matchedDN=l[1].value,
                  errorMessage=l[2].value,
                  referral=referral,
                  serverSaslCreds=serverSaslCreds,
                  tag=tag)
        return r

    def __init__(self, resultCode=None, matchedDN=None, errorMessage=None, referral=None, serverSaslCreds=None, tag=None):
        LDAPResult.__init__(self, resultCode=resultCode, matchedDN=matchedDN, errorMessage=errorMessage,
                            referral=referral, serverSaslCreds=serverSaslCreds, tag=None)

    def __str__(self):
        return LDAPResult.__str__(self)

    def __repr__(self):
        return LDAPResult.__repr__(self)


class LDAPUnbindRequest(LDAPProtocolRequest, BERNull):
    tag = CLASS_APPLICATION | 0x02
    needs_answer = 0

    def __init__(self, *args, **kwargs):
        LDAPProtocolRequest.__init__(self)
        BERNull.__init__(self, *args, **kwargs)

    def __str__(self):
        return BERNull.__str__(self)


class LDAPAttributeDescription(BEROctetString):
    pass


class LDAPAttributeValueAssertion(BERSequence):
    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(content, berdecoder)
        assert len(l) == 2

        r = klass(attributeDesc=l[0],
                  assertionValue=l[1],
                  tag=tag)
        return r

    def __init__(self, attributeDesc=None, assertionValue=None, tag=None, escaper=escape):
        BERSequence.__init__(self, value=[], tag=tag)
        assert attributeDesc is not None
        self.attributeDesc = attributeDesc
        self.assertionValue = assertionValue
        self.escaper = escaper

    def __str__(self):
        return str(BERSequence([self.attributeDesc,
                                self.assertionValue],
                               tag=self.tag))

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(attributeDesc=%s, assertionValue=%s)" \
                   % (repr(self.attributeDesc), repr(self.assertionValue))
        else:
            return self.__class__.__name__ + "(attributeDesc=%s, assertionValue=%s, tag=%d)" \
                   % (repr(self.attributeDesc), repr(self.assertionValue), self.tag)


class LDAPFilter(BERStructured):
    def __init__(self, tag=None):
        BERStructured.__init__(self, tag=tag)

class LDAPFilterSet(BERSet):
    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(content, LDAPBERDecoderContext_Filter(fallback=berdecoder))
        r = klass(l, tag=tag)
        return r

    def __eq__(self, rhs):
        # Fast paths
        if self is rhs:
            return True
        elif len(self) != len(rhs):
            return False

        return sorted(self, key=str) == sorted(rhs, key=str)

class LDAPFilter_and(LDAPFilterSet):
    tag = CLASS_CONTEXT | 0x00

    def asText(self):
        return '(&' + ''.join([x.asText() for x in self]) + ')'


class LDAPFilter_or(LDAPFilterSet):
    tag = CLASS_CONTEXT | 0x01

    def asText(self):
        return '(|' + ''.join([x.asText() for x in self]) + ')'


class LDAPFilter_not(LDAPFilter):
    tag = CLASS_CONTEXT | 0x02

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        value, bytes = berDecodeObject(LDAPBERDecoderContext_Filter(fallback=berdecoder, inherit=berdecoder), content)
        assert bytes == len(content)

        r = klass(value=value,
                  tag=tag)
        return r

    def __init__(self, value, tag=tag):
        LDAPFilter.__init__(self, tag=tag)
        assert value is not None
        self.value = value

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ \
                   + "(value=%s)" \
                     % repr(self.value)
        else:
            return self.__class__.__name__ \
                   + "(value=%s, tag=%d)" \
                     % (repr(self.value), self.tag)

    def __str__(self):
        r = str(self.value)
        return chr(self.identification()) + int2berlen(len(r)) + r

    def asText(self):
        return '(!' + self.value.asText() + ')'


class LDAPFilter_equalityMatch(LDAPAttributeValueAssertion):
    tag = CLASS_CONTEXT | 0x03

    def asText(self):
        return '('+self.attributeDesc.value+'=' \
               +self.escaper(self.assertionValue.value)+')'

class LDAPFilter_substrings_initial(LDAPString):
    tag = CLASS_CONTEXT | 0x00

    def asText(self):
        return self.escaper(self.value)


class LDAPFilter_substrings_any(LDAPString):
    tag = CLASS_CONTEXT | 0x01

    def asText(self):
        return self.escaper(self.value)

class LDAPFilter_substrings_final(LDAPString):
    tag = CLASS_CONTEXT | 0x02

    def asText(self):
        return self.escaper(self.value)

class LDAPBERDecoderContext_Filter_substrings(BERDecoderContext):
    Identities = {
        LDAPFilter_substrings_initial.tag: LDAPFilter_substrings_initial,
        LDAPFilter_substrings_any.tag: LDAPFilter_substrings_any,
        LDAPFilter_substrings_final.tag: LDAPFilter_substrings_final,
        }

class LDAPFilter_substrings(BERSequence):
    tag = CLASS_CONTEXT | 0x04

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(content, LDAPBERDecoderContext_Filter_substrings(fallback=berdecoder))
        assert len(l) == 2
        assert len(l[1]) >= 1

        r = klass(type=l[0].value,
                  substrings=list(l[1]),
                  tag=tag)
        return r

    def __init__(self, type=None, substrings=None, tag=None):
        BERSequence.__init__(self, value=[], tag=tag)
        assert type is not None
        assert substrings is not None
        self.type = type
        self.substrings = substrings

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
        initial = None
        final = None
        any = []

        for s in self.substrings:
            assert s is not None
            if isinstance(s, LDAPFilter_substrings_initial):
                assert initial is None
                assert not any
                assert final is None
                initial = s.asText()
            elif isinstance(s, LDAPFilter_substrings_final):
                assert final is None
                final = s.asText()
            elif isinstance(s, LDAPFilter_substrings_any):
                assert final is None
                any.append(s.asText())
            else:
                raise NotImplementedError('TODO: Filter type not supported %r' % s)

        if initial is None:
            initial = ''
        if final is None:
            final = ''

        return '(' + self.type + '=' \
               + '*'.join([initial] + any + [final]) + ')'


class LDAPFilter_greaterOrEqual(LDAPAttributeValueAssertion):
    tag = CLASS_CONTEXT | 0x05

    def asText(self):
        return '(' + self.attributeDesc.value + '>=' + \
               self.escaper(self.assertionValue.value) + ')'

class LDAPFilter_lessOrEqual(LDAPAttributeValueAssertion):
    tag = CLASS_CONTEXT | 0x06

    def asText(self):
        return '(' + self.attributeDesc.value + '<=' + \
               self.escaper(self.assertionValue.value) + ')'

class LDAPFilter_present(LDAPAttributeDescription):
    tag = CLASS_CONTEXT | 0x07

    def asText(self):
        return '(%s=*)' % self.value


class LDAPFilter_approxMatch(LDAPAttributeValueAssertion):
    tag = CLASS_CONTEXT | 0x08

    def asText(self):
        return '(' + self.attributeDesc.value + '~=' + \
               self.escaper(self.assertionValue.value) + ')'


class LDAPMatchingRuleId(LDAPString):
    pass


class LDAPAssertionValue(BEROctetString):
    pass


class LDAPMatchingRuleAssertion_matchingRule(LDAPMatchingRuleId):
    tag = CLASS_CONTEXT | 0x01
    pass


class LDAPMatchingRuleAssertion_type(LDAPAttributeDescription):
    tag = CLASS_CONTEXT | 0x02
    pass


class LDAPMatchingRuleAssertion_matchValue(LDAPAssertionValue):
    tag = CLASS_CONTEXT | 0x03
    pass


class LDAPMatchingRuleAssertion_dnAttributes(BERBoolean):
    tag = CLASS_CONTEXT | 0x04
    pass


class LDAPBERDecoderContext_MatchingRuleAssertion(BERDecoderContext):
    Identities = {
        LDAPMatchingRuleAssertion_matchingRule.tag: LDAPMatchingRuleAssertion_matchingRule,
        LDAPMatchingRuleAssertion_type.tag: LDAPMatchingRuleAssertion_type,
        LDAPMatchingRuleAssertion_matchValue.tag: LDAPMatchingRuleAssertion_matchValue,
        LDAPMatchingRuleAssertion_dnAttributes.tag: LDAPMatchingRuleAssertion_dnAttributes,
        }


class LDAPMatchingRuleAssertion(BERSequence):
    matchingRule = None
    type = None
    matchValue = None
    dnAttributes = None

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        matchingRule = None
        atype = None
        matchValue = None
        dnAttributes = None
        l = berDecodeMultiple(content,
                              LDAPBERDecoderContext_MatchingRuleAssertion(fallback=berdecoder, inherit=berdecoder))
        assert 1 <= len(l) <= 4
        if isinstance(l[0], LDAPMatchingRuleAssertion_matchingRule):
            matchingRule = l[0]
            del l[0]
        if len(l) >= 1 and isinstance(l[0], LDAPMatchingRuleAssertion_type):
            atype = l[0]
            del l[0]
        if len(l) >= 1 and isinstance(l[0], LDAPMatchingRuleAssertion_matchValue):
            matchValue = l[0]
            del l[0]
        if len(l) >= 1 and isinstance(l[0], LDAPMatchingRuleAssertion_dnAttributes):
            dnAttributes = l[0]
            del l[0]
        assert matchValue
        if not dnAttributes:
            dnAttributes = None
        r = klass(
            matchingRule=matchingRule,
            type=atype,
            matchValue=matchValue,
            dnAttributes=dnAttributes,
            tag=tag)

        return r

    def __init__(self, matchingRule=None, type=None, matchValue=None, dnAttributes=None, tag=None):
        BERSequence.__init__(self, value=[], tag=tag)
        assert matchValue is not None
        if isinstance(matchingRule, basestring):
            matchingRule = LDAPMatchingRuleAssertion_matchingRule(matchingRule)

        if isinstance(type, basestring):
            type = LDAPMatchingRuleAssertion_type(type)

        if isinstance(matchValue, basestring):
            matchValue = LDAPMatchingRuleAssertion_matchValue(matchValue)

        if isinstance(dnAttributes, bool):
            dnAttributes = LDAPMatchingRuleAssertion_dnAttributes(dnAttributes)

        self.matchingRule = matchingRule
        self.type = type
        self.matchValue = matchValue
        self.dnAttributes = dnAttributes
        if not self.dnAttributes:
            self.dnAttributes = None

    def __str__(self):
        return str(BERSequence(
            filter(lambda x: x is not None,
                   [self.matchingRule, self.type, self.matchValue, self.dnAttributes]), tag=self.tag))

    def __repr__(self):
        l=[]
        l.append('matchingRule=%s' % repr(self.matchingRule))
        l.append('type=%s' % repr(self.type))
        l.append('matchValue=%s' % repr(self.matchValue))
        l.append('dnAttributes=%s' % repr(self.dnAttributes))
        if self.tag != self.__class__.tag:
            l.append('tag=%d' % self.tag)
        return self.__class__.__name__ + '(' + ', '.join(l) + ')'


class LDAPFilter_extensibleMatch(LDAPMatchingRuleAssertion):
    tag = CLASS_CONTEXT | 0x09
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

LDAP_SCOPE_baseObject = 0
LDAP_SCOPE_singleLevel = 1
LDAP_SCOPE_wholeSubtree = 2

LDAP_DEREF_neverDerefAliases = 0
LDAP_DEREF_derefInSearching = 1
LDAP_DEREF_derefFindingBaseObj = 2
LDAP_DEREF_derefAlways = 3

LDAPFilterMatchAll = LDAPFilter_present('objectClass')


class LDAPSearchRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 0x03

    baseObject = ''
    scope = LDAP_SCOPE_wholeSubtree
    derefAliases = LDAP_DEREF_neverDerefAliases
    sizeLimit = 0
    timeLimit = 0
    typesOnly = 0
    filter = LDAPFilterMatchAll
    attributes = []  # TODO AttributeDescriptionList

    # TODO decode

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(content, LDAPBERDecoderContext_Filter(fallback=berdecoder, inherit=berdecoder))

        assert 8 <= len(l) <= 8
        r = klass(baseObject=l[0].value,
                  scope=l[1].value,
                  derefAliases=l[2].value,
                  sizeLimit=l[3].value,
                  timeLimit=l[4].value,
                  typesOnly=l[5].value,
                  filter=l[6],
                  attributes=[x.value for x in l[7]],
                  tag=tag)
        return r

    def __init__(self,
                 baseObject=None,
                 scope=None,
                 derefAliases=None,
                 sizeLimit=None,
                 timeLimit=None,
                 typesOnly=None,
                 filter=None,
                 attributes=None,
                 tag=None):
        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)

        if baseObject is not None:
            self.baseObject = baseObject
        if scope is not None:
            self.scope = scope
        if derefAliases is not None:
            self.derefAliases = derefAliases
        if sizeLimit is not None:
            self.sizeLimit = sizeLimit
        if timeLimit is not None:
            self.timeLimit = timeLimit
        if typesOnly is not None:
            self.typesOnly = typesOnly
        if filter is not None:
            self.filter = filter
        if attributes is not None:
            self.attributes = attributes

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
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ \
                   + ("(baseObject=%s, scope=%s, derefAliases=%s, " \
                      + "sizeLimit=%s, timeLimit=%s, typesOnly=%s, " \
                        "filter=%s, attributes=%s)") \
                     % (repr(self.baseObject), self.scope,
                        self.derefAliases, self.sizeLimit,
                        self.timeLimit, self.typesOnly,
                        repr(self.filter), self.attributes)

        else:
            return self.__class__.__name__ \
                   + ("(baseObject=%s, scope=%s, derefAliases=%s, " \
                      + "sizeLimit=%s, timeLimit=%s, typesOnly=%s, " \
                        "filter=%s, attributes=%s, tag=%d)") \
                     % (repr(self.baseObject), self.scope,
                        self.derefAliases, self.sizeLimit,
                        self.timeLimit, self.typesOnly,
                        self.filter, self.attributes, self.tag)


class LDAPSearchResultEntry(LDAPProtocolResponse, BERSequence):
    tag = CLASS_APPLICATION | 0x04

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(content, LDAPBERDecoderContext_Filter(fallback=berdecoder, inherit=berdecoder))

        objectName = l[0].value
        attributes = []
        for attr, li in l[1].data:
            attributes.append((attr.value, map(lambda x: x.value, li)))
        r = klass(objectName=objectName,
                  attributes=attributes,
                  tag=tag)
        return r

    def __init__(self, objectName, attributes, tag=None):
        LDAPProtocolResponse.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        assert objectName is not None
        assert attributes is not None
        self.objectName = objectName
        self.attributes = attributes

    def __str__(self):
        return str(BERSequence([
            BEROctetString(self.objectName),
            BERSequence([
                BERSequence([
                    BEROctetString(attr_li[0]),
                    BERSet(list(map(BEROctetString, attr_li[1])))])
                for attr_li in self.attributes
                ]),
        ], tag=self.tag))

    def __repr__(self):
        if self.tag==self.__class__.tag:
            return self.__class__.__name__\
                   +"(objectName=%s, attributes=%s"\
                   %(repr(str(self.objectName)),
                     repr(map(lambda a, l:
                              (str(a),
                               map(lambda i, l=l: str(i), l)),
                              self.attributes)))
        else:
            return self.__class__.__name__\
                   +"(objectName=%s, attributes=%s, tag=%d"\
                   %(repr(str(self.objectName)),
                     repr(map(lambda a,l:
                              (str(a),
                               map(lambda i, l=l: str(i), l)),
                              self.attributes)),
                     self.tag)


class LDAPSearchResultDone(LDAPResult):
    tag = CLASS_APPLICATION | 0x05

    pass


class LDAPControls(BERSequence):
    tag = CLASS_CONTEXT | 0x00

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(content, LDAPBERDecoderContext_LDAPControls(
                inherit=berdecoder))

        r = klass(l, tag=tag)
        return r


class LDAPControl(BERSequence):
    criticality = None
    controlValue = None

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(content, berdecoder)

        assert 1<=len(l)<= 3

        kw = {}
        if len(l) == 2:
            if isinstance(l[1], BERBoolean):
              kw['criticality'] = l[1].value
            elif isinstance(l[1], BEROctetString):
              kw['controlValue'] = l[1].value
        elif len(l) == 3:
            kw['criticality'] = l[1].value
            kw['controlValue'] = l[2].value

        r = klass(controlType=l[0].value,
                  tag=tag,
                  **kw)
        return r

    def __init__(self,
                 controlType, criticality=None, controlValue=None,
                 id=None, tag=None):
        BERSequence.__init__(self, value=[], tag=tag)
        assert controlType is not None
        self.controlType = controlType
        self.criticality = criticality
        self.controlValue = controlValue

    def __str__(self):
        self.data = [LDAPOID(self.controlType)]
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
        LDAPSearchResultReference.tag: LDAPSearchResultReference,
        }

class LDAPBERDecoderContext_TopLevel(BERDecoderContext):
    Identities = {
        BERSequence.tag: LDAPMessage,
        }

class LDAPModifyRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 0x06
    object = None
    modification = None

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(content, berdecoder)

        assert len(l) == 2

        r = klass(object=l[0].value,
                  modification=l[1].data,
                  tag=tag)
        return r

    def __init__(self, object=None, modification=None, tag=None):
        """
        Initialize the object

        Example usage::

                l = LDAPModifyRequest(
                    object='cn=foo,dc=example,dc=com',
                    modification=[

                      BERSequence([
                        BEREnumerated(0),
                        BERSequence([
                          LDAPAttributeDescription('attr1'),
                          BERSet([
                            LDAPString('value1'),
                            LDAPString('value2'),
                            ]),
                          ]),
                        ]),

                      BERSequence([
                        BEREnumerated(1),
                        BERSequence([
                          LDAPAttributeDescription('attr2'),
                          ]),
                        ]),

                    ])

        But more likely you just want to say::

        	mod = delta.ModifyOp('cn=foo,dc=example,dc=com',
                    [delta.Add('attr1', ['value1', 'value2']),
                     delta.Delete('attr1', ['value1', 'value2'])])
        	l = mod.asLDAP()
        """

        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        self.object = object
        self.modification = modification

    def __str__(self):
        l = [LDAPString(self.object)]
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
    tag = CLASS_APPLICATION | 0x07


class LDAPAddRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 0x08

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(content, berdecoder)

        r = klass(entry=l[0].value,
                  attributes=l[1],
                  tag=tag)
        return r

    def __init__(self, entry=None, attributes=None, tag=None):
        """
        Initialize the object

        Example usage::

                l=LDAPAddRequest(entry='cn=foo,dc=example,dc=com',
                        attributes=[(LDAPAttributeDescription("attrFoo"),
                             BERSet(value=(
                                 LDAPAttributeValue("value1"),
                                 LDAPAttributeValue("value2"),
                             ))),
                             (LDAPAttributeDescription("attrBar"),
                             BERSet(value=(
                                 LDAPAttributeValue("value1"),
                                 LDAPAttributeValue("value2"),
                             ))),
                             ])
"""

        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        self.entry = entry
        self.attributes = attributes

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
    tag = CLASS_APPLICATION | 0x09


class LDAPDelRequest(LDAPProtocolRequest, LDAPString):
    tag = CLASS_APPLICATION | 0x0a

    def __init__(self, value=None, entry=None, tag=None):
        """
        Initialize the object

        l=LDAPDelRequest(entry='cn=foo,dc=example,dc=com')
        """
        if entry is None and value is not None:
            entry = value
        LDAPProtocolRequest.__init__(self)
        LDAPString.__init__(self, value=entry, tag=tag)

    def __str__(self):
        return LDAPString.__str__(self)

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(entry=%s)" \
                   % repr(self.value)
        else:
            return self.__class__.__name__ \
                   + "(entry=%s, tag=%d)" \
                     % (repr(self.value), self.tag)


class LDAPDelResponse(LDAPResult):
    tag = CLASS_APPLICATION | 0x0b
    pass


class LDAPModifyDNResponse_newSuperior(LDAPString):
    tag = CLASS_CONTEXT | 0x00

    pass


class LDAPBERDecoderContext_ModifyDNRequest(BERDecoderContext):
    Identities = {
        LDAPModifyDNResponse_newSuperior.tag: LDAPModifyDNResponse_newSuperior,
        }

class LDAPModifyDNRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 12

    entry = None
    newrdn = None
    deleteoldrdn = None
    newSuperior = None

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(content, LDAPBERDecoderContext_ModifyDNRequest(fallback=berdecoder))

        kw = {}
        try:
            kw['newSuperior'] = str(l[3].value)
        except IndexError:
            pass

        r = klass(entry=str(l[0].value),
                  newrdn=str(l[1].value),
                  deleteoldrdn=l[2].value,
                  tag=tag,
                  **kw)
        return r

    def __init__(self, entry, newrdn, deleteoldrdn, newSuperior=None,
                 tag=None):
        """
        Initialize the object

        Example usage::

                l=LDAPModifyDNRequest(entry='cn=foo,dc=example,dc=com',
                                      newrdn='someAttr=value',
                                      deleteoldrdn=0)
        """

        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        assert entry is not None
        assert newrdn is not None
        assert deleteoldrdn is not None
        self.entry = entry
        self.newrdn = newrdn
        self.deleteoldrdn = deleteoldrdn
        self.newSuperior = newSuperior

    def __str__(self):
        l = [
            LDAPString(self.entry),
            LDAPString(self.newrdn),
            BERBoolean(self.deleteoldrdn),
            ]
        if self.newSuperior is not None:
            l.append(LDAPString(self.newSuperior, tag=CLASS_CONTEXT | 0))
        return str(BERSequence(l, tag=self.tag))

    def __repr__(self):
        l = [
            "entry=%s" % repr(self.entry),
            "newrdn=%s" % repr(self.newrdn),
            "deleteoldrdn=%s" % repr(self.deleteoldrdn),
            ]
        if self.newSuperior is not None:
            l.append("newSuperior=%s" % repr(self.newSuperior))
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        return self.__class__.__name__ + "(" + ', '.join(l) + ")"


class LDAPModifyDNResponse(LDAPResult):
    tag = CLASS_APPLICATION | 13


class LDAPBERDecoderContext_Compare(BERDecoderContext):
    Identities = {
        BERSequence.tag: LDAPAttributeValueAssertion
    }


class LDAPCompareRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 14

    entry = None
    ava = None

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(
                content,
                LDAPBERDecoderContext_Compare(
                    fallback=berdecoder,
                    inherit=berdecoder
                    )
                )

        r = klass(entry=l[0].value,
                  ava=l[1],
                  tag=tag)

        return r

    def __init__(self, entry, ava, tag=None):
        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        assert entry is not None
        assert ava is not None
        self.entry = entry
        self.ava = ava

    def __str__(self):
        l = [LDAPString(self.entry), self.ava]
        return str(BERSequence(l, tag=self.tag))

    def __repr__(self):
        l = ["entry={}".format(self.entry), "ava={}".format(repr(self.ava))]
        return "{}({})".format(self.__class__.__name__, ', '.join(l))


class LDAPCompareResponse(LDAPResult):
    tag = CLASS_APPLICATION | 15


class LDAPAbandonRequest(LDAPProtocolRequest, LDAPInteger):
    tag = CLASS_APPLICATION | 0x10
    needs_answer = 0

    def __init__(self, value=None, id=None, tag=None):
        """
        Initialize the object

        l=LDAPAbandonRequest(id=1)
        """
        if id is None and value is not None:
            id = value
        LDAPProtocolRequest.__init__(self)
        LDAPInteger.__init__(self, value=id, tag=tag)

    def __str__(self):
        return LDAPInteger.__str__(self)

    def __repr__(self):
        if self.tag==self.__class__.tag:
            return self.__class__.__name__+"(id=%s)" \
                   %repr(self.value)
        else:
            return self.__class__.__name__ \
                   + "(id=%s, tag=%d)" \
                     % (repr(self.value), self.tag)


class LDAPOID(BEROctetString):
    pass


class LDAPResponseName(LDAPOID):
    tag = CLASS_CONTEXT | 10


class LDAPResponse(BEROctetString):
    tag = CLASS_CONTEXT | 11


class LDAPBERDecoderContext_LDAPExtendedRequest(BERDecoderContext):
    Identities = {
        CLASS_CONTEXT | 0x00: BEROctetString,
        CLASS_CONTEXT | 0x01: BEROctetString,
        }


class LDAPExtendedRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 23

    requestName = None
    requestValue = None

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(content,
                              LDAPBERDecoderContext_LDAPExtendedRequest(
                                  fallback=berdecoder))

        kw = {}
        try:
            kw['requestValue'] = l[1].value
        except IndexError:
            pass

        r = klass(requestName=l[0].value,
                  tag=tag,
                  **kw)
        return r

    def __init__(self, requestName=None, requestValue=None,
                 tag=None):
        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        assert requestName is not None
        assert isinstance(requestName, basestring)
        assert requestValue is None or isinstance(requestValue, basestring)
        self.requestName = requestName
        self.requestValue = requestValue

    def __str__(self):
        l = [LDAPOID(self.requestName, tag=CLASS_CONTEXT | 0)]
        if self.requestValue is not None:
            l.append(BEROctetString(str(self.requestValue), tag=CLASS_CONTEXT | 1))
        return str(BERSequence(l, tag=self.tag))


class LDAPPasswordModifyRequest_userIdentity(BEROctetString):
    tag = CLASS_CONTEXT | 0


class LDAPPasswordModifyRequest_oldPasswd(BEROctetString):
    tag = CLASS_CONTEXT | 1


class LDAPPasswordModifyRequest_newPasswd(BEROctetString):
    tag = CLASS_CONTEXT | 2


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
    oid = '1.3.6.1.4.1.4203.1.11.1'

    def __init__(self, requestName=None,
                 userIdentity=None, oldPasswd=None, newPasswd=None,
                 tag=None):
        assert (requestName is None
                or requestName == self.oid), \
                '%s requestName was %s instead of %s' \
                % (self.__class__.__name__, requestName, self.oid)
        #TODO genPasswd

        l = []
        if userIdentity is not None:
            l.append(LDAPPasswordModifyRequest_userIdentity(userIdentity))
        if oldPasswd is not None:
            l.append(LDAPPasswordModifyRequest_oldPasswd(oldPasswd))
        if newPasswd is not None:
            l.append(LDAPPasswordModifyRequest_newPasswd(newPasswd))
        LDAPExtendedRequest.__init__(
            self,
            requestName=self.oid,
            requestValue=str(BERSequence(l)),
            tag=tag)

    def __repr__(self):
        l = []
        # TODO userIdentity, oldPasswd, newPasswd
        if self.tag != self.__class__.tag:
            l.append('tag=%d' % self.tag)
        return self.__class__.__name__ + '(' + ', '.join(l) + ')'


class LDAPBERDecoderContext_LDAPExtendedResponse(BERDecoderContext):
    Identities = {
        LDAPResponseName.tag: LDAPResponseName,
        LDAPResponse.tag: LDAPResponse,
        }

class LDAPExtendedResponse(LDAPResult):
    tag = CLASS_APPLICATION | 0x18

    responseName = None
    response = None

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(content, LDAPBERDecoderContext_LDAPExtendedResponse(
            fallback=berdecoder))

        assert 3 <= len(l) <= 6

        referral = None
        responseName = None
        response = None
        for obj in l[3:]:
            if isinstance(obj, LDAPResponseName):
                responseName = obj.value
            elif isinstance(obj, LDAPResponse):
                response = obj.value
            elif isinstance(obj, LDAPReferral):
                #TODO support referrals
                #self.referral=self.data[0]
                pass
            else:
                assert False

        r = klass(resultCode=l[0].value,
                  matchedDN=l[1].value,
                  errorMessage=l[2].value,
                  referral=referral,
                  responseName=responseName,
                  response=response,
                  tag=tag)
        return r

    def __init__(self, resultCode=None, matchedDN=None, errorMessage=None,
                 referral=None, serverSaslCreds=None,
                 responseName=None, response=None,
                 tag=None):
        LDAPResult.__init__(self,
                            resultCode=resultCode,
                            matchedDN=matchedDN,
                            errorMessage=errorMessage,
                            referral=referral,
                            serverSaslCreds=serverSaslCreds)
        self.responseName = responseName
        self.response = response

    def __str__(self):
        assert self.referral is None  # TODO
        l = [BEREnumerated(self.resultCode),
             BEROctetString(self.matchedDN),
             BEROctetString(self.errorMessage),
             # TODO referral [3] Referral OPTIONAL
             ]
        if self.responseName is not None:
            l.append(LDAPOID(self.responseName, tag=CLASS_CONTEXT | 0x0a))
        if self.response is not None:
            l.append(BEROctetString(self.response, tag=CLASS_CONTEXT | 0x0b))
        return str(BERSequence(l, tag=self.tag))


class LDAPStartTLSRequest(LDAPExtendedRequest):
    """
    Request to start Transport Layer Security.
    See RFC 2830 for details.
    """
    oid = '1.3.6.1.4.1.1466.20037'

    def __init__(self, requestName=None, tag=None):
        assert (requestName is None
                or requestName == self.oid), \
            '%s requestName was %s instead of %s' \
            % (self.__class__.__name__, requestName, self.oid)

        LDAPExtendedRequest.__init__(
            self,
            requestName=self.oid,
            tag=tag)

    def __repr__(self):
        l = []
        if self.tag != self.__class__.tag:
            l.append('tag={0}'.format(self.tag))
        return self.__class__.__name__ + '(' + ', '.join(l) + ')'


class LDAPStartTLSResponse(LDAPExtendedResponse):
    """
    Response to start Transport Layer Security.
    See RFC 4511 section 4.14.2 for details.
    """
    oid = '1.3.6.1.4.1.1466.20037'

    def __init__(self, resultCode=None, matchedDN=None, errorMessage=None,
                 referral=None, serverSaslCreds=None,
                 responseName=None, response=None,
                 tag=None):
        LDAPExtendedResponse.__init__(self, 
            resultCode=resultCode, 
            matchedDN=matchedDN, 
            errorMessage=errorMessage,
            referral=referral, 
            serverSaslCreds=serverSaslCreds,
            responseName=responseName, 
            response=response,
            tag=tag)

    def __repr__(self):
        l = []
        if self.tag != self.__class__.tag:
            l.append('tag={0}'.format(self.tag))
        return self.__class__.__name__ + '(' + ', '.join(l) + ')'


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
        LDAPExtendedRequest.tag: LDAPExtendedRequest,
        LDAPExtendedResponse.tag: LDAPExtendedResponse,
        LDAPModifyDNRequest.tag: LDAPModifyDNRequest,
        LDAPModifyDNResponse.tag: LDAPModifyDNResponse,
        LDAPAbandonRequest.tag: LDAPAbandonRequest,
        LDAPCompareRequest.tag: LDAPCompareRequest,
        LDAPCompareResponse.tag: LDAPCompareResponse
    }
