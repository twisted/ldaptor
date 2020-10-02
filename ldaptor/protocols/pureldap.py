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


from ldaptor.protocols.pureber import (
    BERBoolean,
    BERDecoderContext,
    BEREnumerated,
    BERInteger,
    BERNull,
    BEROctetString,
    BERSequence,
    BERSequenceOf,
    BERSet,
    BERStructured,
    CLASS_APPLICATION,
    CLASS_CONTEXT,
    berDecodeMultiple,
    berDecodeObject,
    int2berlen,
)
from ldaptor._encoder import to_bytes

next_ldap_message_id = 1


def alloc_ldap_message_id():
    global next_ldap_message_id
    r = next_ldap_message_id
    next_ldap_message_id = next_ldap_message_id + 1
    return r


def escape(s):
    s = s.replace("\\", r"\5c")
    s = s.replace("*", r"\2a")
    s = s.replace("(", r"\28")
    s = s.replace(")", r"\29")
    s = s.replace("\0", r"\00")
    return s


def binary_escape(s):
    return "".join("\\{:02x}".format(ord(c)) for c in s)


def smart_escape(s, threshold=0.30):
    binary_count = sum(c not in string.printable for c in s)
    if float(binary_count) / float(len(s)) > threshold:
        return binary_escape(s)

    return escape(s)


class LDAPInteger(BERInteger):
    pass


class LDAPString(BEROctetString):
    def __init__(self, *args, **kwargs):
        self.escaper = kwargs.pop("escaper", escape)
        super().__init__(*args, **kwargs)


class LDAPAttributeValue(BEROctetString):
    pass


class LDAPMessage(BERSequence):
    """
    To encode this object in order to be sent over the network use the toWire()
    method.
    """

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
                controls.append(
                    (
                        c.controlType,
                        c.criticality,
                        c.controlValue,
                    )
                )
        else:
            controls = None
        assert not l[3:]

        r = klass(id=id_, value=value, controls=controls, tag=tag)
        return r

    def __init__(self, value=None, controls=None, id=None, tag=None):
        BERSequence.__init__(self, value=[], tag=tag)
        assert value is not None
        self.id = id
        if self.id is None:
            self.id = alloc_ldap_message_id()
        self.value = value
        self.controls = controls

    def toWire(self):
        """
        This is the wire/encoded representation.
        """
        l = [BERInteger(self.id), self.value]
        if self.controls is not None:
            l.append(LDAPControls([LDAPControl(*a) for a in self.controls]))
        return BERSequence(l).toWire()

    def __repr__(self):
        l = []
        l.append("id=%r" % self.id)
        l.append("value=%r" % self.value)
        l.append("controls=%r" % self.controls)
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPProtocolOp:
    def __init__(self):
        pass

    def toWire(self):
        raise NotImplementedError()


class LDAPProtocolRequest(LDAPProtocolOp):
    needs_answer = 1


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
        l = berDecodeMultiple(
            content, LDAPBERDecoderContext_LDAPBindRequest(fallback=berdecoder)
        )

        sasl = False
        auth = None
        if isinstance(l[2], BEROctetString):
            auth = l[2].value
        elif isinstance(l[2], BERSequence):
            # per https://ldap.com/ldapv3-wire-protocol-reference-bind/
            # Credentials are optional and not always provided
            if len(l[2].data) == 2:
                auth = (l[2][0].value, l[2][1].value)
            else:
                auth = (l[2][0].value, None)
            sasl = True

        r = klass(version=l[0].value, dn=l[1].value, auth=auth, tag=tag, sasl=sasl)
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
            self.dn = ""
        self.auth = auth
        if self.auth is None:
            self.auth = ""
            assert not sasl
        self.sasl = sasl

    def toWire(self):
        if not self.sasl:
            auth_ber = BEROctetString(self.auth, tag=CLASS_CONTEXT | 0)
        else:
            # since the credentails for SASL is optional must check first
            # if credentials are None don't send them.
            if self.auth[1]:
                auth_ber = BERSequence(
                    [BEROctetString(self.auth[0]), BEROctetString(self.auth[1])],
                    tag=CLASS_CONTEXT | 3,
                )
            else:
                auth_ber = BERSequence(
                    [BEROctetString(self.auth[0])], tag=CLASS_CONTEXT | 3
                )
        return BERSequence(
            [
                BERInteger(self.version),
                BEROctetString(self.dn),
                auth_ber,
            ],
            tag=self.tag,
        ).toWire()

    def __repr__(self):
        auth = "*" * len(self.auth)
        l = []
        l.append("version=%d" % self.version)
        l.append("dn=%s" % repr(self.dn))
        l.append("auth=%s" % repr(auth))
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        l.append("sasl=%s" % repr(self.sasl))
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPReferral(BERSequence):
    tag = CLASS_CONTEXT | 0x03


class LDAPBERDecoderContext_LDAPSearchResultReference(BERDecoderContext):
    Identities = {
        BEROctetString.tag: LDAPString,
    }


class LDAPSearchResultReference(LDAPProtocolResponse, BERSequence):
    tag = CLASS_APPLICATION | 0x13

    def __init__(self, uris=None, tag=None):
        LDAPProtocolResponse.__init__(self)
        BERSequence.__init__(self, value=[], tag=tag)
        assert uris is not None
        self.uris = uris

    @classmethod
    def fromBER(cls, tag, content, berdecoder=None):
        l = berDecodeMultiple(
            content,
            LDAPBERDecoderContext_LDAPSearchResultReference(fallback=berdecoder),
        )
        r = cls(uris=l)
        return r

    def toWire(self):
        return BERSequence(BERSequence(self.uris), tag=self.tag).toWire()

    def __repr__(self):
        return "{}(uris={}{})".format(
            self.__class__.__name__,
            repr([uri for uri in self.uris]),
            ", tag={}".format(self.tag) if self.tag != self.__class__.tag else "",
        )


class LDAPResult(LDAPProtocolResponse, BERSequence):
    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(
            content, LDAPBERDecoderContext_LDAPBindRequest(fallback=berdecoder)
        )

        assert 3 <= len(l) <= 4

        referral = None
        # if (l[3:] and isinstance(l[3], LDAPReferral)):
        # TODO support referrals
        # self.referral=self.data[0]

        r = klass(
            resultCode=l[0].value,
            matchedDN=l[1].value,
            errorMessage=l[2].value,
            referral=referral,
            tag=tag,
        )
        return r

    def __init__(
        self,
        resultCode=None,
        matchedDN=None,
        errorMessage=None,
        referral=None,
        serverSaslCreds=None,
        tag=None,
    ):
        LDAPProtocolResponse.__init__(self)
        BERSequence.__init__(self, value=[], tag=tag)
        assert resultCode is not None
        self.resultCode = resultCode
        if matchedDN is None:
            matchedDN = ""
        self.matchedDN = matchedDN
        if errorMessage is None:
            errorMessage = ""
        self.errorMessage = errorMessage
        self.referral = referral
        self.serverSaslCreds = serverSaslCreds

    def toWire(self):
        assert self.referral is None  # TODO
        if self.serverSaslCreds:
            return BERSequence(
                [
                    BEREnumerated(self.resultCode),
                    BEROctetString(self.matchedDN),
                    BEROctetString(self.errorMessage),
                    LDAPBindResponse_serverSaslCreds(self.serverSaslCreds),
                ],
                tag=self.tag,
            ).toWire()
        else:
            return BERSequence(
                [
                    BEREnumerated(self.resultCode),
                    BEROctetString(self.matchedDN),
                    BEROctetString(self.errorMessage),
                ],
                tag=self.tag,
            ).toWire()

    def __repr__(self):
        l = []
        l.append("resultCode=%r" % self.resultCode)
        if self.matchedDN:
            l.append("matchedDN=%r" % self.matchedDN)
        if self.errorMessage:
            l.append("errorMessage=%r" % self.errorMessage)
        if self.referral:
            l.append("referral=%r" % self.referral)
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPBindResponse_serverSaslCreds(BEROctetString):
    tag = CLASS_CONTEXT | 0x07

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%s)" % self.value
        else:
            return self.__class__.__name__ + "(value=%s, tag=%d)" % (
                self.value,
                self.tag,
            )


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
        l = berDecodeMultiple(
            content, LDAPBERDecoderContext_BindResponse(fallback=berdecoder)
        )

        assert 3 <= len(l) <= 4

        try:
            if isinstance(l[3], LDAPBindResponse_serverSaslCreds):
                serverSaslCreds = l[3].value
            else:
                serverSaslCreds = None
        except IndexError:
            serverSaslCreds = None

        referral = None
        # if (l[3:] and isinstance(l[3], LDAPReferral)):
        # TODO support referrals
        # self.referral=self.data[0]

        r = klass(
            resultCode=l[0].value,
            matchedDN=l[1].value,
            errorMessage=l[2].value,
            referral=referral,
            serverSaslCreds=serverSaslCreds,
            tag=tag,
        )
        return r

    def __init__(
        self,
        resultCode=None,
        matchedDN=None,
        errorMessage=None,
        referral=None,
        serverSaslCreds=None,
        tag=None,
    ):
        LDAPResult.__init__(
            self,
            resultCode=resultCode,
            matchedDN=matchedDN,
            errorMessage=errorMessage,
            referral=referral,
            serverSaslCreds=serverSaslCreds,
            tag=None,
        )

    def __repr__(self):
        return LDAPResult.__repr__(self)


class LDAPUnbindRequest(LDAPProtocolRequest, BERNull):
    tag = CLASS_APPLICATION | 0x02
    needs_answer = 0

    def __init__(self, *args, **kwargs):
        LDAPProtocolRequest.__init__(self)
        BERNull.__init__(self, *args, **kwargs)

    def toWire(self):
        return BERNull.toWire(self)


class LDAPAttributeDescription(BEROctetString):
    pass


class LDAPAttributeValueAssertion(BERSequence):
    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(content, berdecoder)
        assert len(l) == 2

        r = klass(attributeDesc=l[0], assertionValue=l[1], tag=tag)
        return r

    def __init__(
        self, attributeDesc=None, assertionValue=None, tag=None, escaper=escape
    ):
        BERSequence.__init__(self, value=[], tag=tag)
        assert attributeDesc is not None
        self.attributeDesc = attributeDesc
        self.assertionValue = assertionValue
        self.escaper = escaper

    def toWire(self):
        return BERSequence(
            [self.attributeDesc, self.assertionValue], tag=self.tag
        ).toWire()

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return (
                self.__class__.__name__
                + "(attributeDesc={}, assertionValue={})".format(
                    repr(self.attributeDesc),
                    repr(self.assertionValue),
                )
            )
        else:
            return (
                self.__class__.__name__
                + "(attributeDesc=%s, assertionValue=%s, tag=%d)"
                % (repr(self.attributeDesc), repr(self.assertionValue), self.tag)
            )


class LDAPFilter(BERStructured):
    def __init__(self, tag=None):
        BERStructured.__init__(self, tag=tag)


class LDAPFilterSet(BERSet):
    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(
            content, LDAPBERDecoderContext_Filter(fallback=berdecoder)
        )
        r = klass(l, tag=tag)
        return r

    def __eq__(self, rhs):
        # Fast paths
        if self is rhs:
            return True
        elif len(self) != len(rhs):
            return False

        return sorted(self, key=lambda x: x.toWire()) == sorted(
            rhs, key=lambda x: x.toWire()
        )


class LDAPFilter_and(LDAPFilterSet):
    tag = CLASS_CONTEXT | 0x00

    def asText(self):
        return "(&" + "".join([x.asText() for x in self]) + ")"


class LDAPFilter_or(LDAPFilterSet):
    tag = CLASS_CONTEXT | 0x01

    def asText(self):
        return "(|" + "".join([x.asText() for x in self]) + ")"


class LDAPFilter_not(LDAPFilter):
    tag = CLASS_CONTEXT | 0x02

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        value, bytes = berDecodeObject(
            LDAPBERDecoderContext_Filter(fallback=berdecoder, inherit=berdecoder),
            content,
        )
        assert bytes == len(content)

        r = klass(value=value, tag=tag)
        return r

    def __init__(self, value, tag=tag):
        LDAPFilter.__init__(self, tag=tag)
        assert value is not None
        self.value = value

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%s)" % repr(self.value)
        else:
            return self.__class__.__name__ + "(value=%s, tag=%d)" % (
                repr(self.value),
                self.tag,
            )

    def toWire(self):
        value = to_bytes(self.value)
        return bytes((self.identification(),)) + int2berlen(len(value)) + value

    def asText(self):
        return "(!" + self.value.asText() + ")"


class LDAPFilter_equalityMatch(LDAPAttributeValueAssertion):
    tag = CLASS_CONTEXT | 0x03

    def asText(self):
        return (
            "("
            + self.attributeDesc.value
            + "="
            + self.escaper(self.assertionValue.value)
            + ")"
        )


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
        l = berDecodeMultiple(
            content, LDAPBERDecoderContext_Filter_substrings(fallback=berdecoder)
        )
        assert len(l) == 2
        assert len(l[1]) >= 1

        r = klass(type=l[0].value, substrings=list(l[1]), tag=tag)
        return r

    def __init__(self, type=None, substrings=None, tag=None):
        BERSequence.__init__(self, value=[], tag=tag)
        assert type is not None
        assert substrings is not None
        self.type = type
        self.substrings = substrings

    def toWire(self):
        return BERSequence(
            [LDAPString(self.type), BERSequence(self.substrings)], tag=self.tag
        ).toWire()

    def __repr__(self):
        tp = self.type
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(type={}, substrings={})".format(
                repr(tp),
                repr(self.substrings),
            )
        else:
            return self.__class__.__name__ + "(type=%s, substrings=%s, tag=%d)" % (
                repr(tp),
                repr(self.substrings),
                self.tag,
            )

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
                raise NotImplementedError("TODO: Filter type not supported %r" % s)

        if initial is None:
            initial = ""
        if final is None:
            final = ""

        return "(" + self.type + "=" + "*".join([initial] + any + [final]) + ")"


class LDAPFilter_greaterOrEqual(LDAPAttributeValueAssertion):
    tag = CLASS_CONTEXT | 0x05

    def asText(self):
        return (
            "("
            + self.attributeDesc.value
            + ">="
            + self.escaper(self.assertionValue.value)
            + ")"
        )


class LDAPFilter_lessOrEqual(LDAPAttributeValueAssertion):
    tag = CLASS_CONTEXT | 0x06

    def asText(self):
        return (
            "("
            + self.attributeDesc.value
            + "<="
            + self.escaper(self.assertionValue.value)
            + ")"
        )


class LDAPFilter_present(LDAPAttributeDescription):
    tag = CLASS_CONTEXT | 0x07

    def asText(self):
        return "(%s=*)" % self.value


class LDAPFilter_approxMatch(LDAPAttributeValueAssertion):
    tag = CLASS_CONTEXT | 0x08

    def asText(self):
        return (
            "("
            + self.attributeDesc.value
            + "~="
            + self.escaper(self.assertionValue.value)
            + ")"
        )


class LDAPMatchingRuleId(LDAPString):
    pass


class LDAPAssertionValue(BEROctetString):
    pass


class LDAPMatchingRuleAssertion_matchingRule(LDAPMatchingRuleId):
    tag = CLASS_CONTEXT | 0x01


class LDAPMatchingRuleAssertion_type(LDAPAttributeDescription):
    tag = CLASS_CONTEXT | 0x02


class LDAPMatchingRuleAssertion_matchValue(LDAPAssertionValue):
    tag = CLASS_CONTEXT | 0x03


class LDAPMatchingRuleAssertion_dnAttributes(BERBoolean):
    tag = CLASS_CONTEXT | 0x04


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
        l = berDecodeMultiple(
            content,
            LDAPBERDecoderContext_MatchingRuleAssertion(
                fallback=berdecoder, inherit=berdecoder
            ),
        )
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
            tag=tag,
        )

        return r

    def __init__(
        self,
        matchingRule=None,
        type=None,
        matchValue=None,
        dnAttributes=None,
        tag=None,
        escaper=escape,
    ):
        BERSequence.__init__(self, value=[], tag=tag)
        assert matchValue is not None
        if isinstance(matchingRule, (bytes, str)):
            matchingRule = LDAPMatchingRuleAssertion_matchingRule(matchingRule)

        if isinstance(type, (bytes, str)):
            type = LDAPMatchingRuleAssertion_type(type)

        if isinstance(matchValue, (bytes, str)):
            matchValue = LDAPMatchingRuleAssertion_matchValue(matchValue)

        if isinstance(dnAttributes, bool):
            dnAttributes = LDAPMatchingRuleAssertion_dnAttributes(dnAttributes)

        self.matchingRule = matchingRule
        self.type = type
        self.matchValue = matchValue
        self.dnAttributes = dnAttributes
        if not self.dnAttributes:
            self.dnAttributes = None
        self.escaper = escaper

    def toWire(self):
        return BERSequence(
            filter(
                lambda x: x is not None,
                [self.matchingRule, self.type, self.matchValue, self.dnAttributes],
            ),
            tag=self.tag,
        ).toWire()

    def __repr__(self):
        l = []
        l.append("matchingRule=%s" % repr(self.matchingRule))
        l.append("type=%s" % repr(self.type))
        l.append("matchValue=%s" % repr(self.matchValue))
        l.append("dnAttributes=%s" % repr(self.dnAttributes))
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPFilter_extensibleMatch(LDAPMatchingRuleAssertion):
    tag = CLASS_CONTEXT | 0x09

    def asText(self):
        return (
            "("
            + (self.type.value if self.type else "")
            + (":dn" if self.dnAttributes and self.dnAttributes.value else "")
            + ((":" + self.matchingRule.value) if self.matchingRule else "")
            + ":="
            + self.escaper(self.matchValue.value)
            + ")"
        )


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

LDAPFilterMatchAll = LDAPFilter_present("objectClass")


class LDAPSearchRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 0x03

    baseObject = ""
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
        l = berDecodeMultiple(
            content,
            LDAPBERDecoderContext_Filter(fallback=berdecoder, inherit=berdecoder),
        )

        assert 8 <= len(l) <= 8
        r = klass(
            baseObject=l[0].value,
            scope=l[1].value,
            derefAliases=l[2].value,
            sizeLimit=l[3].value,
            timeLimit=l[4].value,
            typesOnly=l[5].value,
            filter=l[6],
            attributes=[x.value for x in l[7]],
            tag=tag,
        )
        return r

    def __init__(
        self,
        baseObject=None,
        scope=None,
        derefAliases=None,
        sizeLimit=None,
        timeLimit=None,
        typesOnly=None,
        filter=None,
        attributes=None,
        tag=None,
    ):
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

    def toWire(self):
        return BERSequence(
            [
                BEROctetString(self.baseObject),
                BEREnumerated(self.scope),
                BEREnumerated(self.derefAliases),
                BERInteger(self.sizeLimit),
                BERInteger(self.timeLimit),
                BERBoolean(self.typesOnly),
                self.filter,
                BERSequenceOf(map(BEROctetString, self.attributes)),
            ],
            tag=self.tag,
        ).toWire()

    def __repr__(self):
        base = self.baseObject
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + (
                "(baseObject=%s, scope=%s, derefAliases=%s, "
                + "sizeLimit=%s, timeLimit=%s, typesOnly=%s, "
                "filter=%s, attributes=%s)"
            ) % (
                repr(base),
                self.scope,
                self.derefAliases,
                self.sizeLimit,
                self.timeLimit,
                self.typesOnly,
                repr(self.filter),
                self.attributes,
            )

        else:
            return self.__class__.__name__ + (
                "(baseObject=%s, scope=%s, derefAliases=%s, "
                + "sizeLimit=%s, timeLimit=%s, typesOnly=%s, "
                "filter=%s, attributes=%s, tag=%d)"
            ) % (
                repr(base),
                self.scope,
                self.derefAliases,
                self.sizeLimit,
                self.timeLimit,
                self.typesOnly,
                repr(self.filter),
                self.attributes,
                self.tag,
            )


class LDAPSearchResultEntry(LDAPProtocolResponse, BERSequence):
    tag = CLASS_APPLICATION | 0x04

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(
            content,
            LDAPBERDecoderContext_Filter(fallback=berdecoder, inherit=berdecoder),
        )

        objectName = l[0].value
        attributes = []
        for attr, li in l[1].data:
            attributes.append((attr.value, [x.value for x in li]))
        r = klass(objectName=objectName, attributes=attributes, tag=tag)
        return r

    def __init__(self, objectName, attributes, tag=None):
        LDAPProtocolResponse.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        assert objectName is not None
        assert attributes is not None
        self.objectName = objectName
        self.attributes = attributes

    def toWire(self):
        return BERSequence(
            [
                BEROctetString(self.objectName),
                BERSequence(
                    [
                        BERSequence(
                            [
                                BEROctetString(attr_li[0]),
                                BERSet([BEROctetString(x) for x in attr_li[1]]),
                            ]
                        )
                        for attr_li in self.attributes
                    ]
                ),
            ],
            tag=self.tag,
        ).toWire()

    def __repr__(self):
        name = self.objectName
        attributes = [(key, [v for v in value]) for (key, value) in self.attributes]
        return "{}(objectName={}, attributes={}{})".format(
            self.__class__.__name__,
            repr(name),
            repr(attributes),
            ", tag={}".format(self.tag) if self.tag != self.__class__.tag else "",
        )


class LDAPSearchResultDone(LDAPResult):
    tag = CLASS_APPLICATION | 0x05


class LDAPControls(BERSequence):
    tag = CLASS_CONTEXT | 0x00

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(
            content, LDAPBERDecoderContext_LDAPControls(inherit=berdecoder)
        )

        r = klass(l, tag=tag)
        return r


class LDAPControl(BERSequence):
    criticality = None
    controlValue = None

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(content, berdecoder)

        assert 1 <= len(l) <= 3

        kw = {}
        if len(l) == 2:
            if isinstance(l[1], BERBoolean):
                kw["criticality"] = l[1].value
            elif isinstance(l[1], BEROctetString):
                kw["controlValue"] = l[1].value
        elif len(l) == 3:
            kw["criticality"] = l[1].value
            kw["controlValue"] = l[2].value

        r = klass(controlType=l[0].value, tag=tag, **kw)
        return r

    def __init__(
        self, controlType, criticality=None, controlValue=None, id=None, tag=None
    ):
        BERSequence.__init__(self, value=[], tag=tag)
        assert controlType is not None
        self.controlType = controlType
        self.criticality = criticality
        self.controlValue = controlValue

    def toWire(self):
        self.data = [LDAPOID(self.controlType)]
        if self.criticality is not None:
            self.data.append(BERBoolean(self.criticality))
        if self.controlValue is not None:
            self.data.append(BEROctetString(self.controlValue))
        return BERSequence.toWire(self)


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

        r = klass(object=l[0].value, modification=l[1].data, tag=tag)
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

    def toWire(self):
        l = [LDAPString(self.object)]
        if self.modification is not None:
            l.append(BERSequence(self.modification))
        return BERSequence(l, tag=self.tag).toWire()

    def __repr__(self):
        name = self.object
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(object={}, modification={})".format(
                repr(name),
                repr(self.modification),
            )
        else:
            return self.__class__.__name__ + "(object=%s, modification=%s, tag=%d)" % (
                repr(name),
                repr(self.modification),
                self.tag,
            )


class LDAPModifyResponse(LDAPResult):
    tag = CLASS_APPLICATION | 0x07


class LDAPAddRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 0x08

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(content, berdecoder)

        r = klass(entry=l[0].value, attributes=l[1], tag=tag)
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
                             ])"""

        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        self.entry = entry
        self.attributes = attributes

    def toWire(self):
        return BERSequence(
            [
                LDAPString(self.entry),
                BERSequence(map(BERSequence, self.attributes)),
            ],
            tag=self.tag,
        ).toWire()

    def __repr__(self):
        entry = self.entry
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(entry={}, attributes={})".format(
                repr(entry),
                repr(self.attributes),
            )
        else:
            return self.__class__.__name__ + "(entry=%s, attributes=%s, tag=%d)" % (
                repr(entry),
                repr(self.attributes),
                self.tag,
            )


class LDAPAddResponse(LDAPResult):
    tag = CLASS_APPLICATION | 0x09


class LDAPDelRequest(LDAPProtocolRequest, LDAPString):
    tag = CLASS_APPLICATION | 0x0A

    def __init__(self, value=None, entry=None, tag=None):
        """
        Initialize the object

        l=LDAPDelRequest(entry='cn=foo,dc=example,dc=com')
        """
        if entry is None and value is not None:
            entry = value
        LDAPProtocolRequest.__init__(self)
        LDAPString.__init__(self, value=entry, tag=tag)

    def toWire(self):
        return LDAPString.toWire(self)

    def __repr__(self):
        entry = self.value
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(entry=%s)" % repr(entry)
        else:
            return self.__class__.__name__ + "(entry=%s, tag=%d)" % (
                repr(entry),
                self.tag,
            )


class LDAPDelResponse(LDAPResult):
    tag = CLASS_APPLICATION | 0x0B


class LDAPModifyDNResponse_newSuperior(LDAPString):
    tag = CLASS_CONTEXT | 0x00


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
        l = berDecodeMultiple(
            content, LDAPBERDecoderContext_ModifyDNRequest(fallback=berdecoder)
        )

        kw = {}
        try:
            kw["newSuperior"] = to_bytes(l[3].value)
        except IndexError:
            pass

        r = klass(
            entry=to_bytes(l[0].value),
            newrdn=to_bytes(l[1].value),
            deleteoldrdn=l[2].value,
            tag=tag,
            **kw,
        )
        return r

    def __init__(self, entry, newrdn, deleteoldrdn, newSuperior=None, tag=None):
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

    def toWire(self):
        l = [
            LDAPString(self.entry),
            LDAPString(self.newrdn),
            BERBoolean(self.deleteoldrdn),
        ]
        if self.newSuperior is not None:
            l.append(LDAPString(self.newSuperior, tag=CLASS_CONTEXT | 0))
        return BERSequence(l, tag=self.tag).toWire()

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
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPModifyDNResponse(LDAPResult):
    tag = CLASS_APPLICATION | 13


class LDAPBERDecoderContext_Compare(BERDecoderContext):
    Identities = {BERSequence.tag: LDAPAttributeValueAssertion}


class LDAPCompareRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 14

    entry = None
    ava = None

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(
            content,
            LDAPBERDecoderContext_Compare(fallback=berdecoder, inherit=berdecoder),
        )

        r = klass(entry=l[0].value, ava=l[1], tag=tag)

        return r

    def __init__(self, entry, ava, tag=None):
        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        assert entry is not None
        assert ava is not None
        self.entry = entry
        self.ava = ava

    def toWire(self):
        l = [LDAPString(self.entry), self.ava]
        return BERSequence(l, tag=self.tag).toWire()

    def __repr__(self):
        l = [
            "entry={}".format(repr(self.entry)),
            "ava={}".format(repr(self.ava)),
        ]
        return "{}({})".format(self.__class__.__name__, ", ".join(l))


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

    def toWire(self):
        return LDAPInteger.toWire(self)

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(id=%s)" % repr(self.value)
        else:
            return self.__class__.__name__ + "(id=%s, tag=%d)" % (
                repr(self.value),
                self.tag,
            )


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
        l = berDecodeMultiple(
            content, LDAPBERDecoderContext_LDAPExtendedRequest(fallback=berdecoder)
        )

        kw = {}
        try:
            kw["requestValue"] = l[1].value
        except IndexError:
            pass

        r = klass(requestName=l[0].value, tag=tag, **kw)
        return r

    def __init__(self, requestName=None, requestValue=None, tag=None):
        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        assert requestName is not None
        assert isinstance(requestName, (bytes, str))
        assert requestValue is None or isinstance(requestValue, (bytes, str))
        self.requestName = requestName
        self.requestValue = requestValue

    def toWire(self):
        l = [LDAPOID(self.requestName, tag=CLASS_CONTEXT | 0)]
        if self.requestValue is not None:
            value = to_bytes(self.requestValue)
            l.append(BEROctetString(value, tag=CLASS_CONTEXT | 1))
        return BERSequence(l, tag=self.tag).toWire()


class LDAPPasswordModifyRequest_userIdentity(BEROctetString):
    tag = CLASS_CONTEXT | 0


class LDAPPasswordModifyRequest_passwd(BEROctetString):
    def __repr__(self):
        value = "*" * len(self.value)
        return "{}(value={}{})".format(
            self.__class__.__name__,
            repr(value),
            ", tag={}".format(self.tag) if self.tag != self.__class__.tag else "",
        )


class LDAPPasswordModifyRequest_oldPasswd(LDAPPasswordModifyRequest_passwd):
    tag = CLASS_CONTEXT | 1


class LDAPPasswordModifyRequest_newPasswd(LDAPPasswordModifyRequest_passwd):
    tag = CLASS_CONTEXT | 2


class LDAPBERDecoderContext_LDAPPasswordModifyRequest(BERDecoderContext):
    Identities = {
        LDAPPasswordModifyRequest_userIdentity.tag: LDAPPasswordModifyRequest_userIdentity,
        LDAPPasswordModifyRequest_oldPasswd.tag: LDAPPasswordModifyRequest_oldPasswd,
        LDAPPasswordModifyRequest_newPasswd.tag: LDAPPasswordModifyRequest_newPasswd,
    }


class LDAPPasswordModifyRequest(LDAPExtendedRequest):
    oid = b"1.3.6.1.4.1.4203.1.11.1"

    def __init__(
        self,
        requestName=None,
        userIdentity=None,
        oldPasswd=None,
        newPasswd=None,
        tag=None,
    ):
        assert (
            requestName is None or requestName == self.oid
        ), "{} requestName was {} instead of {}".format(
            self.__class__.__name__,
            requestName,
            self.oid,
        )
        # TODO genPasswd

        l = []
        self.userIdentity = None
        if userIdentity is not None:
            self.userIdentity = LDAPPasswordModifyRequest_userIdentity(userIdentity)
            l.append(self.userIdentity)

        self.oldPasswd = None
        if oldPasswd is not None:
            self.oldPasswd = LDAPPasswordModifyRequest_oldPasswd(oldPasswd)
            l.append(self.oldPasswd)

        self.newPasswd = None
        if newPasswd is not None:
            self.newPasswd = LDAPPasswordModifyRequest_newPasswd(newPasswd)
            l.append(self.newPasswd)

        LDAPExtendedRequest.__init__(
            self, requestName=self.oid, requestValue=BERSequence(l).toWire(), tag=tag
        )

    def __repr__(self):
        l = []
        if self.userIdentity is not None:
            l.append("userIdentity={}".format(repr(self.userIdentity)))
        if self.oldPasswd is not None:
            l.append("oldPasswd={}".format(repr(self.oldPasswd)))
        if self.newPasswd is not None:
            l.append("newPasswd={}".format(repr(self.newPasswd)))
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


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
        l = berDecodeMultiple(
            content, LDAPBERDecoderContext_LDAPExtendedResponse(fallback=berdecoder)
        )

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
                # TODO support referrals
                # self.referral=self.data[0]
                pass
            else:
                assert False

        r = klass(
            resultCode=l[0].value,
            matchedDN=l[1].value,
            errorMessage=l[2].value,
            referral=referral,
            responseName=responseName,
            response=response,
            tag=tag,
        )
        return r

    def __init__(
        self,
        resultCode=None,
        matchedDN=None,
        errorMessage=None,
        referral=None,
        serverSaslCreds=None,
        responseName=None,
        response=None,
        tag=None,
    ):
        LDAPResult.__init__(
            self,
            resultCode=resultCode,
            matchedDN=matchedDN,
            errorMessage=errorMessage,
            referral=referral,
            serverSaslCreds=serverSaslCreds,
            tag=tag,
        )
        self.responseName = responseName
        self.response = response

    def toWire(self):
        assert self.referral is None  # TODO
        l = [
            BEREnumerated(self.resultCode),
            BEROctetString(self.matchedDN),
            BEROctetString(self.errorMessage),
            # TODO referral [3] Referral OPTIONAL
        ]
        if self.responseName is not None:
            l.append(LDAPOID(self.responseName, tag=CLASS_CONTEXT | 0x0A))
        if self.response is not None:
            l.append(BEROctetString(self.response, tag=CLASS_CONTEXT | 0x0B))
        return BERSequence(l, tag=self.tag).toWire()


class LDAPStartTLSRequest(LDAPExtendedRequest):
    """
    Request to start Transport Layer Security.
    See RFC 2830 for details.
    """

    oid = b"1.3.6.1.4.1.1466.20037"

    def __init__(self, requestName=None, tag=None):
        assert (
            requestName is None or requestName == self.oid
        ), "{} requestName was {} instead of {}".format(
            self.__class__.__name__,
            requestName,
            self.oid,
        )

        LDAPExtendedRequest.__init__(self, requestName=self.oid, tag=tag)

    def __repr__(self):
        l = []
        if self.tag != self.__class__.tag:
            l.append("tag={}".format(self.tag))
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPStartTLSResponse(LDAPExtendedResponse):
    """
    Response to start Transport Layer Security.
    See RFC 4511 section 4.14.2 for details.
    """

    oid = b"1.3.6.1.4.1.1466.20037"

    def __init__(
        self,
        resultCode=None,
        matchedDN=None,
        errorMessage=None,
        referral=None,
        serverSaslCreds=None,
        responseName=None,
        response=None,
        tag=None,
    ):
        LDAPExtendedResponse.__init__(
            self,
            resultCode=resultCode,
            matchedDN=matchedDN,
            errorMessage=errorMessage,
            referral=referral,
            serverSaslCreds=serverSaslCreds,
            responseName=responseName,
            response=response,
            tag=tag,
        )

    def __repr__(self):
        l = []
        if self.tag != self.__class__.tag:
            l.append("tag={}".format(self.tag))
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPBERDecoderContext(BERDecoderContext):
    Identities = {
        LDAPBindResponse.tag: LDAPBindResponse,
        LDAPBindRequest.tag: LDAPBindRequest,
        LDAPUnbindRequest.tag: LDAPUnbindRequest,
        LDAPSearchRequest.tag: LDAPSearchRequest,
        LDAPSearchResultEntry.tag: LDAPSearchResultEntry,
        LDAPSearchResultDone.tag: LDAPSearchResultDone,
        LDAPSearchResultReference.tag: LDAPSearchResultReference,
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
        LDAPCompareResponse.tag: LDAPCompareResponse,
    }
