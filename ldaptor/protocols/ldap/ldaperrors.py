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

import six

from ldaptor._encoder import to_bytes


def get(resultCode, errorMessage):
    """Get an instance of the correct exception for this resultCode."""
    return LDAPExceptionCollection.get_instance(resultCode, errorMessage)


class LDAPExceptionCollection(type):
    """
    Storage for the LDAP result codes and
    the corresponding classes.
    """

    collection = {}

    def __new__(mcs, name, bases, attributes):
        cls = type.__new__(mcs, name, bases, attributes)
        code = attributes.get('resultCode')
        if code is not None:
            assert isinstance(code, int)
            assert isinstance(attributes.get('name'), bytes)
            mcs.collection[code] = cls
        return cls

    @classmethod
    def get_instance(mcs, code, message):
        """Get an instance of the correct exception for this result code."""
        cls = mcs.collection.get(code)
        if cls is not None:
            return cls(message)
        return LDAPUnknownError(code, message)


class LDAPResult(six.with_metaclass(LDAPExceptionCollection)):
    resultCode = None
    name = None


class Success(LDAPResult):
    resultCode = 0
    name = b'success'

    def __init__(self, msg):
        pass


class LDAPException(Exception, LDAPResult):
    def __init__(self, message=None):
        Exception.__init__(self)
        self.message = message

    def __str__(self):
        message = self.toWire()
        return message if six.PY2 else message.decode('utf-8')

    def toWire(self):
        if self.message:
            return b'%s: %s' % (self.name, to_bytes(self.message))
        if self.name:
            return self.name
        return b'Unknown LDAP error %r' % self


class LDAPUnknownError(LDAPException):
    def __init__(self, resultCode, message=None):
        assert resultCode not in LDAPExceptionCollection.collection, \
            "resultCode %r must be unknown" % resultCode
        self.code = resultCode
        LDAPException.__init__(self, message)

    def toWire(self):
        codeName = b'unknownError(%d)' % self.code
        if self.message:
            return b'%s: %s' % (codeName, to_bytes(self.message))
        else:
            return codeName


class LDAPOperationsError(LDAPException):
    resultCode = 1
    name = b'operationsError'


class LDAPProtocolError(LDAPException):
    resultCode = 2
    name = b'protocolError'


class LDAPTimeLimitExceeded(LDAPException):
    resultCode = 3
    name = b'timeLimitExceeded'


class LDAPSizeLimitExceeded(LDAPException):
    resultCode = 4
    name = b'sizeLimitExceeded'


class LDAPCompareFalse(LDAPException):
    resultCode = 5
    name = b'compareFalse'


class LDAPCompareTrue(LDAPException):
    resultCode = 6
    name = b'compareTrue'


class LDAPAuthMethodNotSupported(LDAPException):
    resultCode = 7
    name = b'authMethodNotSupported'


class LDAPStrongAuthRequired(LDAPException):
    resultCode = 8
    name = b'strongAuthRequired'

# 9 reserved


class LDAPReferral(LDAPException):
    resultCode = 10
    name = b'referral'


class LDAPAdminLimitExceeded(LDAPException):
    resultCode = 11
    name = b'adminLimitExceeded'


class LDAPUnavailableCriticalExtension(LDAPException):
    resultCode = 12
    name = b'unavailableCriticalExtension'


class LDAPConfidentialityRequired(LDAPException):
    resultCode = 13
    name = b'confidentialityRequired'


class LDAPSaslBindInProgress(LDAPException):
    resultCode = 14
    name = b'saslBindInProgress'


class LDAPNoSuchAttribute(LDAPException):
    resultCode = 16
    name = b'noSuchAttribute'


class LDAPUndefinedAttributeType(LDAPException):
    resultCode = 17
    name = b'undefinedAttributeType'


class LDAPInappropriateMatching(LDAPException):
    resultCode = 18
    name = b'inappropriateMatching'


class LDAPConstraintViolation(LDAPException):
    resultCode = 19
    name = b'constraintViolation'


class LDAPAttributeOrValueExists(LDAPException):
    resultCode = 20
    name = b'attributeOrValueExists'


class LDAPInvalidAttributeSyntax(LDAPException):
    resultCode = 21
    name = b'invalidAttributeSyntax'

# 22-31 unused


class LDAPNoSuchObject(LDAPException):
    resultCode = 32
    name = b'noSuchObject'


class LDAPAliasProblem(LDAPException):
    resultCode = 33
    name = b'aliasProblem'


class LDAPInvalidDNSyntax(LDAPException):
    resultCode = 34
    name = b'invalidDNSyntax'

# 35 reserved for undefined isLeaf


class LDAPAliasDereferencingProblem(LDAPException):
    resultCode = 36
    name = b'aliasDereferencingProblem'

# 37-47 unused


class LDAPInappropriateAuthentication(LDAPException):
    resultCode = 48
    name = b'inappropriateAuthentication'


class LDAPInvalidCredentials(LDAPException):
    resultCode = 49
    name = b'invalidCredentials'


class LDAPInsufficientAccessRights(LDAPException):
    resultCode = 50
    name = b'insufficientAccessRights'


class LDAPBusy(LDAPException):
    resultCode = 51
    name = b'busy'


class LDAPUnavailable(LDAPException):
    resultCode = 52
    name = b'unavailable'


class LDAPUnwillingToPerform(LDAPException):
    resultCode = 53
    name = b'unwillingToPerform'


class LDAPLoopDetect(LDAPException):
    resultCode = 54
    name = b'loopDetect'

# 55-63 unused


class LDAPNamingViolation(LDAPException):
    resultCode = 64
    name = b'namingViolation'


class LDAPObjectClassViolation(LDAPException):
    resultCode = 65
    name = b'objectClassViolation'


class LDAPNotAllowedOnNonLeaf(LDAPException):
    resultCode = 66
    name = b'notAllowedOnNonLeaf'


class LDAPNotAllowedOnRDN(LDAPException):
    resultCode = 67
    name = b'notAllowedOnRDN'


class LDAPEntryAlreadyExists(LDAPException):
    resultCode = 68
    name = b'entryAlreadyExists'


class LDAPObjectClassModsProhibited(LDAPException):
    resultCode = 69
    name = b'objectClassModsProhibited'

# 70 reserved for CLDAP


class LDAPAffectsMultipleDSAs(LDAPException):
    resultCode = 71
    name = b'affectsMultipleDSAs'

# 72-79 unused


class LDAPOther(LDAPException):
    resultCode = 80
    name = b'other'

# 81-90 reserved for APIs


# Backwards compatibility
other = LDAPOther.resultCode
reverse = LDAPExceptionCollection.collection
