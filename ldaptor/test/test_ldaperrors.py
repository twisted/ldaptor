"""
    Test cases for ldaptor.protocols.ldap.ldaperrors module.
"""

from twisted.trial import unittest

from ldaptor.protocols.ldap import ldaperrors


class UnnamedException(ldaperrors.LDAPException):
    """LDAP exception with undefined name"""


class GetTests(unittest.TestCase):
    """Getting LDAP exception implementation by error code"""

    def test_get_success(self):
        """Getting OK message"""
        success = ldaperrors.get(0, "Some message")
        self.assertEqual(success.__class__, ldaperrors.Success)
        self.assertEqual(success.resultCode, 0)
        self.assertEqual(success.name, b"success")

    def test_get_existing_exception(self):
        """Getting existing LDAPException subclass"""
        exception = ldaperrors.get(49, "Error message")
        self.assertEqual(exception.__class__, ldaperrors.LDAPInvalidCredentials)
        self.assertEqual(exception.resultCode, 49)
        self.assertEqual(exception.name, b"invalidCredentials")
        self.assertEqual(exception.message, "Error message")

    def test_get_nonexisting_exception(self):
        """Getting non-existing LDAP error"""
        exception = ldaperrors.get(55, "Error message")
        self.assertEqual(exception.__class__, ldaperrors.LDAPUnknownError)
        self.assertEqual(exception.code, 55)
        self.assertEqual(exception.message, "Error message")


class LDAPExceptionTests(unittest.TestCase):
    """Getting bytes representations of LDAP exceptions"""

    def test_exception_with_message(self):
        """Exception with a text message"""
        exception = ldaperrors.LDAPProtocolError("Error message")
        self.assertEqual(exception.toWire(), b"protocolError: Error message")

    def test_empty_exception(self):
        """Exception with no message"""
        exception = ldaperrors.LDAPCompareFalse()
        self.assertEqual(exception.toWire(), b"compareFalse")

    def test_unnamed_exception(self):
        """Exception with no name"""
        exception = UnnamedException()
        self.assertEqual(exception.toWire(), b"Unknown LDAP error UnnamedException()")

    def test_unknown_exception_with_message(self):
        """Unknown exception with a text message"""
        exception = ldaperrors.LDAPUnknownError(56, "Error message")
        self.assertEqual(exception.toWire(), b"unknownError(56): Error message")

    def test_unknown_empty_exception(self):
        """Unknown exception with no message"""
        exception = ldaperrors.LDAPUnknownError(57)
        self.assertEqual(exception.toWire(), b"unknownError(57)")


class LDAPExceptionStrTests(unittest.TestCase):
    """Getting string representations of LDAP exceptions"""

    def test_exception_with_message(self):
        """Exception with a text message"""
        exception = ldaperrors.LDAPProtocolError("Error message")
        self.assertEqual(str(exception), "protocolError: Error message")
