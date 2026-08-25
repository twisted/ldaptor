"""
Test cases for ldaptor.usage
"""

import re

from twisted.python.usage import UsageError
from twisted.trial.unittest import TestCase

from ldaptor.protocols.ldap.distinguishedname import DistinguishedName
from ldaptor.usage import Options, Options_service_location, Options_scope


class ScopeOptionsImplementation(Options, Options_scope):
    """
    Minimal implementation for a command line using `Options_scope`.
    """


class TestOptions_scope(TestCase):
    def test_parseOptions_bad_scope(self):
        """
        It fails to parse the option when the scope is bad
        """
        self.assertRaisesRegex(
            UsageError,
            re.escape("bad scope: this is a bad scope"),
            ScopeOptionsImplementation().parseOptions,
            options=["--scope", "this is a bad scope"],
        )

    def test_parseOptions_default(self):
        """
        When no explicit options is provided it will set an empty dict.
        """
        sut = ServiceLocationOptionsImplementation()
        self.assertNotIn("service-location", sut.opts)

        sut.parseOptions(options=[])

        self.assertEqual({}, sut.opts["service-location"])


class ServiceLocationOptionsImplementation(Options, Options_service_location):
    """
    Minimal implementation for a command line using `Options_service_location`.
    """


class TestOptions_service_location(TestCase):
    """
    Unit tests for Options_service_location.
    """

    def test_parseOptions_default(self):
        """
        When no explicit options is provided it will set an empty dict.
        """
        sut = ServiceLocationOptionsImplementation()
        self.assertNotIn("service-location", sut.opts)

        sut.parseOptions(options=[])

        self.assertEqual({}, sut.opts["service-location"])

    def test_parseOptions_single(self):
        """
        It can have a single --service-location option.
        """
        sut = ServiceLocationOptionsImplementation()

        sut.parseOptions(
            options=["--service-location", "dc=example,dc=com:127.0.0.1:1234"]
        )

        base = DistinguishedName("dc=example,dc=com")
        value = sut.opts["service-location"][base]
        self.assertEqual(("127.0.0.1", "1234"), value)

    def test_parseOptions_invalid_DN(self):
        """
        It fails to parse the option when the base DN is not valid.
        """
        sut = ServiceLocationOptionsImplementation()

        exception = self.assertRaises(
            UsageError,
            sut.parseOptions,
            options=["--service-location", "example.com:1.2.3.4"],
        )

        self.assertEqual(
            "Invalid relative distinguished name 'example.com'.", exception.args[0]
        )

    def test_parseOptions_no_server(self):
        """
        It fails to parse the option when no host is defined, but only
        a base DN.
        """
        sut = ServiceLocationOptionsImplementation()

        exception = self.assertRaises(
            UsageError,
            sut.parseOptions,
            options=["--service-location", "dc=example,dc=com"],
        )

        self.assertEqual("service-location must specify host", exception.args[0])

    def test_parseOptions_multiple(self):
        """
        It can have have multiple --service-location options and they are
        indexed using the base DN.
        """
        sut = ServiceLocationOptionsImplementation()

        sut.parseOptions(
            options=[
                "--service-location",
                "dc=example,dc=com:127.0.0.1",
                "--service-location",
                "dc=example,dc=org:172.0.0.1",
            ]
        )

        base_com = DistinguishedName("dc=example,dc=com")
        base_org = DistinguishedName("dc=example,dc=org")
        value_com = sut.opts["service-location"][base_com]
        value_org = sut.opts["service-location"][base_org]
        self.assertEqual(("127.0.0.1", None), value_com)
        self.assertEqual(("172.0.0.1", None), value_org)
