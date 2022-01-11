"""
Test cases for the ldaptor.config module.
"""

import os

from twisted.trial import unittest
from ldaptor import config


def writeFile(path, content):
    f = open(path, "wb")
    f.write(content)
    f.close()


def reloadFromContent(testCase, content):
    """
    Reload the global configuration file with raw `content`.
    """
    base_path = testCase.mktemp()
    os.mkdir(base_path)
    config_path = os.path.join(base_path, "test.cfg")
    writeFile(config_path, content)

    # Reload with empty content to reduce the side effects.
    testCase.addCleanup(reloadFromContent, testCase, b"")

    return config.loadConfig(
        configFiles=[config_path],
        reload=True,
    )


class TestLoadConfig(unittest.TestCase):
    """
    Tests for loadConfig.
    """

    def testMultileConfigurationFile(self):
        """
        It can read configuration from multiple files, merging the
        loaded values.
        """
        self.dir = self.mktemp()
        os.mkdir(self.dir)
        self.f1 = os.path.join(self.dir, "one.cfg")
        writeFile(
            self.f1,
            b"""\
[fooSection]
fooVar = val

[barSection]
barVar = anotherVal
""",
        )
        self.f2 = os.path.join(self.dir, "two.cfg")
        writeFile(
            self.f2,
            b"""\
[fooSection]
fooVar = val2
""",
        )
        self.cfg = config.loadConfig(configFiles=[self.f1, self.f2], reload=True)

        val = self.cfg.get("fooSection", "fooVar")
        self.assertEqual(val, "val2")

        val = self.cfg.get("barSection", "barVar")
        self.assertEqual(val, "anotherVal")


class TestLDAPConfig(unittest.TestCase):
    """
    Unit tests for LDAPConfig.
    """

    def testGetBaseDNOK(self):
        """
        It will return the base DN found in the configuration in the [ldap]
        section as `base` option.
        """
        reloadFromContent(self, b"[ldap]\nbase=dc=test,dc=net\n")
        sut = config.LDAPConfig()

        result = sut.getBaseDN()

        self.assertEqual("dc=test,dc=net", result)

    def testGetBaseDNNoSection(self):
        """
        It raise an exception when the the configuration has no [ldap]
        section.
        """
        reloadFromContent(self, b"[other]\nbase=dc=test,dc=net\n")
        sut = config.LDAPConfig()

        self.assertRaises(
            config.MissingBaseDNError,
            sut.getBaseDN,
        )

    def testGetBaseDNNoOption(self):
        """
        It raise an exception when the the configuration has [ldap]
        section but no `base` option.
        """
        reloadFromContent(self, b"[ldap]\nbaseless=dc=test,dc=net\n")
        sut = config.LDAPConfig()

        self.assertRaises(
            config.MissingBaseDNError,
            sut.getBaseDN,
        )

    def testGetIdentityBaseDNOK(self):
        """
        It will return the value found in the configuration in the
        [authentication] section as `identity-base` option.
        """
        reloadFromContent(
            self, b"[authentication]\n" b"identity-base=ou=users,dc=test,dc=net\n"
        )
        sut = config.LDAPConfig()

        result = sut.getIdentityBaseDN()

        self.assertEqual("ou=users,dc=test,dc=net", result)

    def testGetIdentityBaseSectionSection(self):
        """
        When the configuration does not contains the
        `[authentication]` section it will return the configured Base DN.
        """
        reloadFromContent(self, b"[ldap]\n" b"basE=dc=test,dc=net\n")
        sut = config.LDAPConfig()

        result = sut.getIdentityBaseDN()

        self.assertEqual("dc=test,dc=net", result)

    def testGetIdentityBaseNoOption(self):
        """
        When the configuration does not contains the `identity-base` option
        inside the `[authentication]` section it will return the configured
        Base DN.
        """
        reloadFromContent(
            self,
            b"[ldap]\n"
            b"BASE=dc=test,dc=net\n"
            b"[authentication]\n"
            b"no-identity-base=dont care\n",
        )
        sut = config.LDAPConfig()

        result = sut.getIdentityBaseDN()

        self.assertEqual("dc=test,dc=net", result)

    def testGetIdentitySearchOK(self):
        """
        It will use the value from to configuration for its return value.
        """
        reloadFromContent(
            self,
            b"""[authentication]
identity-search = (something=%(name)s)
""",
        )
        sut = config.LDAPConfig()

        result = sut.getIdentitySearch("foo")

        self.assertEqual("(something=foo)", result)

    def testGetIdentitySearchNoSection(self):
        """
        When the configuration file does not contains the `authentication`
        section it will use a default expression.
        """
        sut = config.LDAPConfig()

        result = sut.getIdentitySearch("foo")

        self.assertEqual("(|(cn=foo)(uid=foo))", result)

    def testGetIdentitySearchNoOption(self):
        """
        When the configuration file contains the `authentication`
        section but without the identity search option,
        it will use a default expression.
        """
        reloadFromContent(self, b"[authentication]\nother_key=value")
        sut = config.LDAPConfig()

        result = sut.getIdentitySearch("foo")

        self.assertEqual("(|(cn=foo)(uid=foo))", result)

    def testgetIdentitySearchFromInitArguments(self):
        """
        When data is provided at LDAPConfig initialization it is used
        as the backend data.
        """
        sut = config.LDAPConfig(identitySearch="(&(bar=thud)(quux=%(name)s))")

        result = sut.getIdentitySearch("foo")

        self.assertEqual("(&(bar=thud)(quux=foo))", result)

    def testCopy(self):
        """
        It returns a copy of the configuration.
        """
        sut = config.LDAPConfig()

        copied = sut.copy(identitySearch="(&(bar=baz)(quux=%(name)s))")

        self.assertIsInstance(copied, config.LDAPConfig)

        result = copied.getIdentitySearch("foo")

        self.assertEqual("(&(bar=baz)(quux=foo))", result)
