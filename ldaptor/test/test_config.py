"""
Test cases for the ldaptor.config module.
"""

import os

from twisted.trial import unittest
from ldaptor import config


def writeFile(path, content):
    f = open(path, 'w')
    f.write(content)
    f.close()


class TestConfig(unittest.TestCase):
    def testSomething(self):
        self.dir = self.mktemp()
        os.mkdir(self.dir)
        self.f1 = os.path.join(self.dir, 'one.cfg')
        writeFile(self.f1, """\
[fooSection]
fooVar = val

[barSection]
barVar = anotherVal
""")
        self.f2 = os.path.join(self.dir, 'two.cfg')
        writeFile(self.f2, """\
[fooSection]
fooVar = val2
""")
        self.cfg = config.loadConfig(
            configFiles=[self.f1, self.f2],
            reload=True)

        val = self.cfg.get('fooSection', 'fooVar')
        self.assertEqual(val, 'val2')

        val = self.cfg.get('barSection', 'barVar')
        self.assertEqual(val, 'anotherVal')

class IdentitySearch(unittest.TestCase):
    def setUp(self):
        self.dir = self.mktemp()
        os.mkdir(self.dir)
        self.f1 = os.path.join(self.dir, 'one.cfg')
        writeFile(self.f1, """\
[authentication]
identity-search = (something=%(name)s)
""")
        self.cfg = config.loadConfig(
            configFiles=[self.f1],
            reload=True)
        self.config = config.LDAPConfig()

    def testConfig(self):
        self.assertEqual(self.config.getIdentitySearch('foo'),
                          '(something=foo)')

    def testCopy(self):
        conf = self.config.copy(identitySearch='(&(bar=baz)(quux=%(name)s))')
        self.assertEqual(conf.getIdentitySearch('foo'),
                          '(&(bar=baz)(quux=foo))')

    def testInitArg(self):
        conf = config.LDAPConfig(identitySearch='(&(bar=thud)(quux=%(name)s))')
        self.assertEqual(conf.getIdentitySearch('foo'),
                          '(&(bar=thud)(quux=foo))')
