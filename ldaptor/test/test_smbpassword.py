"""
Test cases for the ldaptor.samba.smbpassword module.
"""

from twisted.trial import unittest
from ldaptor.samba import smbpassword
from ldaptor import config

class TestNTHash(unittest.TestCase):
    """
    Unit tests for smbpassword.nthash.
    """
    knownValues=[ # password, expected_result
        (b'', b'31D6CFE0D16AE931B73C59D7E0C089C0'),
        (b'foo', b'AC8E657F83DF82BEEA5D43BDAF7800CC'),
        (127 * b'x', b'25900FAB94A048BCF438615217776562'),
        (128 * b'x', b'65681023D0CB5E7E96FF662150EF060D'),
        (129 * b'x', b'65681023D0CB5E7E96FF662150EF060D'),
        (1000 * b'x', b'65681023D0CB5E7E96FF662150EF060D'),
    ]

    def testKnownValues(self):
        """nthash(...) gives known results"""
        self.assertEqual(
            self.knownValues,
            [(p, smbpassword.nthash(p)) for p, _ in self.knownValues]
        )


class TestLMHash(unittest.TestCase):
    """
    Unit tests for smbpassword.lmhash.
    """
    knownValues=[ # password, expected_result
        (b'', b'AAD3B435B51404EEAAD3B435B51404EE'),
        (b'foo', b'5BFAFBEBFB6A0942AAD3B435B51404EE'),
        (13 * b'x', b'3AA62DBBEFDB676366B4159AF5A7C45C'),
        (14 * b'x', b'3AA62DBBEFDB67633AA62DBBEFDB6763'),
        (15 * b'x', b'3AA62DBBEFDB67633AA62DBBEFDB6763'),
        (100 * b'x', b'3AA62DBBEFDB67633AA62DBBEFDB6763'),
        (b'1234567abcdefg', b'0182BD0BD4444BF8E0C510199CC66ABD'),
        (b'XXXXXXXabcdefg', b'3AA62DBBEFDB6763E0C510199CC66ABD'),
        (b'1234567XXXXXXX', b'0182BD0BD4444BF83AA62DBBEFDB6763'),
    ]

    def testKnownValues(self):
        """
        When lanman password are enabled in the configuration, they will
        return
        """
        cfg = config.loadConfig()
        cfg.set('samba', 'use-lmhash', 'yes')
        self.assertEqual(
            self.knownValues,
            [(p, smbpassword.lmhash(p)) for p, _ in self.knownValues]
        )

    def testLMHashConfiguationDisabled(self):
        """
        When the lanman passwords are disabled from the configuration, it will
        return the disabled password.
        """
        cfg = config.loadConfig()
        cfg.set('samba', 'use-lmhash', 'no')

        result = smbpassword.lmhash(b'any-pass')

        self.assertEqual(32 * b'X', result)
