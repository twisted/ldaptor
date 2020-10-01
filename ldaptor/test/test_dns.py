"""
Test cases for ldaptor.dns
"""

from twisted.trial import unittest
from ldaptor import dns


class NetmaskToNumbits(unittest.TestCase):
    def test_classA(self):
        self.assertEqual(dns.netmaskToNumbits("255.0.0.0"), 8)

    def test_classB(self):
        self.assertEqual(dns.netmaskToNumbits("255.255.0.0"), 16)

    def test_classC(self):
        self.assertEqual(dns.netmaskToNumbits("255.255.255.0"), 24)

    def test_host(self):
        self.assertEqual(dns.netmaskToNumbits("255.255.255.255"), 32)

    def test_numbits(self):
        for i in range(0, 33):
            self.assertEqual(dns.netmaskToNumbits(str(i)), i)

    def test_CIDR(self):
        for i in range(0, 33):
            mask = dns.ntoa(dns.aton(i))
            self.assertEqual(dns.netmaskToNumbits(mask), i)


class PtrSoaName(unittest.TestCase):
    def test_classA(self):
        self.assertEqual(dns.ptrSoaName("1.2.3.4", "255.0.0.0"), "1.in-addr.arpa.")
        self.assertEqual(dns.ptrSoaName("1.2.3.4", "8"), "1.in-addr.arpa.")

    def test_classB(self):
        self.assertEqual(dns.ptrSoaName("1.2.3.4", "255.255.0.0"), "2.1.in-addr.arpa.")
        self.assertEqual(dns.ptrSoaName("1.2.3.4", "16"), "2.1.in-addr.arpa.")

    def test_classC(self):
        self.assertEqual(
            dns.ptrSoaName("1.2.3.4", "255.255.255.0"), "3.2.1.in-addr.arpa."
        )
        self.assertEqual(dns.ptrSoaName("1.2.3.4", "24"), "3.2.1.in-addr.arpa.")

    def test_CIDR_9(self):
        self.assertEqual(dns.ptrSoaName("1.2.3.4", "9"), "0/9.1.in-addr.arpa.")
        self.assertEqual(dns.ptrSoaName("1.200.3.4", "9"), "128/9.1.in-addr.arpa.")

    def test_CIDR_12(self):
        self.assertEqual(dns.ptrSoaName("1.2.3.4", "12"), "0/12.1.in-addr.arpa.")
        self.assertEqual(dns.ptrSoaName("1.200.3.4", "12"), "192/12.1.in-addr.arpa.")

    def test_CIDR_13(self):
        self.assertEqual(dns.ptrSoaName("1.2.3.4", "13"), "0/13.1.in-addr.arpa.")
        self.assertEqual(dns.ptrSoaName("1.200.3.4", "13"), "200/13.1.in-addr.arpa.")

    def test_CIDR_15(self):
        self.assertEqual(dns.ptrSoaName("1.2.3.4", "15"), "2/15.1.in-addr.arpa.")
        self.assertEqual(dns.ptrSoaName("1.200.3.4", "15"), "200/15.1.in-addr.arpa.")

    def test_CIDR_29(self):
        self.assertEqual(dns.ptrSoaName("1.2.3.4", "29"), "0/29.3.2.1.in-addr.arpa.")

    def test_CIDR_30(self):
        self.assertEqual(dns.ptrSoaName("1.2.3.4", "30"), "4/30.3.2.1.in-addr.arpa.")
