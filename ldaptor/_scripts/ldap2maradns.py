from ldaptor.protocols.ldap import ldapclient, ldapconnector, ldapsyntax
from ldaptor.protocols import pureber, pureldap
from ldaptor import usage, ldapfilter, config, dns
import sys
from twisted.internet import reactor


def printIPAddress(name, ip):
    print("A" + name + ".%|86400|" + ip)


def printPTR(name, ip):
    octets = ip.split(".")
    octets.reverse()
    octets.append("in-addr.arpa.")
    print("P" + (".".join(octets)) + "|86400|" + name + ".%")


class HostIPAddress:
    def __init__(self, host, ipAddress):
        self.host = host
        self.ipAddress = ipAddress

    def printZone(self, domain):
        print("#  " + self.host.dn)
        printIPAddress(self.host.name + "." + domain, self.ipAddress)
        printPTR(self.host.name + "." + domain, self.ipAddress)

    def __repr__(self):
        return (
            self.__class__.__name__
            + "("
            + "host=%r, " % self.host.name
            + "ipAddress=%s" % repr(self.ipAddress)
            + ")"
        )


class Host:
    def __init__(self, dn, name, ipAddresses):
        self.dn = dn
        self.name = name
        self.ipAddresses = [HostIPAddress(self, ip) for ip in ipAddresses]

    def __repr__(self):
        return (
            self.__class__.__name__
            + "("
            + "dn=%s, " % repr(self.dn)
            + "name=%s, " % repr(self.name)
            + "ipAddresses=%s" % repr(self.ipAddresses)
            + ")"
        )


class Net:
    def __init__(self, dn, name, address, mask):
        self.dn = dn
        self.name = name
        self.address = address
        self.mask = mask

    def isInNet(self, ipAddress):
        net = dns.aton(self.address)
        mask = dns.aton(self.mask)
        ip = dns.aton(ipAddress)
        if ip & mask == net:
            return 1
        return 0

    def printZone(self):
        print("#" + self.dn)
        printIPAddress(self.name, self.address)
        printPTR(self.name, self.address)
        ip = dns.aton(self.address)
        mask = dns.aton(self.mask)
        ipmask = dns.ntoa(mask)
        broadcast = dns.ntoa(ip | ~mask)
        printIPAddress("netmask." + self.name, ipmask)
        printIPAddress("broadcast." + self.name, broadcast)
        printPTR("broadcast." + self.name, broadcast)

    def __repr__(self):
        return (
            self.__class__.__name__
            + "("
            + "dn=%s, " % repr(self.dn)
            + "name=%s, " % repr(self.name)
            + "address=%s, " % repr(self.address)
            + "mask=%s" % repr(self.mask)
            + ")"
        )


exitStatus = 0


def error(fail):
    print("fail:", str(fail), file=sys.stderr)  # .getErrorMessage()
    global exitStatus
    exitStatus = 1


def only(e, attrName):
    assert (
        len(e[attrName]) == 1
    ), "object {} attribute {!r} has multiple values: {}".format(
        e.dn,
        attrName,
        e[attrName],
    )
    for val in e[attrName]:
        return val


def getNets(e, filter):
    filt = pureldap.LDAPFilter_and(
        value=(
            pureldap.LDAPFilter_present("cn"),
            pureldap.LDAPFilter_present("ipNetworkNumber"),
            pureldap.LDAPFilter_present("ipNetmaskNumber"),
        )
    )
    if filter:
        filt = pureldap.LDAPFilter_and(value=(filter, filt))
    d = e.search(
        filterObject=filt,
        attributes=[
            "cn",
            "ipNetworkNumber",
            "ipNetmaskNumber",
        ],
    )

    def _cbGotNets(nets):
        r = []
        for e in nets:
            net = Net(
                str(e.dn),
                str(only(e, "cn")),
                str(only(e, "ipNetworkNumber")),
                str(only(e, "ipNetmaskNumber")),
            )
            net.printZone()
            r.append(net)
        return r

    d.addCallback(_cbGotNets)
    return d


def getHosts(nets, e, filter):
    filt = pureldap.LDAPFilter_equalityMatch(
        attributeDesc=pureldap.LDAPAttributeDescription("objectClass"),
        assertionValue=pureber.BEROctetString("ipHost"),
    )
    if filter:
        filt = pureldap.LDAPFilter_and(value=(filter, filt))

    def _cbGotHost(e):
        host = Host(
            str(e.dn), str(only(e, "cn")), list(str(i) for i in e["ipHostNumber"])
        )
        for hostIP in host.ipAddresses:
            parent = None
            for net in nets:
                if net.isInNet(hostIP.ipAddress):
                    parent = net
                    break

            if parent:
                hostIP.printZone(parent.name)
            else:
                sys.stderr.write("IP address %s is in no net, discarding.\n" % hostIP)

    d = e.search(
        filterObject=filt, attributes=["ipHostNumber", "cn"], callback=_cbGotHost
    )
    return d


def cbConnected(client, cfg, filter):
    e = ldapsyntax.LDAPEntryWithClient(client, cfg.getBaseDN())
    d = getNets(e, filter)
    d.addCallback(getHosts, e, filter)

    def unbind(r, e):
        e.client.unbind()
        return r

    d.addCallback(unbind, e)
    return d


def main(cfg, filter_text):
    from twisted.python import log

    log.startLogging(sys.stderr, setStdout=0)

    try:
        baseDN = cfg.getBaseDN()
    except config.MissingBaseDNError as e:
        print(f"{sys.argv[0]}: {e}.", file=sys.stderr)
        sys.exit(1)

    if filter_text is not None:
        filt = ldapfilter.parseFilter(filter_text)
    else:
        filt = None

    c = ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
    d = c.connectAnonymously(baseDN, overrides=cfg.getServiceLocationOverrides())
    d.addCallback(cbConnected, cfg, filt)
    d.addErrback(error)
    d.addBoth(lambda x: reactor.stop())

    reactor.run()
    sys.exit(exitStatus)


class MyOptions(
    usage.Options, usage.Options_service_location, usage.Options_base_optional
):
    """LDAPtor maradns zone file exporter"""

    def parseArgs(self, filter=None):
        self.opts["filter"] = filter


def console_script():
    try:
        opts = MyOptions()
        opts.parseOptions()
    except usage.UsageError as ue:
        sys.stderr.write(f"{sys.argv[0]}: {ue}\n")
        sys.exit(1)

    cfg = config.LDAPConfig(
        baseDN=opts["base"], serviceLocationOverrides=opts["service-location"]
    )
    main(cfg, opts["filter"])


if __name__ == "__main__":
    sys.exit(console_script())
