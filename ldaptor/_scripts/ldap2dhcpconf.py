# host fantasia {
#  dhcp-client-identifier
#  hardware ethernet 08:00:07:26:c0:a5;
#  fixed-address fantasia.fugue.com;
# }

# subnet 1.2.3.0 netmask 255.255.255.0 {
#  option routers 1.2.3.4;
#  range 1.2.3.100 1.2.3.200;
#  option domain-name "foo.bar.example.com";
# }

# shared-network "foo" {
# }
import sys
from ldaptor.protocols.ldap import ldapclient, ldapconnector, ldapsyntax
from ldaptor.protocols import pureber, pureldap
from ldaptor import usage, ldapfilter, config
from twisted.internet import reactor
from socket import inet_aton, inet_ntoa
import struct


def my_aton_octets(ip):
    (n,) = struct.unpack("!I", inet_aton(ip))
    return n


def my_aton_numbits(num):
    n = 0
    while num > 0:
        n >>= 1
        n |= 2 ** 31
        num -= 1
    return n


def my_aton(ip):
    try:
        i = int(ip)
    except ValueError:
        return my_aton_octets(ip)
    else:
        return my_aton_numbits(i)


def my_ntoa(n):
    s = struct.pack("!I", n)
    ip = inet_ntoa(s)
    return ip


class HostIPAddress:
    def __init__(self, host, ipAddress):
        self.host = host
        self.ipAddress = ipAddress

    def printDHCP(self, domain, prefix=""):
        def output():
            yield "# %s" % self.host.dn
            yield f"host {self.host.name}.{domain} {{"
            for mac in self.host.macAddresses:
                yield "\thardware ethernet %s;" % mac
            yield "\tfixed-address %s;" % self.ipAddress
            if self.host.bootFile is not None:
                # TODO quote bootFile
                yield '\tfilename "%s";' % self.host.bootFile
            yield "}"

        print("\n".join([prefix + line for line in output()]))

    def __repr__(self):
        return (
            self.__class__.__name__
            + "("
            + "host=%s, " % id(self.host)
            + "ipAddress=%s" % repr(self.ipAddress)
            + ")"
        )


class Group:
    def __init__(self, dn, bootFile=None):
        self.dn = dn
        self.bootFile = bootFile
        self.hosts = set()

    def addHost(self, host):
        if host.group is not None:
            print(
                (
                    "Host {} is in two groups: {!r} and {!r}".format(
                        host.dn, host.group, self
                    )
                ),
                file=sys.stderr,
            )
        else:
            host.group = self
            self.hosts.add(host)

    def printDHCP(self, domain, addrs, prefix=""):
        addresses = {addr for host in self.hosts for addr in host.ipAddresses}
        addresses.intersection_update(addrs)
        addrs.difference_update(addresses)

        if addresses:
            print(prefix + "# " + str(self.dn))
            print(prefix + "group {")

            if self.bootFile is not None:
                # TODO quote bootFile
                print(prefix + '\tfilename "%s";' % self.bootFile)

            for addr in addresses:
                addr.printDHCP(domain, prefix=prefix + "\t")

            print(prefix + "}")


class Host:
    group = None

    def __init__(self, dn, name, ipAddresses, macAddresses=(), bootFile=None):
        self.dn = dn
        self.name = name
        self.ipAddresses = [HostIPAddress(self, ip) for ip in ipAddresses]
        self.macAddresses = macAddresses
        self.bootFile = bootFile

    def __repr__(self):
        return (
            self.__class__.__name__
            + "("
            + "dn=%s, " % repr(self.dn)
            + "name=%s, " % repr(self.name)
            + "ipAddresses=%s, " % repr(self.ipAddresses)
            + "macAddresses=%s, " % repr(self.macAddresses)
            + "bootFile=%s" % repr(self.bootFile)
            + ")"
        )


class Net:
    def __init__(
        self,
        dn,
        name,
        address,
        mask,
        routers=(),
        dhcpRanges=(),
        winsServers=(),
        domainNameServers=(),
    ):
        self.dn = dn
        self.name = name
        self.address = address
        self.mask = mask
        self.routers = routers
        self.dhcpRanges = dhcpRanges
        self.winsServers = winsServers
        self.domainNameServers = domainNameServers
        self.hosts = []

    def isInNet(self, ipAddress):
        net = my_aton(self.address)
        mask = my_aton(self.mask)
        ip = my_aton(ipAddress)
        if ip & mask == net:
            return 1
        return 0

    def addHost(self, host):
        assert self.isInNet(host.ipAddress)
        self.hosts.append(host)

    def printDHCP(self, domain, prefix=""):
        nm = self.mask
        nm = my_aton(nm)
        nm = my_ntoa(nm)
        r = [
            "# %s" % self.dn,
            f"subnet {self.address} netmask {nm} {{",
            f'\toption domain-name "{self.name}.{domain}";',
        ]
        if self.routers:
            r.append("\toption routers %s;" % (", ".join(self.routers)))
        for dhcpRange in self.dhcpRanges:
            r.append("\trange %s;" % dhcpRange)
        if self.winsServers:
            r.append(
                "\toption netbios-name-servers %s;" % (", ".join(self.winsServers))
            )
        if self.domainNameServers:
            r.append(
                "\toption domain-name-servers %s;" % (", ".join(self.domainNameServers))
            )
        r.append("}")

        print("\n".join([prefix + line for line in r]))

        addrs = set(self.hosts)

        for addr in self.hosts:
            g = addr.host.group
            if g is not None:
                g.printDHCP(self.name + "." + domain, addrs, prefix=prefix)

        while addrs:
            addr = addrs.pop()
            addr.printDHCP(self.name + "." + domain, prefix=prefix)

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


class SharedNet:
    def __init__(self, name):
        self.name = name
        self.nets = []

    def addNet(self, net):
        self.nets.append(net)

    def printDHCP(self, domain):
        print('shared-network "%s" {' % self.name)
        for net in self.nets:
            net.printDHCP(domain, prefix="\t")
        print("}")
        print()


def _cbGetGroups(entries, hosts):
    dnToHost = {}
    for host in hosts:
        assert host.dn not in dnToHost
        dnToHost[host.dn] = host

    for e in entries:
        group = Group(dn=e.dn, bootFile=only(e, "bootFile", None))

        for member in e.get("member", []):
            host = dnToHost.get(member, None)
            if host is not None:
                group.addHost(host)

    return hosts


def getGroups(hosts, e, filter):
    """Add group info to hosts."""

    def buildFilter(hosts):
        for host in hosts:
            f = pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription("member"),
                assertionValue=pureber.BEROctetString(str(host.dn)),
            )
            yield f

    filt = pureldap.LDAPFilter_and(
        value=(
            # the only reason we do groups is for the bootFile,
            # so require one to be present
            pureldap.LDAPFilter_present("bootFile"),
            pureldap.LDAPFilter_or(value=list(buildFilter(hosts))),
        )
    )
    if filter:
        filt = pureldap.LDAPFilter_and(value=(filter, filt))

    d = e.search(filterObject=filt, attributes=["member", "bootFile"])

    d.addCallback(_cbGetGroups, hosts)
    return d


def haveHosts(hosts, e, filt, nets, sharedNets, dnsDomain):
    d = getGroups(hosts, e, filt)
    d.addCallback(haveGroups, nets, sharedNets, dnsDomain)
    return d


def haveGroups(hosts, nets, sharedNets, dnsDomain):
    for host in hosts:
        for hostIP in host.ipAddresses:
            parent = None
            for net in nets + list(
                net_ for x in sharedNets.values() for net_ in x.nets
            ):
                if net.isInNet(hostIP.ipAddress):
                    parent = net
                    break

            if parent:
                parent.addHost(hostIP)
            else:
                sys.stderr.write("IP address %s is in no net, discarding.\n" % hostIP)

    for net in sharedNets.values():
        net.printDHCP(dnsDomain)
    for net in nets:
        net.printDHCP(dnsDomain)


class _NO_DEFAULT:
    pass


def only(e, attr, default=_NO_DEFAULT):
    val = e.get(attr, _NO_DEFAULT)
    if val is _NO_DEFAULT:
        if default is not _NO_DEFAULT:
            return default
        else:
            raise RuntimeError(f"object {e.dn} does not have attribute {attr!r}.")
    else:
        if len(val) != 1:
            raise RuntimeError(
                "object {} attribute {!r} has multiple values: {}".format(
                    e.dn, attr, val
                )
            )
        for item in val:
            return item


def _cbGetHosts(entries):
    hosts = []
    for e in entries:
        cn = only(e, "cn")
        hosts.append(
            Host(
                str(e.dn),
                str(cn),
                list(str(i) for i in e["ipHostNumber"]),
                tuple(str(i) for i in e.get("macAddress", ())),
                bootFile=only(e, "bootFile", default=None),
            )
        )
    return hosts


def getHosts(e, filter):
    filt = pureldap.LDAPFilter_and(
        value=(
            pureldap.LDAPFilter_present("cn"),
            pureldap.LDAPFilter_present("ipHostNumber"),
        )
    )
    if filter:
        filt = pureldap.LDAPFilter_and(value=(filter, filt))

    d = e.search(
        filterObject=filt,
        attributes=[
            "cn",
            "ipHostNumber",
            "macAddress",
            "bootFile",
        ],
    )
    d.addCallback(_cbGetHosts)
    return d


def haveNets(data, e, baseDN, filt, dnsDomain):
    nets, sharedNets = data
    d = getHosts(e, filt)
    d.addCallback(haveHosts, e, filt, nets, sharedNets, dnsDomain)
    return d


def _cbGetNets(entries):
    sharedNetworks = {}
    nets = []

    for e in entries:
        cn = only(e, "cn")
        ipNetworkNumber = only(e, "ipNetworkNumber")
        ipNetmaskNumber = only(e, "ipNetmaskNumber")
        net = Net(
            e.dn,
            cn,
            ipNetworkNumber,
            ipNetmaskNumber,
            routers=e.get("router", ()),
            dhcpRanges=e.get("dhcpRange", ()),
            winsServers=e.get("winsServer", ()),
            domainNameServers=e.get("domainNameServer", ()),
        )
        if "sharedNetworkName" in e:
            name = only(e, "sharedNetworkName")
            if name not in sharedNetworks:
                sharedNetworks[name] = SharedNet(name)
            sharedNetworks[name].addNet(net)
        else:
            nets.append(net)

    return (nets, sharedNetworks)


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
            "router",
            "dhcpRange",
            "winsServer",
            "domainNameServer",
            "sharedNetworkName",
        ],
    )
    d.addCallback(_cbGetNets)
    return d


def search(client, baseDN, filter, dnsDomain):
    e = ldapsyntax.LDAPEntry(client=client, dn=baseDN)
    d = getNets(e, filter)
    d.addCallback(haveNets, e, baseDN, filter, dnsDomain)
    return d


exitStatus = 0


def error(fail):
    print("fail:", fail.getErrorMessage(), file=sys.stderr)
    global exitStatus
    exitStatus = 1


def main(cfg, filter_text, dnsDomain):
    try:
        baseDN = cfg.getBaseDN()
    except config.MissingBaseDNError as e:
        print(f"{sys.argv[0]}: {e}.", file=sys.stderr)
        sys.exit(1)

    from twisted.python import log

    log.startLogging(sys.stderr, setStdout=0)

    if filter_text is not None:
        filt = ldapfilter.parseFilter(filter_text)
    else:
        filt = None

    c = ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
    d = c.connectAnonymously(dn=baseDN, overrides=cfg.getServiceLocationOverrides())
    d.addCallback(search, baseDN, filt, dnsDomain)
    d.addErrback(error)
    d.addBoth(lambda x: reactor.stop())

    reactor.run()
    sys.exit(exitStatus)


class MyOptions(
    usage.Options, usage.Options_service_location, usage.Options_base_optional
):
    """LDAPtor dhcpd config file exporter"""

    optParameters = (("dns-domain", None, "example.com", "DNS domain name"),)

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
    main(
        cfg,
        opts["filter"],
        opts["dns-domain"],
    )


if __name__ == "__main__":
    sys.exit(console_script())
