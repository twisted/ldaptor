from ldaptor.protocols.ldap import ldapclient, ldapconnector, ldapsyntax
from ldaptor.protocols import pureber, pureldap
from ldaptor import usage, ldapfilter, config, dns
import os
import sys
from twisted.internet import reactor


def formatIPAddress(name, ip):
    return f"{name}\tIN A\t{ip}\n"


def formatPTR(name, ip):
    octets = ip.split(".")
    octets.reverse()
    octets.append("in-addr.arpa.")
    return "{}\tIN PTR\t{}.\n".format(".".join(octets), name)


class HostIPAddress:
    def __init__(self, host, ipAddress):
        self.host = host
        self.ipAddress = ipAddress

    def getForward(self, domain):
        return (";  %s\n" % self.host.dn) + formatIPAddress(
            self.host.name + "." + domain, self.ipAddress
        )

    def getReverse(self, domain):
        return (";  %s\n" % self.host.dn) + formatPTR(
            self.host.name + "." + domain, self.ipAddress
        )

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
    reverseZone = None

    def __init__(self, dn, name, address, mask):
        self.dn = dn
        self.name = name
        self.address = address
        self.mask = mask

    def isInNet(self, ipAddress):
        try:
            net = dns.aton(self.address)
            mask = dns.aton(self.mask)
            ip = dns.aton(ipAddress)
        except OSError:
            # no need to log here, higher levels will log a warning
            # when they see the address is in no net
            return False
        if ip & mask == net:
            return True
        return False

    def getForward(self):
        ip = dns.aton(self.address)
        mask = dns.aton(self.mask)
        ipmask = dns.ntoa(mask)
        broadcast = dns.ntoa(ip | ~mask)

        return (
            ("; %s\n" % self.dn)
            + formatIPAddress(self.name, self.address)
            + formatIPAddress("netmask." + self.name, ipmask)
            + formatIPAddress("broadcast." + self.name, broadcast)
        )

    def getReverse(self, domain):
        ip = dns.aton(self.address)
        mask = dns.aton(self.mask)
        broadcast = dns.ntoa(ip | ~mask)

        return (
            ("; %s\n" % self.dn)
            + formatPTR(self.name + "." + domain, self.address)
            + formatPTR("broadcast." + self.name + "." + domain, broadcast)
        )

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


def getNets(e, domain, forward, reverse, filter):
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

    def _cbGotNets(nets, forward, reverse):
        r = []
        for e in nets:
            net = Net(
                str(e.dn),
                str(only(e, "cn")),
                str(only(e, "ipNetworkNumber")),
                str(only(e, "ipNetmaskNumber")),
            )
            print(net.getForward(), file=forward)

            for data in reverse:
                ip = dns.aton(net.address)
                if ip & data["netmask"] == data["address"]:
                    if "file" not in data:
                        data["tempname"] = "%s.%d.tmp" % (data["filename"], os.getpid())
                        data["file"] = open(data["tempname"], "w")
                    print(net.getReverse(domain), file=data["file"])
                    net.reverseZone = data
            r.append(net)
        return r

    d.addCallback(_cbGotNets, forward, reverse)
    return d


def getHosts(nets, e, domain, forward, reverse, filter):
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
                print(hostIP.getForward(parent.name), file=forward)
                if parent.reverseZone:
                    print(
                        hostIP.getReverse(parent.name + "." + domain),
                        file=parent.reverseZone["file"],
                    )
                else:
                    print("Not writing PTR for %s." % hostIP, file=sys.stderr)
            else:
                sys.stderr.write("IP address %s is in no net, discarding.\n" % hostIP)

    d = e.search(
        filterObject=filt, attributes=["ipHostNumber", "cn"], callback=_cbGotHost
    )
    return d


def cbConnected(client, cfg, domain, forward, reverse, filter):
    e = ldapsyntax.LDAPEntryWithClient(client, cfg.getBaseDN())
    d = getNets(e, domain, forward, reverse, filter)
    d.addCallback(getHosts, e, domain, forward, reverse, filter)

    def unbind(r, e):
        e.client.unbind()
        return r

    d.addCallback(unbind, e)
    return d


def filesOk(result, forward, forwardTmp, forwardFile, reverse):
    forwardFile.close()
    os.rename(forwardTmp, forward)
    for data in reverse:
        if "file" in data:
            data["file"].close()
            del data["file"]
        if "tempname" in data:
            os.rename(data["tempname"], data["filename"])
            del data["tempname"]
    return result


def filesAbort(reason, forward, forwardTmp, forwardFile, reverse):
    forwardFile.close()
    os.unlink(forwardTmp)
    for data in reverse:
        if "file" in data:
            data["file"].close()
        if "tempname" in data:
            os.unlink(data["tempname"])
    return reason


def main(cfg, domain, forward, reverse, filter_text):
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

    forwardTmp = "%s.%d.tmp" % (forward, os.getpid())
    forwardFile = open(forwardTmp, "w")

    print("$ORIGIN\t%s." % domain, file=forwardFile)
    print(file=forwardFile)

    c = ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
    d = c.connectAnonymously(baseDN, overrides=cfg.getServiceLocationOverrides())
    d.addCallback(cbConnected, cfg, domain, forwardFile, reverse, filt)
    d.addCallbacks(
        callback=filesOk,
        callbackArgs=(forward, forwardTmp, forwardFile, reverse),
        errback=filesAbort,
        errbackArgs=(forward, forwardTmp, forwardFile, reverse),
    )
    d.addErrback(error)
    d.addBoth(lambda x: reactor.stop())

    reactor.run()
    sys.exit(exitStatus)


class MyOptions(
    usage.Options, usage.Options_service_location, usage.Options_base_optional
):
    """LDAPtor DNS zone file exporter"""

    synopsis = "Usage: %s [OPTION..] DOMAIN OUTPUTFILE [FILTER]" % sys.argv[0]

    def opt_reverse(self, net_file):
        """Write out reverse zone, in the form ADDRESS/NETMASK:FILE"""
        if ":" not in net_file:
            raise usage.UsageError("--reverse= value must contain semicolon")
        addr_nm, filename = net_file.split(":", 1)

        if "/" not in addr_nm:
            raise usage.UsageError("--reverse= value must have netmask")
        addressString, netmaskString = addr_nm.split("/", 1)

        try:
            address = dns.aton(addressString)
        except OSError as e:
            raise usage.UsageError("--reverse= address is invalid: %s" % e)

        try:
            netmask = dns.aton(netmaskString)
        except OSError as e:
            raise usage.UsageError("--reverse= netmask is invalid: %s" % e)

        self.opts.setdefault("reverse", []).append(
            {
                "address": address,
                "netmask": netmask,
                "filename": filename,
            }
        )

    def parseArgs(self, domain, forward, filter=None):
        self.opts["domain"] = domain
        self.opts["forward"] = forward
        self.opts["filter"] = filter


def console_script():
    import sys

    try:
        opts = MyOptions()
        opts.parseOptions()
    except usage.UsageError as ue:
        sys.stderr.write(f"{sys.argv[0]}: {ue}\n")
        sys.exit(1)

    cfg = config.LDAPConfig(
        baseDN=opts["base"], serviceLocationOverrides=opts["service-location"]
    )
    main(cfg, opts["domain"], opts["forward"], opts["reverse"], opts["filter"])


if __name__ == "__main__":
    sys.exit(console_script())
