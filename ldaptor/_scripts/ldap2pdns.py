import sys
from twisted.internet.defer import succeed, fail
from twisted.internet import defer, reactor
from twisted.internet.stdio import StandardIO
from twisted.protocols.basic import LineReceiver
from twisted.python.failure import Failure
from twisted.python import log
from ldaptor.protocols.ldap import ldapclient, ldapconnector
from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry
from ldaptor import usage, config


class ExitSentinel:
    pass


class TooMuchQueued(Exception):
    """Too many requests queued already waiting for server"""

    def __str__(self):
        return self.__doc__


class PdnsPipeProtocol(LineReceiver):
    delimiter = "\n"
    state = "start"

    ldapEntry = None
    ldapEntryFetchInProgress = False

    MAX_WAIT_QUEUE = 10

    def __init__(self, ldapEntryFactory, dnsDomain):
        self.work = []
        self.ldapEntryFactory = ldapEntryFactory
        self.waitingForLdapEntry = []
        self.dnsDomain = dnsDomain

    def _cbLdapEntry(self, e):
        self.ldapEntryFetchInProgress = False
        assert self.ldapEntry is None
        self.ldapEntry = e
        while self.waitingForLdapEntry:
            d = self.waitingForLdapEntry.pop(0)
            d.callback(e)

    def _ebLdapEntry(self, reason):
        self.ldapEntryFetchInProgress = False
        waiters, self.waitingForLdapEntry = self.waitingForLdapEntry, []
        for w in waiters:
            w.errback(reason)
        return reason

    def getLdapEntry(self):
        if self.ldapEntry is not None:
            return defer.succeed(self.ldapEntry)
        else:
            if len(self.waitingForLdapEntry) > self.MAX_WAIT_QUEUE:
                raise TooMuchQueued
            d = defer.Deferred()
            self.waitingForLdapEntry.append(d)

            if not self.ldapEntryFetchInProgress:
                self.ldapEntryFetchInProgress = True
                fetch = self.ldapEntryFactory(self)
                fetch.addCallback(self._cbLdapEntry)
                fetch.addErrback(self._ebLdapEntry)
                fetch.addErrback(log.err)

            return d

    def _doWork(self):
        while self.work:
            if isinstance(self.work[0][0], defer.Deferred):
                # end of done items, stop and wait for completions
                break
            else:
                done = self.work.pop(0)

                if done == [ExitSentinel]:
                    # that's it, I'm outtahere
                    assert not self.work
                    reactor.stop()
                else:
                    for line in done:
                        self.sendLine(line)
                    sys.stdout.flush()

    def completed(self, result, who):
        who[:] = result
        self._doWork()

    def failed(self, result, who):
        who[:] = ["LOG\t%s" % line for line in result.getTraceback().splitlines()] + [
            "FAIL"
        ]
        self._doWork()

    def do_start_HELO(self, rest):
        if rest == "1":
            self.state = "main"
            return succeed(["OK\t%s" % sys.argv[0]])
        else:
            return succeed(["FAIL"])

    def _gotA(self, results, qname, qclass, qtype, ident):
        r = []
        for o in results:
            for ip in o.get("ipHostNumber", ()):
                r.append("\t".join(("DATA", qname, qclass, qtype, "3600", ident, ip)))
        r.append("END")
        return r

    def question_A(self, qname, qclass, ident, ipAddress):
        ident = "-1"
        if not qname.endswith("." + self.dnsDomain):
            return succeed(["END"])
        cn = qname[: -len("." + self.dnsDomain)]
        d = self.getLdapEntry()

        def _cb(e):
            d = e.search(
                filterText="(&(cn=%s)(ipHostNumber=*))" % cn,
                attributes=["ipHostNumber"],
            )
            return d

        d.addCallback(_cb)
        d.addCallback(self._gotA, qname, qclass, "A", ident)
        return d

    def question_ANY(self, qname, qclass, ident, ipAddress):
        if qname.endswith(".in-addr.arpa"):
            return self.question_PTR(qname, qclass, ident, ipAddress)
        else:
            return self.question_A(qname, qclass, ident, ipAddress)

    def _gotPTR(self, results, qname, qclass, qtype, ident):
        r = []
        for o in results:
            for cn in o.get("cn", ()):
                r.append(
                    "\t".join(
                        (
                            "DATA",
                            qname,
                            qclass,
                            qtype,
                            "3600",
                            ident,
                            cn + "." + self.dnsDomain + ".",
                        )
                    )
                )
        r.append("END")
        return r

    def question_PTR(self, qname, qclass, ident, ipAddress):
        ident = "-1"
        if not qname.endswith(".in-addr.arpa"):
            return succeed(["END"])

        octets = qname[: -len(".in-addr.arpa")].split(".")
        if len(octets) != 4:
            return succeed(["END"])
        octets.reverse()
        ip = ".".join(octets)
        d = self.getLdapEntry()

        def _cb(e):
            d = e.search(filterText="(ipHostNumber=%s)" % ip, attributes=["cn"])
            return d

        d.addCallback(_cb)
        d.addCallback(self._gotPTR, qname, qclass, "PTR", ident)
        return d

    def do_main_Q(self, rest):
        try:
            qname, qclass, qtype, ident, ipAddress = rest.split("\t", 4)
        except ValueError:
            return succeed(["LOG\tInvalid question: %s" % repr(rest), "END"])
        if qclass != "IN":
            return succeed(["LOG\tInvalid qclass: %s" % repr(qclass), "END"])
        q = getattr(self, "question_" + qtype, None)
        if q:
            return q(qname, qclass, ident, ipAddress)
        else:
            return succeed(["END"])

    def do_main_AXFR(self, rest):
        return succeed(["LOG\tRefusing AXFR", "END"])

    def do_main_PING(self, rest):
        # TODO it's undocumented what I should be saying
        return succeed(["END"])

    def lineReceived(self, line):
        try:
            try:
                type, rest = line.split("\t", 1)
            except ValueError:
                type = line
                rest = ""
            f = getattr(self, "do_" + self.state + "_" + type, None)
            if f:
                d = f(rest)
            else:
                d = succeed(
                    [
                        "LOG\tUnknown command %s in state %s"
                        % (repr(type), self.state),
                        "END",
                    ]
                )
        except BaseException:
            f = Failure()
            d = fail(f)

        l = [d]
        self.work.append(l)
        d.addCallback(self.completed, l)
        d.addErrback(self.failed, l)

    def connectionLost(self, reason=None):
        self.work.append([ExitSentinel])
        self._doWork()

    def lostLDAPClient(self, client):
        assert self.ldapEntry is not None
        assert self.ldapEntry.client is client
        self.ldapEntry = None


exitStatus = 0


def error(fail):
    print("fail:", fail.getErrorMessage(), file=sys.stderr)
    global exitStatus
    exitStatus = 1


class MyLDAPClient(ldapclient.LDAPClient):
    def __init__(self, pdnsProto):
        ldapclient.LDAPClient.__init__(self)
        self.pdnsProto = pdnsProto

    def connectionLost(self, reason):
        ldapclient.LDAPClient.connectionLost(self, reason)
        self.pdnsProto.lostLDAPClient(self)


def main(cfg, dnsDomain):
    try:
        baseDN = cfg.getBaseDN()
    except config.MissingBaseDNError as e:
        print(f"{sys.argv[0]}: {e}.", file=sys.stderr)
        sys.exit(1)

    def ldapEntryFactory(pdnsProto):
        c = ldapconnector.LDAPClientCreator(reactor, MyLDAPClient, pdnsProto=pdnsProto)
        d = c.connectAnonymously(dn=baseDN, overrides=cfg.getServiceLocationOverrides())

        def _cb(client, baseDN):
            e = LDAPEntry(client=client, dn=baseDN)
            return e

        d.addCallback(_cb, baseDN)
        return d

    pdnsPipeProtocol = PdnsPipeProtocol(ldapEntryFactory, dnsDomain)
    reactor.addReader(StandardIO(pdnsPipeProtocol))

    reactor.run()
    sys.exit(exitStatus)


class MyOptions(
    usage.Options, usage.Options_service_location, usage.Options_base_optional
):
    """LDAPtor PDNS pipe backend"""

    optParameters = (("dns-domain", None, "example.com", "DNS domain name"),)


def console_script():
    try:
        opts = MyOptions()
        opts.parseOptions()
    except usage.UsageError as ue:
        sys.stderr.write(f"{sys.argv[0]}: {ue}\n")
        sys.exit(1)

    log.startLogging(sys.stderr, setStdout=0)

    cfg = config.LDAPConfig(
        baseDN=opts["base"], serviceLocationOverrides=opts["service-location"]
    )

    main(cfg, opts["dns-domain"])


if __name__ == "__main__":
    sys.exit(console_script())
if __name__ == "__main__":
    sys.exit(console_script())
