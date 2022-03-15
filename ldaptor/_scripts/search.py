import sys
from ldaptor.protocols.ldap import ldapclient, ldapconnector, ldapsyntax
from ldaptor import config, usage
from twisted.internet import reactor


def printResults(o):
    sys.stdout.write(str(o))


def search(client, baseDN, filter_text, attributes):
    o = ldapsyntax.LDAPEntry(client=client, dn=baseDN)
    d = o.search(filterText=filter_text, attributes=attributes, callback=printResults)
    return d


exitStatus = 0


def error(fail):
    print("fail:", fail.getErrorMessage(), file=sys.stderr)
    global exitStatus
    exitStatus = 1


def main(cfg, filter_text, attributes):
    try:
        baseDN = cfg.getBaseDN()
    except config.MissingBaseDNError as e:
        print(f"{sys.argv[0]}: {e}.", file=sys.stderr)
        sys.exit(1)

    c = ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
    d = c.connectAnonymously(dn=baseDN, overrides=cfg.getServiceLocationOverrides())
    d.addCallback(search, baseDN, filter_text, attributes)
    d.addErrback(error)
    d.addBoth(lambda x: reactor.stop())

    reactor.run()
    sys.exit(exitStatus)


class MyOptions(
    usage.Options, usage.Options_service_location, usage.Options_base_optional
):
    """LDAPtor command line search utility"""

    def parseArgs(self, filter, *attributes):
        self.opts["filter"] = filter
        self.opts["attributes"] = attributes


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
    main(cfg, opts["filter"], opts["attributes"])


if __name__ == "__main__":
    sys.exit(console_script())
