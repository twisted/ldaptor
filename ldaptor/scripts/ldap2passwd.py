import sys
from ldaptor.protocols.ldap import ldapclient, ldapconnector, ldapsyntax
from ldaptor.protocols import pureldap
from ldaptor import usage, ldapfilter, config
from twisted.internet import reactor


def _cbSearch(obj):
    a = {}
    for attr, vals in obj.items():
        attr = str(attr)
        assert attr not in a
        a[attr] = list(str(val) for val in vals)

    print(
        ":".join(
            (
                a["uid"][0],
                "x",
                a["uidNumber"][0],
                a["gidNumber"][0],
                a.get("gecos", a.get("cn", [""]))[0],
                a["homeDirectory"][0],
                a.get("loginShell", [""])[0],
            )
        )
    )


def search(client, baseDN, filt):
    e = ldapsyntax.LDAPEntry(client=client, dn=baseDN)
    d = e.search(
        filterObject=filt,
        attributes=[
            "uid",
            "uidNumber",
            "gidNumber",
            "gecos",
            "cn",
            "homeDirectory",
            "loginShell",
        ],
        callback=_cbSearch,
    )
    return d


exitStatus = 0


def error(fail):
    print("fail:", fail.getErrorMessage(), file=sys.stderr)
    global exitStatus
    exitStatus = 1


def main(cfg, filter_text):
    try:
        baseDN = cfg.getBaseDN()
    except config.MissingBaseDNError as e:
        print("{}: {}.".format(sys.argv[0], e), file=sys.stderr)
        sys.exit(1)

    filt = ldapfilter.parseFilter("(objectClass=posixAccount)")
    if filter_text is not None:
        filt = pureldap.LDAPFilter_and([filt, ldapfilter.parseFilter(filter_text)])

    c = ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
    d = c.connectAnonymously(dn=baseDN, overrides=cfg.getServiceLocationOverrides())
    d.addCallback(search, baseDN, filt)
    d.addErrback(error)
    d.addBoth(lambda x: reactor.stop())

    reactor.run()
    sys.exit(exitStatus)


class MyOptions(
    usage.Options, usage.Options_service_location, usage.Options_base_optional
):
    """LDAPtor command line search utility"""

    def parseArgs(self, filter=None):
        self.opts["filter"] = filter


def console_script():
    try:
        opts = MyOptions()
        opts.parseOptions()
    except usage.usage.UsageError as ue:
        sys.stderr.write("{}: {}\n".format(sys.argv[0], ue))
        sys.exit(1)

    cfg = config.LDAPConfig(
        baseDN=opts["base"], serviceLocationOverrides=opts["service-location"]
    )
    main(cfg, opts["filter"])


if __name__ == "__main__":
    sys.exit(console_script())
