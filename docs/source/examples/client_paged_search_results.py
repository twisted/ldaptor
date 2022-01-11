#! /usr/bin/env python

import argparse
import sys

from twisted.internet import defer
from twisted.internet.endpoints import clientFromString, connectProtocol
from twisted.internet.task import react
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry
from ldaptor.protocols import pureber


@defer.inlineCallbacks
def onConnect(client, args):
    binddn = args.bind_dn
    bindpw = args.passwd_file.read().strip()
    if args.start_tls:
        yield client.startTLS()
    try:
        yield client.bind(binddn, bindpw)
    except Exception as ex:
        print(ex)
        raise
    page_size = args.page_size
    cookie = ""
    page = 1
    count = 0
    while True:
        results, cookie = yield process_entry(
            client, args, args.filter, page_size=page_size, cookie=cookie
        )
        count += len(results)
        print(f"Page {page}")
        display_results(results)
        if len(cookie) == 0:
            break
        page += 1
    print(f"There were {count} results returned in total.")


@defer.inlineCallbacks
def process_entry(client, args, search_filter, page_size=100, cookie=""):
    basedn = args.base_dn
    control_value = pureber.BERSequence(
        [
            pureber.BERInteger(page_size),
            pureber.BEROctetString(cookie),
        ]
    )
    controls = [("1.2.840.113556.1.4.319", None, control_value)]
    o = LDAPEntry(client, basedn)
    results, resp_controls = yield o.search(
        filterText=search_filter,
        attributes=["dn"],
        controls=controls,
        return_controls=True,
    )
    cookie = get_paged_search_cookie(resp_controls)
    defer.returnValue((results, cookie))


def display_results(results):
    for entry in results:
        print(entry.dn.getText())


def get_paged_search_cookie(controls):
    """
    Input: semi-parsed controls list from LDAP response;
    list of tuples (controlType, criticality, controlValue).
    Parses the controlValue and returns the cookie as a byte string.
    """
    control_value = controls[0][2]
    ber_context = pureber.BERDecoderContext()
    ber_seq, bytes_used = pureber.berDecodeObject(ber_context, control_value)
    raw_cookie = ber_seq[1]
    cookie = raw_cookie.value
    return cookie


def onError(err):
    err.printDetailedTraceback(file=sys.stderr)


def main(reactor, args):
    endpoint_str = args.endpoint
    e = clientFromString(reactor, endpoint_str)
    d = connectProtocol(e, LDAPClient())
    d.addCallback(onConnect, args)
    d.addErrback(onError)
    return d


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AD LDAP demo.")
    parser.add_argument(
        "endpoint",
        action="store",
        help="The Active Directory service endpoint. See "
        "https://twistedmatrix.com/documents/current/core/howto/endpoints.html#clients",
    )
    parser.add_argument(
        "bind_dn", action="store", help="The DN to BIND to the service as."
    )
    parser.add_argument(
        "passwd_file",
        action="store",
        type=argparse.FileType("r"),
        help="A file containing the password used to log into the service.",
    )
    parser.add_argument(
        "base_dn", action="store", help="The base DN to start from when searching."
    )
    parser.add_argument("-f", "--filter", action="store", help="LDAP filter")
    parser.add_argument(
        "-p",
        "--page-size",
        type=int,
        action="store",
        default=100,
        help="Page size (default 100).",
    )
    parser.add_argument(
        "--start-tls",
        action="store_true",
        help="Request StartTLS after connecting to the service.",
    )
    args = parser.parse_args()
    react(main, [args])
