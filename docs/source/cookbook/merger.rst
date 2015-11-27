===========
LDAP Merger
===========

A merger forwards search requests to multiple LDAP Servers, and returns
the result entries of each successful response.

-------
Usecase
-------

You have multiple LDAP Servers, and you want to combine the search results
of all of them. This can be the case if you have an application
which needs extra users which are not inside the LDAP directory of your enterprise server,
and it is not desired to store them in it. In this case you could use an internal
LDAP server on the local filesystem (you can also do this with ldaptor, please
look at the LDAP Servers section, File-System LDAP DIT),
and combine this server with your general LDAP server.

-------
Caveats
-------

Be aware that it the merger is a read-only implementation: only BIND and SEARCH
operations are supported. Beyond that, notice that when binding only the servers
where the bind has been successful are delivering search results. So in order to retrieve
results on all servers, the bind user must be available on all LDAP servers. 

-----
Usage
-----

''''
Code
''''

Store the python code in a file called ldap-merger.tac:

.. code-block:: python

    #! /usr/bin/env python

    from twisted.application import service, internet
    from twisted.internet import protocol
    from ldaptor.config import LDAPConfig
    from ldaptor.protocols.ldap.merger import MergedLDAPServer

    application = service.Application("LDAP Merger")

    configs = [LDAPConfig(serviceLocationOverrides={"": ('external', 389)}),
               LDAPConfig(serviceLocationOverrides={"": ('localhost', 38942)})]
    use_tls = [True, False]
    factory = protocol.ServerFactory()
    factory.protocol = lambda: MergedLDAPServer(configs, use_tls)
    mergeService = internet.TCPServer(389, factory)
    mergeService.setServiceParent(application)


''''''''''
Discussion
''''''''''
We use two ldap servers: one listening on the host ''external'' on the
default port 389, and the other is a server running on localhost with port 38942.
TLS is used for the connection to the external server. The merger itself listens
on port 389.

Run it with
    $ twistd -y ldap-merger.tac
