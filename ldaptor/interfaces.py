from twisted.python import components

class ILDAPEntry(components.Interface):
    """

    Pythonic API for LDAP object access and modification.

    >>> o=LDAPEntry(client=ldapclient.LDAPClient(),
    ...     dn='cn=foo,dc=example,dc=com',
    ...     attributes={'anAttribute': ['itsValue', 'secondValue'],
    ...     'onemore': ['aValue'],
    ...     })
    >>> o
    LDAPEntry(dn='cn=foo,dc=example,dc=com', attributes={'anAttribute': ['itsValue', 'secondValue'], 'onemore': ['aValue']})

    """

    def __getitem__(self, key):
        """

        Get all values of an attribute.

        >>> o=LDAPEntry(client=ldapclient.LDAPClient(),
        ...     dn='cn=foo,dc=example,dc=com',
        ...     attributes={'anAttribute': ['itsValue']})
        >>> o['anAttribute']
        ['itsValue']

        """

    def get(self, key, default=None):
        """

        Get all values of an attribute.

        >>> o=LDAPEntry(client=ldapclient.LDAPClient(),
        ...     dn='cn=foo,dc=example,dc=com',
        ...     attributes={'anAttribute': ['itsValue']})
        >>> o.get('anAttribute')
        ['itsValue']
        >>> o.get('foo')
        >>> o.get('foo', [])
        []

        """

    def has_key(self, key):
        """TODO"""

    def __contains__(self, key):
        """TODO"""

    def keys(self):
        """TODO"""

    def items(self):
        """TODO"""

    def __str__(self):
        """

        Stringify as LDIF.

        >>> o=LDAPEntry(client=ldapclient.LDAPClient(),
        ...     dn='cn=foo,dc=example,dc=com',
        ...     attributes={'anAttribute': ['itsValue', 'secondValue'],
        ...     'onemore': ['aValue'],
        ...     })
        >>> # must use rstrip or doctests won't like it due to the empty line
        >>> # you can just say "print o"
        >>> print str(o).rstrip()
        dn: cn=foo,dc=example,dc=com
        anAttribute: itsValue
        anAttribute: secondValue
        onemore: aValue

        """

    def __eq__(self, other):
        """

        Comparison. Only equality is supported.

        >>> client=ldapclient.LDAPClient()
        >>> a=LDAPEntry(client=client,
        ...             dn='dc=example,dc=com')
        >>> b=LDAPEntry(client=client,
        ...             dn='dc=example,dc=com')
        >>> a==b
        1
        >>> c=LDAPEntry(client=ldapclient.LDAPClient(),
        ...             dn='ou=different,dc=example,dc=com')
        >>> a==c
        0

        Comparison does not consider the client of the object.

        >>> anotherClient=ldapclient.LDAPClient()
        >>> d=LDAPEntry(client=anotherClient,
        ...             dn='dc=example,dc=com')
        >>> a==d
        1

        """

    def __ne__(self, other):
        """

        Inequality comparison. See L{__eq__}.

        """

    def __len__(self):
        """TODO"""

    def __nonzero__(self):
        """Always return True"""

    def bind(self, password):
        """
        Try to authenticate with given secret.

        @return: Deferred ILDAPEntry (that is, self).

        @raise ldaperrors.LDAPInvalidCredentials: password was
        incorrect.
        """

class IEditableLDAPEntry(components.Interface):
    """Interface definition for editable LDAP entries."""

    def __setitem__(self, key, value):
        """

        Set values of an attribute. Please use lists. Do not modify
        the lists in place, that's not supported _yet_.

        >>> o=LDAPEntry(client=ldapclient.LDAPClient(),
        ...     dn='cn=foo,dc=example,dc=com',
        ...     attributes={'anAttribute': ['itsValue']})
        >>> o['anAttribute']=['foo', 'bar']
        >>> o['anAttribute']
        ['bar', 'foo']

        """

    def __delitem__(self, key):
        """

        Delete all values of an attribute.

        >>> o=LDAPEntry(client=ldapclient.LDAPClient(),
        ...     dn='cn=foo,dc=example,dc=com',
        ...     attributes={
        ...     'anAttribute': ['itsValue', 'secondValue'],
        ...     'another': ['moreValues'],
        ...     })
        >>> del o['anAttribute']
        >>> o
        LDAPEntry(dn='cn=foo,dc=example,dc=com', attributes={'another': ['moreValues']})

        """

    def undo(self):
        """
        Forget all pending changes.
        """

    def commit(self):
        """
        Send all pending changes to the LDAP server.

        @returns: a Deferred that tells you whether the
        operation succeeded or not. (TODO specify how)
        """

    def move(self, newDN):
        """

        Move the object to a new DN.

        @param newDN: the new DistinguishedName

        @return: A Deferred that will complete when the move is done.

        """

    def delete(self):
        """

        Delete this object from the LDAP server.

        @return: A Deferred that will complete when the delete is done.

        """

    def setPassword(self, newPasswd):
        """

        Set all applicable passwords for this object.

        @param newPasswd: A string containing the new password.

        @return: A Deferred that will complete when the operation is
        done.

        """

class IConnectedLDAPEntry(components.Interface):
    """Interface definition for LDAP entries that are part of a bigger whole."""

    def namingContext(self):
        """

        Return an LDAPEntry for the naming context that contains this object.

        """

    def fetch(self, *attributes):
        """

        Fetch the attributes of this object from the server.

        @param attributes: Attributes to fetch. If none, fetch all
        attributes. Fetched attributes are overwritten, and if
        fetching all attributes, attributes that are not on the server
        are removed.

        @return: A Deferred that will complete when the operation is
        done.

        """

    def search(self,
               filterText=None,
               filterObject=None,
               attributes=(),
               scope=None,
               derefAliases=None,
               sizeLimit=0,
               timeLimit=0,
               typesOnly=0,
               callback=None):
        """

        Perform an LDAP search with this object as the base.

        @param filterText: LDAP search filter as a string.

        @param filterObject: LDAP search filter as LDAPFilter.
        Note if both filterText and filterObject are given, they
        are combined with AND. If neither is given, the search is
        made with a filter that matches everything.

        @param attributes: List of attributes to retrieve for the
        result objects. An empty list and means all.

        @param scope: Whether to recurse into subtrees.

        @param derefAliases: Whether to deref LDAP aliases. TODO write
        better documentation.

        @param sizeLimit: At most how many entries to return. 0 means
        unlimited.

        @param timeLimit: At most how long to use for processing the
        search request. 0 means unlimited.

        @param typesOnly: Whether to return attribute types only, or
        also values.

        @param callback: Callback function to call for each resulting
        LDAPEntry. None means gather the results into a list and give
        that to the Deferred returned from here.

        @return: A Deferred that will complete when the search is
        done. The Deferred gives None if callback was given and a list
        of the search results if callback is not given or is None.

        """

    def children(self, callback=None):
        """

        List the direct children of this entry. Try to avoid using
        .search(), as this will be used later to implement .search()
        on LDAP backends.

        @param callback: Callback function to call for each resulting
        LDAPEntry. None means gather the results into a list and give
        that to the Deferred returned from here.

        @return: A Deferred that will complete when the list is
        over. The Deferred gives None if callback was given and a list
        of the children if callback is not given or is None.

        """

    def subtree(self, callback=None):
        """

        List the subtree rooted at this entry, including this
        entry. Try to avoid using .search(), as this will be used
        later to implement .search() on LDAP backends.

        @param callback: Callback function to call for each resulting
        LDAPEntry. None means gather the results into a list and give
        that to the Deferred returned from here.

        @return: A Deferred that will complete when the list is
        over. The Deferred gives None if callback was given and a list
        of the children if callback is not given or is None.

        """

    def lookup(self, dn):
        """
        Lookup the referred to by dn.

        @return: A Deferred returning an ILDAPEntry, or failing with e.g.
        LDAPNoSuchObject.
        """

    def match(self, filter):
        """

        Does entry match filter.

        @param filter: An LDAPFilter (e.g. LDAPFilter_present,
        LDAPFilter_equalityMatch etc. TODO provide an interface or
        superclass for filters.)

        @return: Boolean.

        """

class ILDAPConfig(components.Interface):
    """Generic LDAP configuration retrieval."""

    def getBaseDN(self):
        """
        Get the LDAP base DN, as a DistinguishedName.

        Raises ldaptor.config.MissingBaseDNError
        if configuration does not specify a base DN.
        """

    def getServiceLocationOverrides(self):
        """
        Get the LDAP service location overrides, as a mapping of
        DistinguishedName to (host, port) tuples.
        """

    def copy(self,
             baseDN=None,
             serviceLocationOverrides=None):
        """
        Make a copy of this configuration, overriding certain aspects
        of it.
        """

    def getIdentityBaseDN(self):
        """TODO"""

    def getIdentitySearch(self, name):
        """TODO"""
