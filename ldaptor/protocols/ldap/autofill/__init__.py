"""LDAP object field value suggestion and autoupdate mechanism."""

class AutofillException(Exception):
    pass

class ObjectMissingObjectClassException(AutofillException):
    """

    The LDAPEntry is missing an objectClass this autofiller needs to
    operate.

    """
    pass
