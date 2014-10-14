How an LDAP Entry looks like to an OO Programmer
================================================

An LDAP entry corresponds with an object.

Whereas object are usually instances of a single class,
LDAP entries can "implement" multiple objectClasses.

objectClasses can inherit zero, one or many
objectClasses, just like programming classes.

objectClasses have a root class, known as
`top`; many object oriented programming
languages have a root class, e.g. named
`Object`.

objectClasses are either `STRUCTURAL`
or `AUXILIARY`; entries can only implement
one `STRUCTURAL` objectClass.

The objectClasses of an entry can be changed at will;
you only need to take care that the entry has all the
`MUST` attribute types, and no attribute
types outside of the ones that are `MUST` or
`MAY`.

.. NOTE::
    Note that e.g. OpenLDAP doesn't implement this.

Attributes of an entry closely match attributes of
objects in programming languages; however, LDAP attributes may
have multiple values.
