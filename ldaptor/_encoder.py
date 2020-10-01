"""
    Encoding / decoding utilities
"""

import warnings


def to_bytes(value):
    """
    Converts value to its bytes representation:

    * Uses value`s toWire method if it has one
    * Encodes to utf-8 if the value is a unicode string
    * Otherwise wraps value into bytes()
    """
    if hasattr(value, "toWire"):
        return value.toWire()
    if isinstance(value, int):
        return str(value).encode("utf-8")
    if isinstance(value, str):
        return value.encode("utf-8")
    return bytes(value)


def to_unicode(value):
    """
    Converts string to unicode:

    * Decodes value from utf-8 if it is a byte string
    * Otherwise just returns the same value
    """
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return value


def repr_converter(value):
    return value


def get_strings(value):
    """
    Getting tuple of available string values
    (byte string and unicode string) for
    given value
    """
    if isinstance(value, str):
        return value, value.encode("utf-8")
    if isinstance(value, bytes):
        return value, value.decode("utf-8")
    return (value,)


class WireStrAlias:
    """
    A helper base or mixin class which adds __str__ method
    as an alias of toWire method but marks it as deprecated
    """

    def __str__(self):
        warnings.simplefilter("always", DeprecationWarning)
        warnings.warn(
            "{0}.__str__ method is deprecated and will not be used "
            "for getting bytes representation in the future "
            "releases, use {0}.toWire instead".format(self.__class__.__name__),
            category=DeprecationWarning,
            stacklevel=2,
        )
        warnings.simplefilter("default", DeprecationWarning)
        return self.toWire()

    def toWire(self):
        raise NotImplementedError("toWire method is not implemented")


class TextStrAlias:
    """
    A helper base or mixin class which adds __str__ method
    as an alias of getText method but marks it as deprecated
    """

    def __str__(self):
        warnings.simplefilter("always", DeprecationWarning)
        warnings.warn(
            "{0}.__str__ method is deprecated and will not be used "
            "for getting human readable representation in the future "
            "releases, use {0}.getText instead".format(self.__class__.__name__),
            category=DeprecationWarning,
            stacklevel=2,
        )
        warnings.simplefilter("default", DeprecationWarning)
        text = self.getText()
        return text

    def getText(self):
        raise NotImplementedError("getText method is not implemented")
