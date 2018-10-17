"""
    Encoding / decoding utilities
"""

import warnings

import six


def to_bytes(value):
    """
    Converts value to its bytes representation:

    * Uses value`s toWire method if it has one
    * Encodes to utf-8 if the value is a unicode string
    * Otherwise wraps value into bytes()
    """
    if hasattr(value, 'toWire'):
        return value.toWire()
    if isinstance(value, six.text_type):
        return value.encode('utf-8')
    return bytes(value)


def to_unicode(value):
    """
    Converts string to unicode:

    * Decodes value from utf-8 if it is a byte string
    * Otherwise just returns the same value
    """
    if isinstance(value, six.binary_type):
        return value.decode('utf-8')
    return value


class WireStrAlias(object):
    """
    A helper base or mixin class which adds __str__ method
    as an alias of toWire method but marks it as deprecated
    """

    def __str__(self):
        warnings.simplefilter('always', DeprecationWarning)
        warnings.warn('{0}.__str__ method is deprecated and will not be used '
                      'for getting bytes representation in the future '
                      'releases, use {0}.toWire instead'.format(self.__class__.__name__),
                      category=DeprecationWarning)
        warnings.simplefilter('default', DeprecationWarning)
        return self.toWire()

    def toWire(self):
        raise NotImplementedError('toWire method is not implemented')
