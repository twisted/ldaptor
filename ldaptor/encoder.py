"""
    Encoding / decoding utilities
"""

import warnings

import six


def to_bytes(value):
    if hasattr(value, 'toWire'):
        return value.toWire()
    if isinstance(value, six.text_type):
        return value.encode('utf-8')
    return bytes(value)


def to_unicode(value):
    if isinstance(value, six.binary_type):
        return value.decode('utf-8')
    return value


class WireStrAlias(object):
    def __str__(self):
        warnings.simplefilter('always', DeprecationWarning)
        warnings.warn('{0}.__str__ method is deprecated and will not be used '
                      'for getting bytes representation in the future '
                      'releases, use {0}.toWire instead'.format(self.__class__.__name__),
                      category=DeprecationWarning)
        warnings.simplefilter('default', DeprecationWarning)
        return self.toWire()

    def toWire(self):
        raise NotImplementedError()
