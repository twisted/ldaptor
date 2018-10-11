"""
    Encoding / decoding utilities
"""

import six


def to_bytes(value):
    if hasattr(value, 'toWire'):
        return value.toWire()
    if isinstance(value, six.text_type):
        return value.encode('utf-8')
    return bytes(value)
