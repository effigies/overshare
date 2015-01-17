#!/usr/bin/env python3
"""Define integer types to conform to OTRv3 standard

Definitions quote the standard, hosted at:
https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html"""
import math


class UNSIGNED(int):
    """Generic unsigned integer. Handles assertions and common
    functions for subclasses.
    """
    maxbytes = None

    def __new__(cls, *args, **kwargs):
        """Create a new UNSIGNED object, verifying nonnegativity and checking
        bounds for subclasses where maxbytes is defined"""
        x = super(UNSIGNED, cls).__new__(cls, *args, **kwargs)
        assert x >= 0
        if cls.maxbytes:
            assert x.byte_length() <= cls.maxbytes
        return x

    def byte_length(self):
        """Number of bytes required to represent the object.

        If maxbytes is set, maxbytes is used."""
        if self.maxbytes:
            return self.maxbytes
        return int(math.ceil(self.bit_length() / 8.0))

    def to_bytes(self):
        """Return a big-endian bytestring representation of the integer.

        If maxbytes is set, length is always maxbytes."""
        if self.maxbytes:
            n = self.maxbytes
        else:
            n = self.byte_length()

        return super(UNSIGNED, self).to_bytes(n, 'big')

    def bytestring(self):
        """Return a big-endian bytestring representation of the object.

        If not overridden, this is simply an alias for to_bytes()."""
        return self.to_bytes()


class BYTE(UNSIGNED):
    """
    Bytes (BYTE):
        1 byte unsigned value
    """
    maxbytes = 1


class SHORT(UNSIGNED):
    """
    Shorts (SHORT):
        2 byte unsigned value, big-endian
    """
    maxbytes = 2


class INT(UNSIGNED):
    """
    Ints (INT):
        4 byte unsigned value, big-endian
    """
    maxbytes = 4


class MPI(UNSIGNED):
    """
    Multi-precision integers (MPI):
        4 byte unsigned len, big-endian
        len byte unsigned value, big-endian

        (MPIs must use the minimum-length encoding; i.e. no leading 0x00
        bytes. This is important when calculating public key fingerprints.)
    """
    def bytestring(self):
        """Return a big-endian bytestring representation of the object.

        For MPI, this is the concatenated bytestrings of the length of the
        integer and the integer's minimum-length encoding."""
        length = INT(self.byte_length())
        return length.to_bytes() + self.to_bytes()
