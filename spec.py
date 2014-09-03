#!/usr/bin/env python3
"""Define integer types to conform to OTRv3 standard"""
import math


class UNSIGNED(int):
    maxbytes = None
    def __new__(cls, *args, **kwargs):
        x = super(UNSIGNED, cls).__new__(cls, *args, **kwargs)
        assert x >= 0
        if cls.maxbytes:
            assert x.byte_length() <= cls.maxbytes
        return x

    def byte_length(self):
        if self.maxbytes:
            return self.maxbytes
        return int(math.ceil(self.bit_length() / 8.0))

    def to_bytes(self):
        if self.maxbytes:
            n = self.maxbytes
        else:
            n = self.byte_length()

        return super(UNSIGNED, self).to_bytes(n, 'big')

    def bytestring(self):
        return self.to_bytes()


class BYTE(UNSIGNED):
    maxbytes = 1


class SHORT(UNSIGNED):
    maxbytes = 2


class INT(UNSIGNED):
    maxbytes = 4


class MPI(UNSIGNED):
    """Multiple precision integer"""
    def bytestring(self):
        length = INT(self.byte_length())
        return length.to_bytes() + self.to_bytes()
