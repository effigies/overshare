#!/usr/bin/env python3
from hashlib import sha1
from base64 import b64encode, b64decode
from spec import SHORT, INT, MPI


class PublicKey:
    """Generic public key class

    Provides OTRv3 fingerprint functionality and ASCII-armored public key
    printing, and a fromBase64 method to decode ASCII public keys
    
    Subclasses are responsible for defining a parameter sequence to be
    hashed for fingerprints"""
    @property
    def fingerprint(self):
        # DSA keys should not have keytype, for backward compatibility
        if self.keytype == 0:
            seq = self.params
        else:
            seq = [self.keytype] + self.params

        return '{:x}'.format(int.from_bytes(sha1(b''.join(
            keypart.bytestring() for keypart in seq)).digest(), 'big'))

    def bytes(self):
        seq = [self.keytype] + self.params
        return b''.join(keypart.bytestring() for keypart in seq)

    def __str__(self):
        return b64encode(self.bytes()).decode()

    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, self.fingerprint)

    @classmethod
    def fromBase64(cls, string):
        bs = b64decode(string.encode())
        classcode = KEYCODES[SHORT.from_bytes(bs[:2], 'big')]
        if cls == PublicKey:
            cls = classcode
        else:
            assert classcode == cls

        return cls.fromBase64(string)


class PublicDSA(PublicKey):
    keytype = SHORT(0x0000)

    def __init__(self, p, q, g, y):
        self.p, self.q, self.g, self.y = map(MPI, (p, q, g, y))

    @property
    def params(self):
        return [self.p, self.q, self.g, self.y]

    @classmethod
    def fromSExpression(cls, expr):
        return cls(expr[0]['p'], expr[1]['q'], expr[2]['g'], expr[3]['y'])

    @classmethod
    def fromBase64(cls, string):
        bs = b64decode(string.encode())

        keycode = SHORT.from_bytes(bs[:2], 'big')
        assert keycode == cls.keytype

        bs = bs[2:]
        plen = INT.from_bytes(bs[:4], 'big')
        p = MPI.from_bytes(bs[4:4 + plen], 'big')

        bs = bs[4 + plen:]
        qlen = INT.from_bytes(bs[:4], 'big')
        q = MPI.from_bytes(bs[4:4 + qlen], 'big')

        bs = bs[4 + qlen:]
        glen = INT.from_bytes(bs[:4], 'big')
        g = MPI.from_bytes(bs[4:4 + glen], 'big')

        bs = bs[4 + glen:]
        ylen = INT.from_bytes(bs[:4], 'big')
        y = MPI.from_bytes(bs[4:4 + ylen], 'big')

        assert len(bs) == 4 + ylen

        return cls(p, q, g, y)


class PrivateDSA(PublicDSA):
    def __init__(self, p, q, g, y, x):
        self.p, self.q, self.g, self.y, self.x = map(MPI, (p, q, g, y, x))

    @classmethod
    def fromSExpression(cls, expr):
        return cls(expr[0]['p'], expr[1]['q'], expr[2]['g'], expr[3]['y'],
                   expr[4]['x'])

KEYCODES = {SHORT(0x0000): PublicDSA}
