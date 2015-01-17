#!/usr/bin/env python3
"""Handler for OTRv3-conforming keys"""
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
        """The fingerprint is the SHA1 hash of the concatenated public key
        parameters."""
        # DSA keys should not have keytype, for backward compatibility
        if self.keytype == 0:
            seq = self.params
        else:
            seq = [self.keytype] + self.params

        return '{:x}'.format(int.from_bytes(sha1(b''.join(
            keypart.bytestring() for keypart in seq)).digest(), 'big'))

    def bytes(self):
        """A bytestring representation of a public key: the key type code,
        followed by the key parameters."""
        seq = [self.keytype] + self.params
        return b''.join(keypart.bytestring() for keypart in seq)

    def __str__(self):
        """Base-64 encoding of the public key.

        The following assertions should hold:
            str(PublicKey.fromBase64(<ASCII>)) == <ASCII>
            PublicKey.fromBase64(str(<KEYOBJ>)) == <KEYOBJ>
        """
        return b64encode(self.bytes()).decode()

    def __repr__(self):
        """Represent a key as its class name and fingerprint"""
        return '<{} {}>'.format(self.__class__.__name__, self.fingerprint)

    @classmethod
    def fromBase64(cls, string):
        """Determine keytype from first two bytes, and allow the subclass to
        interpret the key"""

        bs = b64decode(string.encode())
        classcode = KEYCODES[SHORT.from_bytes(bs[:2], 'big')]
        if cls == PublicKey:
            cls = classcode
        else:
            assert classcode == cls

        return cls.fromBase64(string)


class PublicDSA(PublicKey):
    """
    OTR public authentication DSA key (PUBKEY):

        Pubkey type (SHORT)
            DSA public keys have type 0x0000

        p (MPI)
        q (MPI)
        g (MPI)
        y (MPI)

            (p,q,g,y) are the DSA public key parameters

    Quoted from: https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html
    """
    keytype = SHORT(0x0000)

    def __init__(self, p, q, g, y):
        """Construct DSA public key from p, q, g, y parameters"""
        self.p, self.q, self.g, self.y = map(MPI, (p, q, g, y))

    @property
    def params(self):
        """(p,q,g,y) are the DSA public key parameters"""
        return [self.p, self.q, self.g, self.y]

    @classmethod
    def fromSExpression(cls, expr):
        """Interpret S-expression representation of public key, such
        as that used in libpurple.

        Example:
            (dsa
                (p <PVALUE>)
                (q <QVALUE>)
                (g <GVALUE>)
                (y <YVALUE>)
                [OPTIONAL FURTHER VALUES...]
            )
        """
        return cls(expr[0]['p'], expr[1]['q'], expr[2]['g'], expr[3]['y'])

    @classmethod
    def fromBase64(cls, string):
        """Decode base-64 encoded DSA public key.

        Input should be keycode, followed by MPI representation of p, q, g
        and y.

        MPI representation is a 4-byte length field, followed by the number
        of bytes in that field.

        All values are big-endian."""
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
    """Private DSA keys contain the same information as public keys, but with
    a secret parameter"""
    def __init__(self, p, q, g, y, x):
        """Construct DSA private key from p, q, g, y and x parameters"""
        self.p, self.q, self.g, self.y, self.x = map(MPI, (p, q, g, y, x))

    @classmethod
    def fromSExpression(cls, expr):
        """Interpret S-expression representation of public key, such
        as that used in libpurple.

        Example:
            (dsa
                (p <PVALUE>)
                (q <QVALUE>)
                (g <GVALUE>)
                (y <YVALUE>)
                (x <XVALUE>)
                [OPTIONAL FURTHER VALUES...]
            )
        """
        return cls(expr[0]['p'], expr[1]['q'], expr[2]['g'], expr[3]['y'],
                   expr[4]['x'])

KEYCODES = {SHORT(0x0000): PublicDSA}
