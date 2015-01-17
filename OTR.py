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

    def public(self):
        """Return public key associated with given key.

        If object is a public key, key == key.public().
        """
        return KEYCODES[self.keytype](*self.params)

    def bytes(self):
        """A bytestring representation of a public key: the key type code,
        followed by the key parameters."""
        seq = [self.keytype] + self.params
        return b''.join(keypart.bytestring() for keypart in seq)

    def __str__(self):
        """Base-64 encoding of the public key.

        The following assertions should hold:
            str(PublicKey.fromBase64(<ASCII>)) == <ASCII>
            PublicKey.fromBase64(str(<KEYOBJ>)) == <KEYOBJ>.public()

        """
        return b64encode(self.bytes()).decode()

    def __repr__(self):
        """Represent a key as its class name and fingerprint"""
        return '<{} {}>'.format(self.__class__.__name__, self.fingerprint)

    def __eq__(self, comp):
        """Two public keys are equal iff their parameters are equal"""
        return self.__class__ == comp.__class__ and self.params == comp.params

    @classmethod
    def fromBase64(cls, string):
        """Determine keytype from first two bytes, and allow the subclass to
        interpret the key"""

        # If subclasses do not implement their own fromBase64, we get
        # recursion with no base
        assert cls == PublicKey

        # Note that 4 base-64 characters = 3 bytes
        bs = b64decode(string[:4].encode())
        classcode = KEYCODES[SHORT.from_bytes(bs[:2], 'big')]

        return classcode.fromBase64(string)


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

        def readmpi(bs):
            length = INT.from_bytes(bs[:4], 'big')
            mpi = MPI.from_bytes(bs[4:4 + length], 'big')
            return mpi, bs[4 + length:]

        p, bs = readmpi(bs[2:])
        q, bs = readmpi(bs)
        g, bs = readmpi(bs)
        y, bs = readmpi(bs)

        assert len(bs) == 0

        return cls(p, q, g, y)


class PrivateDSA(PublicDSA):
    """Private DSA keys contain the same information as public keys, but with
    a secret parameter x."""
    def __init__(self, p, q, g, y, x):
        """Construct DSA private key from p, q, g, y and x parameters"""
        self.p, self.q, self.g, self.y, self.x = map(MPI, (p, q, g, y, x))

    def __eq__(self, comp):
        """Two private keys are equal iff their parameters are equal"""
        return super(PrivateDSA, self).__eq__(comp) and self.x == comp.x

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

    @classmethod
    def fromBase64(cls, string):
        """Decode base-64 encoded DSA public key.

        Input should be keycode, followed by MPI representation of p, q, g,
        y and x.

        MPI representation is a 4-byte length field, followed by the number
        of bytes in that field.

        All values are big-endian."""
        bs = b64decode(string.encode())

        keycode = SHORT.from_bytes(bs[:2], 'big')
        assert keycode == cls.keytype

        def readmpi(bs):
            length = INT.from_bytes(bs[:4], 'big')
            mpi = MPI.from_bytes(bs[4:4 + length], 'big')
            return mpi, bs[4 + length:]

        p, bs = readmpi(bs[2:])
        q, bs = readmpi(bs)
        g, bs = readmpi(bs)
        y, bs = readmpi(bs)
        x, bs = readmpi(bs)

        assert len(bs) == 0

        return cls(p, q, g, y, x)

    def toBase64(self):
        """Base-64 encoding of PrivateDSA key."""
        seq = [self.keytype, self.p, self.q, self.g, self.y, self.x]

        return b64encode(b''.join(keypart.bytestring()
                                  for keypart in seq)).decode()


KEYCODES = {SHORT(0x0000): PublicDSA}
