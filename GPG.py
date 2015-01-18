#!/usr/bin/env python3
"""Utilities for verifying other secure channels with GPG, or vice versa
"""
import gnupg


class Signature:
    """Wrapper for parsing and verifying GnuPG signatures"""
    def __init__(self, message, signature, hashfun, version):
        """Represent message, signature, hash function and PGP version"""
        self.message = message
        self.signature = signature
        self.hashfun = hashfun
        self.version = version

    def __str__(self):
        """Reconstruct ASCII-armored PGP signature"""
        return """-----BEGIN PGP SIGNED MESSAGE-----
Hash: {}

{}
-----BEGIN PGP SIGNATURE-----
Version: {}

{}
-----END PGP SIGNATURE-----""".format(self.hashfun, self.message, self.version,
                                      self.signature)

    @classmethod
    def fromstring(cls, string):
        """Parse ASCII-armored PGP signature for named access to components"""
        sections = string.split('-----')
        assert sections[0] == ''
        assert sections[1] == 'BEGIN PGP SIGNED MESSAGE'
        assert sections[3] == 'BEGIN PGP SIGNATURE'
        assert sections[5] == 'END PGP SIGNATURE'

        hashfun, message = sections[2].split('\n\n', 1)
        assert hashfun.startswith('\nHash: ')
        assert message[-1] == '\n'

        version, signature = sections[4].split('\n\n', 1)
        assert version.startswith('\nVersion: ')
        assert signature[-1] == '\n'

        return cls(message[:-1], signature[:-1], hashfun[7:], version[10:])

    def verify(self):
        """Reconstruct and verify signature, and determine if trust threshold
        is passed"""
        gpg = gnupg.GPG()
        self.ver = gpg.verify(str(self))
        assert self.ver
        return self.ver.trust_level >= self.ver.TRUST_FULLY
