#!/usr/bin/env python3
"""Interface to libpurple OTR keys and fingerprints"""
import os
import csv
import shutil
from sexpParser import sexp, sexptodict
from OTR import PrivateDSA


class Account:
    """An account has a username, protocol and associated private key"""
    def __init__(self, name, protocol, private_key):
        """Construct an account record with username, protcol and an OTR
        private key"""
        self.name = name
        self.protocol = protocol
        self.private_key = private_key

    def __repr__(self):
        """Represent an account with the class name, username, and public key
        fingerprint."""
        return '<{} {} {}>'.format(self.__class__.__name__,
                                   self.name, self.private_key.fingerprint)

    @classmethod
    def fromSExpression(cls, expr):
        """Interpret S-expression representation of account, such as that
        used in libpurple.

        Example S-expression:
            (account
                (name <USERNAME>)
                (protocol <PROTOCOL>)
                (private-key <PRIVATE-KEY-S-EXP>)
            )

        Parsed S-expression:
            {'account': [
                {'name': <USERNAME>},
                {'protocol': <PROTOCOL>},
                {'private-key': <PRIVATE-KEY-EXPR>}
            ]}

        This method accepts the value associated with the key 'account'.
        """
        name = expr[0]['name']
        protocol = expr[1]['protocol']
        private_key = PrivateDSA.fromSExpression(expr[2]['private-key']['dsa'])
        return cls(name, protocol, private_key)


class PrivKeys:
    """Representation of a libpurple privkeys data structure, which is a
    list of account structures, in turn represented by Account."""
    def __init__(self, accounts):
        """Build a PrivKeys object containing a list of Account objects"""
        self.accounts = accounts

    @classmethod
    def fromSExpression(cls, expr):
        """Interpret S-expression representation of account, such as that
        used in libpurple.

        Example S-expression:
            (privkeys
                (account <ACCT-S-EXP>)
                (account <ACCT-S-EXP>)
                [...]
            )

        Parsed S-expression:
            {'privkeys': [
                {'account': <ACCT-EXPR>},
                {'account': <ACCT-EXPR>},
                ...
            ]}

        This method accepts a parsed S-expression as shown.
        """
        accounts = [Account.fromSExpression(sub['account'])
                    for sub in expr['privkeys']]
        return cls(accounts)

    @classmethod
    def getPurpleKeys(cls):
        """Build a PrivKeys object from your ~/.purple/otr.private_key file"""
        key_file = os.path.join(os.environ['HOME'], '.purple',
                                'otr.private_key')
        sexpr = sexp.parseFile(key_file)
        return cls.fromSExpression(sexptodict(sexpr))


class FingerprintEntry:
    """Represent a line in a libpurple OTR fingerprint table"""
    def __init__(self, uid, account, proto, fpr, verified):
        """Construct a fingerprint entry with a username, a local account
        name, a protocol identifier, public key fingerprint, and an
        indicator of whether the fingerprint has been verified.

        Note that by default value of the verified parameter will either be
        '' or 'verified', but any values that map to False or True under
        the bool() operation will be accepted."""
        self.uid = uid
        self.account = account
        self.proto = proto
        self.fpr = fpr
        self.verified = verified

    def __str__(self):
        """Produce the tab-separated value line that would have produced
        this FingerprintEntry."""
        return '\t'.join((self.uid, self.account, self.proto, self.fpr,
                          'verified' if self.verified else ''))

    def __repr__(self):
        """Represent an entry as <(Verified) FPR <UID> <FINGERPRINT>>
        where <UID> is the username, and <FINGERPRINT> is the associated
        public key fingerprint."""
        if self.verified:
            return '<Verified FPR {} {}>'.format(self.uid, self.fpr)
        else:
            return '<FPR {} {}>'.format(self.uid, self.fpr)


class FingerprintTable(dict):
    """Represent the ~/.purple/otr.fingerprints file as a dictionary of
    (username, FingerprintEntry pairs)."""
    fpr_file = os.path.join(os.environ['HOME'], '.purple',
                            'otr.fingerprints')

    @classmethod
    def getTable(cls):
        """Read fingerprint file"""
        with open(cls.fpr_file) as f:
            tsv = csv.reader(f, delimiter='\t')
            entries = [(line[0], FingerprintEntry(*line)) for line in tsv]

        return cls(entries)

    def save(self, safe=True):
        """Save fingerprint file, optionally creating a backup."""
        if safe:
            shutil.copy(self.fpr_file, self.fpr_file + '.bak')

        with open(self.fpr_file, 'w') as f:
            for uid in self:
                print(self[uid], file=f)
