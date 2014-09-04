#!/usr/bin/env python3
import os
import csv
import shutil
from sexpParser import sexp, sexptodict
from OTR import PrivateDSA


class Account:
    def __init__(self, name, protocol, private_key):
        self.name = name
        self.protocol = protocol
        self.private_key = private_key


    def __repr__(self):
        return '<{} {} {}>'.format(self.__class__.__name__,
                                   self.name, self.private_key.fingerprint)

    @classmethod
    def fromSExpression(cls, expr):
        name = expr[0]['name']
        protocol = expr[1]['protocol']
        private_key = PrivateDSA.fromSExpression(expr[2]['private-key']['dsa'])
        return cls(name, protocol, private_key)


class PrivKeys:
    def __init__(self, accounts):
        self.accounts = accounts

    @classmethod
    def fromSExpression(cls, expr):
        accounts = [Account.fromSExpression(sub['account'])
                    for sub in expr['privkeys']]
        return cls(accounts)

    @classmethod
    def getPurpleKeys(cls):
        key_file = os.path.join(os.environ['HOME'], '.purple',
                                'otr.private_key')
        sexpr = sexp.parseFile(key_file)
        return cls.fromSExpression(sexptodict(sexpr))


class FingerprintEntry:
    def __init__(self, uid, account, proto, fpr, verified):
        self.uid = uid
        self.account = account
        self.proto = proto
        self.fpr = fpr
        self.verified = verified

    def __str__(self):
        return '\t'.join((self.uid, self.account, self.proto, self.fpr,
                          'verified' if self.verified else ''))

    def __repr__(self):
        if self.verified:
            return '<Verified FPR {} {}>'.format(self.uid, self.fpr)
        else:
            return '<FPR {} {}>'.format(self.uid, self.fpr)

class FingerprintTable(dict):
    fpr_file = os.path.join(os.environ['HOME'], '.purple',
                            'otr.fingerprints')

    @classmethod
    def getTable(cls):
        with open(cls.fpr_file) as f:
            tsv = csv.reader(f, delimiter='\t')
            entries = [(line[0], FingerprintEntry(*line)) for line in tsv]

        return cls(entries)

    def save(self, safe=True):
        if safe:
            shutil.copy(self.fpr_file, self.fpr_file + '.bak')

        with open(self.fpr_file, 'w') as f:
            for uid in self:
                print(self[uid], file=f)
