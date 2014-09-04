#!/usr/bin/env python3
import sys
import getopt
import gnupg
from GPG import Signature
import OTR
import purple

gpg = gnupg.GPG()

def signKey(uid):
    keys = purple.PrivKeys.getPurpleKeys()
    for account in keys.accounts:
        if not account.name.startswith(uid):
            continue
        sig = gpg.sign(str(account.private_key))
        assert sig
        print(sig.data.decode())

def verifyKey(uid):
    sig = Signature.fromstring(sys.stdin.read())

    assert sig.verify()
    print("Good signature from: " + sig.ver.username)

    key = OTR.PublicKey.fromBase64(sig.message)

    print(key.fingerprint)

    table = purple.FingerprintTable.getTable()

    if uid in table:
        if table[uid].fpr == key.fingerprint:
            table[uid].verified = True
            table.save()
        else:
            print("Fingerprint mismatch!")
    else:
        print("Could not find ID in fingerprint table.")



def main(cmd, *argv):
    try:
        opts, args = getopt.getopt(argv, "svi:", ["sign", "verify", "id="])
    except getopt.GetoptError as err:
        print(str(err))
        return 2

    sign = False
    verify = False
    uid = None
    for opt, arg in opts:
        if opt in ('-s', '--sign'):
            sign = True
        elif opt in ('-v', '--verify'):
            verify = True
        elif opt in ('-i', '--id'):
            uid = arg
        else:
            print('Invalid usage')
            return 2

    if not sign ^ verify:
        print('Signing or verifying is required, and the two are mutually '
              'exclusive')
        return 2

    if not uid:
        print('ID (--id=...) mandatory')
        return 2

    if sign:
        signKey(uid)
    else:
        verifyKey(uid)

if __name__ == '__main__':
    sys.exit(main(*sys.argv))
