#!/usr/bin/env python3
"""Use GnuPG to verify libpurple (Pidgin/Adium) OTR keys

Sign OTR keys with a PGP key, or verify keys signed with this program
and add to verified fingerprints list."""
import sys
import getopt
import gnupg
from GPG import Signature
import purple
from base64 import b64encode, b64decode
from potr.compatcrypto.pycrypto import DSAKey


def signKey(uid):
    """Sign each public key associated with a given UID (should be one)
    and print key and signature to STDOUT."""
    keys = purple.PrivKeys.getPurpleKeys()
    gpg = gnupg.GPG()
    for account in keys:
        if not account.name.startswith(uid):
            continue
        sig = gpg.sign(b64encode(account.key.serializePublicKey()).decode())
        assert sig
        print(sig.data.decode())


def verifyKey(uid):
    """Verify a signature on a public key and attempt to verify an existing
    fingerprint entry."""
    sig = Signature.fromstring(sys.stdin.read())

    assert sig.verify()
    print("Good signature from: " + sig.ver.username)

    key = DSAKey.parsePublicKey(b64decode(sig.message.encode()))[0]

    fpr = '{:x}'.format(int.from_bytes(key.fingerprint(), 'big'))

    table = purple.FingerprintTable.getTable()

    found = False
    for entry in table:
        if uid != entry.uid:
            continue

        found = True
        if entry.fpr == fpr:
            if not entry.verified:
                print("Verifying for account: {}".format(entry.account))
                entry.verified = True
                table.save()
        else:
            print("Fingerprint mismatch!")
    if not found:
        print("Could not find ID in fingerprint table.")


def main(cmd, *argv):
    """Interpret commandline options and sign or verify a public key."""
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
