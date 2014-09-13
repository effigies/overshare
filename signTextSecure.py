#!/usr/bin/env python3
#
# Produce a human- and phone-readable TextSecure fingerprint and
# sign with a GPG key
#
# The signed message includes a UTF8 QR code containing base-64 encoded
# fingerprint, in addition to the hex fingerprint as shown in TextSecure and
# the base-64 encoded fingerprint in plain text
#
# Dependencies: qrencode, GnuPG
#
# 2014 Christopher J Johnson
import sys
import base64
import subprocess
import gnupg

gpg = gnupg.GPG()
splitsixes = lambda x: [x[:6]] + splitsixes(x[6:]) if x else []


def getQR(fingerprint):
    qr = subprocess.check_output(
        ["qrencode", "-t", "UTF8", fingerprint]).decode()

    inverted = qr.translate({9608: 32,      # Black to white
                             32: 9608,      # White to black
                             9604: 9600,    # White/black to black/white
                             9600: 9604})   # Black/white to white/black

    # qrencode's UTF8 encoder sometimes adds extra dots on the bottom line
    split = inverted.splitlines()
    split[-3] = split[-3].translate({9608: 9600,    # Black to black/white
                                     9604: 32})     # White/black to white
    return '\n'.join(split)


def main(cmd, fingerprint):
    lines = [getQR(fingerprint), '']
    front = 'Fingerprint: '
    for six in splitsixes(base64.b64decode(fingerprint)):
        lines.append(front + ' '.join('{:02x}'.format(x) for x in six))
        front = '             '
    lines.append('')
    lines.append('Base 64 encoded: ' + fingerprint)
    lines.append('')

    sig = gpg.sign('\n'.join(lines))
    assert sig
    print(sig.data.decode())

if __name__ == '__main__':
    sys.exit(main(*sys.argv))
