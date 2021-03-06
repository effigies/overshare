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
# Optional dependency: zbar (for reading QR images)
#
# 2014 Christopher J Markiewicz
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


def readQR(fname):
    return subprocess.check_output(["zbarimg", "-q", "--raw",
                                    fname]).decode().rstrip()


def main(cmd, fingerprint):
    if fingerprint.endswith('.png'):
        fingerprint = readQR(fingerprint)

    try:
        bytestring = int(fingerprint, 16).to_bytes(33, 'big')
        fingerprint = base64.b64encode(bytestring).decode()
    except ValueError:
        bytestring = base64.b64decode(fingerprint)

    lines = [getQR(fingerprint), '']
    front = 'Fingerprint: '
    for six in splitsixes(bytestring):
        lines.append(front + ' '.join('{:02x}'.format(x) for x in six))
        front = '             '
    lines.extend(['', 'Base 64 encoded: ' + fingerprint, '', ''])

    sig = gpg.sign('\n'.join(lines))
    assert sig
    print(sig.data.decode())

if __name__ == '__main__':
    sys.exit(main(*sys.argv))
