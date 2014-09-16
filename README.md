overshare
=========

Once a user has been associated with an encryption key, the encrypted channels
opened should be usable to verify further keys. The aim of this project is to
simplify this process.

There isn't likely to be any one optimal strategy for using an arbitrary
channel to verify another arbitrary channel. I am more inclined to create a
battery of chaining tools than to try to build some kind of unified framework.

Verifying OTR over GPG
----------------------
On Linux, `libpurple` stores keys in an S-expression in
`$HOME/.purple/otr.private_key`. The existing code parses the S-expression and
constructs public keys that can be signed with GPG. On the receiving end, the
GPG signature will be verified, the public key reconstructed and the
fingerprint derived and checked against the fingerprint found in
`$HOME/.purple/otr.fingerprints`.

Create a signature that can be copied into a chat session or email:

    OTRoverGPG.py --sign --id my-id@jabber.org

Validate a signature and mark verified if it matches (paste in stdin):

    OTRoverGPG.py --verify --id your-id@jabber.org


Verifying GPG over OTR
----------------------
In this case, simply copy the exported key into a chat session or, on the other
end, import the copied text.

Export:

    gpg -a --export-options export-minimal --export $KEY_ID

Import:

    gpg --import


Signing TextSecure keys with GPG
--------------------------------
TextSecure currently validates keys with QR codes. From the main menu, you may
find your key under the option "My identity key". There you will see a key like

    01 23 45 67 89 ab
    cd ef 02 13 46 57
    8a 9b ce df 04 15
    26 37 8c 9d ae bf
    08 19 2a 3b 4c 5d
    6e 7f ff

A barcode symbol gives you the option to "Get scanned to compare". There is a
QR code containing the base-64 version of your key, with the encoded text
beneath, for example:

    ASNFZ4mrze8CE0ZXipvO3wQVJjeMna6/CBkqO0xdbn//

You may use either form of the key as the the argument to
`signTextSecure.py`, which will produce a block that includes QR, hex and
base-64 versions of the fingerprint. This block may be emailed or posted
online. The block may be copied into the terminal following

    gpg --verify

after which the user may scan the QR code to verify your identity in
TextSecure.

Note that, to display the QR code properly in a web browser, the `<pre>` or
`<textarea>` tag will need to have the `line-height` property set to `1em`.
