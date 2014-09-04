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
