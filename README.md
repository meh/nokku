nokku
=====

Design
------
X25119 is used for ECDH with static-static keys, this is done to avoid sending
32 additional bytes, a paranoid mode is provided where the exchange is
ephemeral-static ECDH, but it halves the transfer speed.

Every message is prefixed with a 32 bits nonce, this must be unique for each
private key.

After the nonce the encrypted payload starts, on successful decryption the
payload is composed of a 16 bits constant cookie to avoid bruteforcing or
acting on garbage, an 8 bits `length` header, and then `length` bytes. At the
end the Poly1305 MAC (which is 16 bytes).

ChaCha20Poly1305 is used to encrypt and authenticate the payload, the key for this
is derived with HKDF from the ECDH shared secret and the nonce.

As stealth transport the ID header in IPv4 is used to stuff the fragmented
payload and then send it with ICMP Echo Requests to make it look like someone
just pinging a server.
