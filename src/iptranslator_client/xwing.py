"""X-Wing hybrid post-quantum KEM (draft-connolly-cfrg-xwing-kem):
ML-KEM-768 + X25519 combined with SHA3-256, built on ``cryptography``.

Client side only (encapsulation): being a KEM, X-Wing does not encrypt a
caller-chosen key — :func:`encrypt_key` *derives* a fresh 32-byte AES key and
returns it together with the ciphertext ("encrypted key") from which the
service's private key recovers it.

Sizes: public key 1216 bytes (ML-KEM-768 ek 1184 || X25519 pk 32), ciphertext
1120 bytes (ML-KEM-768 ct 1088 || X25519 ephemeral pk 32), derived key 32 bytes.
Byte-identical with ``XWingKem`` in the .NET client and ``xwing.py`` in the
service.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

#: ML-KEM-768 encapsulation key (1184) || X25519 public key (32).
PUBLIC_KEY_SIZE = 1216
#: ML-KEM-768 ciphertext (1088) || X25519 ephemeral public key (32).
CIPHERTEXT_SIZE = 1120
#: Size of the derived AES key.
KEY_SIZE = 32

_MLKEM_PK_SIZE = 1184
_MLKEM_CT_SIZE = 1088

# the 6-byte ASCII label "\.//^\" (hex 5c2e2f2f5e5c)
XWING_LABEL = bytes.fromhex("5c2e2f2f5e5c")


def encrypt_key(public_key: bytes) -> tuple[bytes, bytes]:
    """Derive a fresh 32-byte AES key for the holder of ``public_key``.

    Returns ``(key, encrypted_key)``: the key to use locally and the 1120-byte
    encrypted key to transmit.
    """
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != PUBLIC_KEY_SIZE:
        raise ValueError(f"X-Wing public key must be {PUBLIC_KEY_SIZE} bytes")
    public_key = bytes(public_key)
    pk_m = public_key[:_MLKEM_PK_SIZE]
    pk_x = public_key[_MLKEM_PK_SIZE:]

    # ML-KEM-768 encapsulation
    ss_m, ct_m = mlkem.MLKEM768PublicKey.from_public_bytes(pk_m).encapsulate()

    # X25519 with an ephemeral key; the ephemeral public key is the ciphertext part
    ephemeral = X25519PrivateKey.generate()
    ct_x = ephemeral.public_key().public_bytes_raw()
    ss_x = ephemeral.exchange(X25519PublicKey.from_public_bytes(pk_x))

    # combiner: SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(ss_m)
    digest.update(ss_x)
    digest.update(ct_x)
    digest.update(pk_x)
    digest.update(XWING_LABEL)
    key = digest.finalize()

    return key, ct_m + ct_x
