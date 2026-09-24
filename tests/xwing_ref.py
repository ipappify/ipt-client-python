"""Test-only reference implementation of the X-Wing *receiver* side (key
generation + decapsulation), ported from the service's xwing.py. The client
never decapsulates; the tests use this to prove that what the client
encapsulates is what the service will recover."""

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from iptranslator_client.xwing import CIPHERTEXT_SIZE, XWING_LABEL

_MLKEM_PK_SIZE = 1184
_MLKEM_CT_SIZE = 1088


def _expand(seed: bytes):
    """expandDecapsulationKey: 32-byte seed -> (ML-KEM key, X25519 key, public key)."""
    shake = hashes.Hash(hashes.SHAKE256(96))
    shake.update(seed)
    expanded = shake.finalize()
    mlkem_key = mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[0:64])
    x25519_key = X25519PrivateKey.from_private_bytes(expanded[64:96])
    public_key = mlkem_key.public_key().public_bytes_raw() + x25519_key.public_key().public_bytes_raw()
    return mlkem_key, x25519_key, public_key


def generate_key_pair() -> tuple[bytes, bytes]:
    seed = os.urandom(32)
    return seed, _expand(seed)[2]


def decrypt_key(seed: bytes, encrypted_key: bytes) -> bytes:
    assert len(encrypted_key) == CIPHERTEXT_SIZE
    mlkem_key, x25519_key, public_key = _expand(seed)
    ct_m, ct_x = encrypted_key[:_MLKEM_CT_SIZE], encrypted_key[_MLKEM_CT_SIZE:]
    ss_m = mlkem_key.decapsulate(ct_m)
    ss_x = x25519_key.exchange(X25519PublicKey.from_public_bytes(ct_x))
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(ss_m + ss_x + ct_x + public_key[_MLKEM_PK_SIZE:] + XWING_LABEL)
    return digest.finalize()
