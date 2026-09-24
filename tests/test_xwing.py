import base64

import pytest

from iptranslator_client import xwing
from tests import xwing_ref
from tests.devkeys import PUBLIC_KEY_BASE64

DEV_PUBLIC_KEY = base64.b64decode(PUBLIC_KEY_BASE64)


def test_encrypt_key_sizes():
    key, encrypted_key = xwing.encrypt_key(DEV_PUBLIC_KEY)
    assert len(key) == xwing.KEY_SIZE
    assert len(encrypted_key) == xwing.CIPHERTEXT_SIZE


def test_encrypt_key_is_randomized():
    key1, ct1 = xwing.encrypt_key(DEV_PUBLIC_KEY)
    key2, ct2 = xwing.encrypt_key(DEV_PUBLIC_KEY)
    assert key1 != key2
    assert ct1 != ct2


def test_invalid_public_key_size_raises():
    with pytest.raises(ValueError):
        xwing.encrypt_key(bytes(xwing.PUBLIC_KEY_SIZE - 1))
    with pytest.raises(ValueError):
        xwing.encrypt_key(None)


def test_receiver_recovers_the_key():
    # the service side (reference port of its xwing.py) must derive the same
    # AES key from the ciphertext the client produced
    seed, public_key = xwing_ref.generate_key_pair()
    assert len(public_key) == xwing.PUBLIC_KEY_SIZE
    key, encrypted_key = xwing.encrypt_key(public_key)
    assert xwing_ref.decrypt_key(seed, encrypted_key) == key

    # a ciphertext for another key pair yields a different key (implicit rejection)
    other_seed, _ = xwing_ref.generate_key_pair()
    assert xwing_ref.decrypt_key(other_seed, encrypted_key) != key
