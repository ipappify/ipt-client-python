import base64
import json

import pytest

from iptranslator_client.announcement import VERIFICATION_KEY_SIZE, SignedKeyAnnouncement
from iptranslator_client.errors import EncryptionError
from tests.devkeys import ANNOUNCEMENT_JSON, OLDER_ANNOUNCEMENT_JSON, PUBLIC_KEY_BASE64, VERIFICATION_KEY_BASE64


def parse_fixture() -> SignedKeyAnnouncement:
    return SignedKeyAnnouncement.parse(ANNOUNCEMENT_JSON)


def test_verifies_python_signed_announcement():
    # the fixture was signed by ipt-service's announce.py: parsing + verifying
    # it here is the cross-language compatibility test
    assert parse_fixture().verify_and_get_public_key(VERIFICATION_KEY_BASE64) == PUBLIC_KEY_BASE64
    assert SignedKeyAnnouncement.parse(OLDER_ANNOUNCEMENT_JSON).verify_and_get_public_key(
        VERIFICATION_KEY_BASE64) == PUBLIC_KEY_BASE64


def test_rejects_tampered_public_key():
    announcement = parse_fixture()
    tampered = bytearray(base64.b64decode(announcement.public_key))
    tampered[0] ^= 0x01
    announcement.public_key = base64.b64encode(bytes(tampered)).decode("ascii")
    with pytest.raises(EncryptionError, match="signature"):
        announcement.verify_and_get_public_key(VERIFICATION_KEY_BASE64)


def test_rejects_extended_validity():
    announcement = parse_fixture()
    announcement.not_after += 3600  # extend without re-signing
    with pytest.raises(EncryptionError, match="signature"):
        announcement.verify_and_get_public_key(VERIFICATION_KEY_BASE64)


def test_rejects_outside_validity_window():
    announcement = parse_fixture()
    with pytest.raises(EncryptionError, match="expired"):
        announcement.verify_and_get_public_key(VERIFICATION_KEY_BASE64, now=announcement.not_after + 1)
    with pytest.raises(EncryptionError, match="expired"):
        announcement.verify_and_get_public_key(VERIFICATION_KEY_BASE64, now=announcement.not_before - 1)
    # the window bounds themselves are valid
    announcement.verify_and_get_public_key(VERIFICATION_KEY_BASE64, now=announcement.not_before)
    announcement.verify_and_get_public_key(VERIFICATION_KEY_BASE64, now=announcement.not_after)


def test_rejects_wrong_verification_key():
    wrong = bytearray(base64.b64decode(VERIFICATION_KEY_BASE64))
    assert len(wrong) == VERIFICATION_KEY_SIZE
    wrong[0] ^= 0x01  # corrupt the Ed25519 half
    with pytest.raises(EncryptionError, match="Ed25519"):
        parse_fixture().verify_and_get_public_key(base64.b64encode(bytes(wrong)).decode("ascii"))
    with pytest.raises(EncryptionError, match="1984"):
        parse_fixture().verify_and_get_public_key(base64.b64encode(bytes(wrong[:-1])).decode("ascii"))
    with pytest.raises(ValueError):
        parse_fixture().verify_and_get_public_key("")


def test_rejects_single_valid_signature():
    # hybrid means BOTH must verify: corrupt only the ML-DSA signature so the
    # Ed25519 one alone must not be enough
    announcement = parse_fixture()
    sig = bytearray(base64.b64decode(announcement.sig_mldsa65))
    sig[0] ^= 0x01
    announcement.sig_mldsa65 = base64.b64encode(bytes(sig)).decode("ascii")
    with pytest.raises(EncryptionError, match="ML-DSA"):
        announcement.verify_and_get_public_key(VERIFICATION_KEY_BASE64)


def test_rejects_malformed_json():
    with pytest.raises(EncryptionError):
        SignedKeyAnnouncement.parse("{}")
    with pytest.raises(EncryptionError):
        SignedKeyAnnouncement.parse("not json")
    partial = dict(json.loads(ANNOUNCEMENT_JSON))
    partial["sig_ed25519"] = ""
    with pytest.raises(EncryptionError):
        SignedKeyAnnouncement.parse(json.dumps(partial))
