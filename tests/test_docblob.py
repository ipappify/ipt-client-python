import pytest

from iptranslator_client import docblob
from iptranslator_client.errors import EncryptionError

# ---- cross-language vectors -------------------------------------------------
# Pinned in DocumentBlobCipherTest.cs (.NET client) and ipt-service's
# test_docblob.py with the SAME bytes — a change that breaks one side must
# break every test suite.
VECTOR_KEY = bytes(range(32))
VECTOR_NONCE = bytes(range(12))
VECTOR_JOB_ID = "a3b2c1d0-0000-4000-8000-000000000001"
VECTOR_PLAINTEXT = b"IPTranslator document blob cross-language test vector."
VECTOR_BLOB_IN = bytes.fromhex(
    "000102030405060708090a0b0e528269a48bb177ec35f8f9918d170ef6bbe25a845b3d10"
    "5705c5e66f0673c12c7ccf92c8b473ff11840b88fbf3084e8b3a14e228f88809e1fd8c61"
    "fe20f18f506adeb5ac77")
VECTOR_BLOB_OUT = bytes.fromhex(
    "000102030405060708090a0b0e528269a48bb177ec35f8f9918d170ef6bbe25a845b3d10"
    "5705c5e66f0673c12c7ccf92c8b473ff11840b88fbf3084e8b3a14e228f8af114992f155"
    "c30f1a4cc1f2845958c9")
VECTOR_BLOB_CTX0 = bytes.fromhex(
    "000102030405060708090a0b0e528269a48bb177ec35f8f9918d170ef6bbe25a845b3d10"
    "5705c5e66f0673c12c7ccf92c8b473ff11840b88fbf3084e8b3a14e228f8ecfc102b77fb"
    "f175c08d5c9bbdaf5791")
VECTOR_BLOB_DICT = bytes.fromhex(
    "000102030405060708090a0b0e528269a48bb177ec35f8f9918d170ef6bbe25a845b3d10"
    "5705c5e66f0673c12c7ccf92c8b473ff11840b88fbf3084e8b3a14e228f8ed2b5d533cb1"
    "82175b42b55db91b7d37")
VECTOR_BLOB_TM0 = bytes.fromhex(
    "000102030405060708090a0b0e528269a48bb177ec35f8f9918d170ef6bbe25a845b3d10"
    "5705c5e66f0673c12c7ccf92c8b473ff11840b88fbf3084e8b3a14e228f8babe3132ae5e"
    "f59c897bd7c45274d238")


def test_cross_language_vectors():
    enc = lambda slot: docblob.encrypt(VECTOR_KEY, VECTOR_JOB_ID, slot, VECTOR_PLAINTEXT, _nonce=VECTOR_NONCE)
    assert enc(docblob.DIRECTION_IN) == VECTOR_BLOB_IN
    assert enc(docblob.DIRECTION_OUT) == VECTOR_BLOB_OUT
    assert enc(docblob.context_slot(0)) == VECTOR_BLOB_CTX0
    assert enc(docblob.DICTIONARY_SLOT) == VECTOR_BLOB_DICT
    assert enc(docblob.translation_memory_slot(0)) == VECTOR_BLOB_TM0
    for slot, blob in (("in", VECTOR_BLOB_IN), ("out", VECTOR_BLOB_OUT), ("ctx0", VECTOR_BLOB_CTX0),
                       ("dict", VECTOR_BLOB_DICT), ("tm0", VECTOR_BLOB_TM0)):
        assert docblob.decrypt(VECTOR_KEY, VECTOR_JOB_ID, slot, blob) == VECTOR_PLAINTEXT


def test_slot_binding():
    key = docblob.new_key()
    blob = docblob.encrypt(key, "job-1", docblob.context_slot(0), b"context pdf")
    assert docblob.decrypt(key, "job-1", "ctx0", blob) == b"context pdf"
    with pytest.raises(EncryptionError):
        docblob.decrypt(key, "job-1", docblob.context_slot(1), blob)
    with pytest.raises(EncryptionError):
        docblob.decrypt(key, "job-1", docblob.DIRECTION_OUT, blob)


def test_roundtrip_both_directions():
    key = docblob.new_key()
    assert len(key) == docblob.KEY_SIZE
    data = b" docx bytes" * 1000
    for direction in (docblob.DIRECTION_IN, docblob.DIRECTION_OUT):
        blob = docblob.encrypt(key, "job-1", direction, data)
        assert len(blob) == docblob.NONCE_SIZE + len(data) + docblob.TAG_SIZE
        assert docblob.decrypt(key, "job-1", direction, blob) == data


def test_direction_and_job_binding():
    key = docblob.new_key()
    blob = docblob.encrypt(key, "job-1", docblob.DIRECTION_IN, b"\x01\x02\x03")
    with pytest.raises(EncryptionError):
        docblob.decrypt(key, "job-1", docblob.DIRECTION_OUT, blob)
    with pytest.raises(EncryptionError):
        docblob.decrypt(key, "job-2", docblob.DIRECTION_IN, blob)
    with pytest.raises(EncryptionError):
        docblob.decrypt(docblob.new_key(), "job-1", docblob.DIRECTION_IN, blob)


def test_tampered_and_truncated_blobs_rejected():
    key = docblob.new_key()
    blob = bytearray(docblob.encrypt(key, "job-1", docblob.DIRECTION_IN, b"\x01\x02\x03"))
    blob[docblob.NONCE_SIZE] ^= 0x01
    with pytest.raises(EncryptionError):
        docblob.decrypt(key, "job-1", docblob.DIRECTION_IN, bytes(blob))
    with pytest.raises(ValueError):
        docblob.decrypt(key, "job-1", docblob.DIRECTION_IN, bytes(docblob.NONCE_SIZE + docblob.TAG_SIZE - 1))


def test_aad_format():
    assert docblob.document_aad("j", "in") == b"iptd-doc:v1:j:in"
    assert docblob.document_aad("j", "out") == b"iptd-doc:v1:j:out"
    assert docblob.context_slot(3) == "ctx3"
    assert docblob.document_aad("j", docblob.context_slot(0)) == b"iptd-doc:v1:j:ctx0"
    assert docblob.document_aad("j", "ctx12") == b"iptd-doc:v1:j:ctx12"
    assert docblob.translation_memory_slot(3) == "tm3"
    assert docblob.document_aad("j", docblob.DICTIONARY_SLOT) == b"iptd-doc:v1:j:dict"
    assert docblob.document_aad("j", docblob.translation_memory_slot(0)) == b"iptd-doc:v1:j:tm0"
    assert docblob.document_aad("j", "tm12") == b"iptd-doc:v1:j:tm12"
    for bad in ("sideways", "ctx", "ctx01", "ctx1x", "CTX1", "", "tm", "tm01", "tm1x", "TM1",
                "dic", "dict2", "dictionary", "ctx١"):
        with pytest.raises(ValueError):
            docblob.document_aad("j", bad)
    with pytest.raises(ValueError):
        docblob.document_aad("", "in")
    with pytest.raises(ValueError):
        docblob.context_slot(-1)
    with pytest.raises(ValueError):
        docblob.translation_memory_slot(-1)
