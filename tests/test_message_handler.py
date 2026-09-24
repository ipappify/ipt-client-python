import base64
import json
import os

import pytest

from iptranslator_client import message_handler as mh
from iptranslator_client.contracts import (RequestType, ResultType, TranslatorRequestBody,
                                           TranslatorResponseMessage)
from iptranslator_client.errors import EncryptionError
from tests import xwing_ref
from tests.devkeys import PUBLIC_KEY_BASE64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def test_encrypt_decrypt_gcm():
    key = os.urandom(32)
    data = b"Hello, World!"
    aad = mh.request_aad("req-0", "key-0")
    nonce, encrypted = mh.encrypt_gcm(key, data, aad)
    assert len(nonce) == mh.GCM_NONCE_SIZE
    assert len(encrypted) == len(data) + mh.GCM_TAG_SIZE  # ciphertext || tag
    assert mh.decrypt_gcm(key, nonce, encrypted, aad) == data


def test_gcm_detects_tampering():
    key = os.urandom(32)
    aad = mh.request_aad("req-0", "key-0")
    nonce, encrypted = mh.encrypt_gcm(key, b"Hello, World!", aad)
    tampered = bytearray(encrypted)
    tampered[0] ^= 0x01
    with pytest.raises(EncryptionError):
        mh.decrypt_gcm(key, nonce, bytes(tampered), aad)
    with pytest.raises(EncryptionError):  # tampered envelope metadata (different AAD)
        mh.decrypt_gcm(key, nonce, encrypted, mh.request_aad("req-1", "key-0"))


def test_aad_formats():
    # must match ipt-service message.py request_aad/response_aad and the .NET handler
    assert mh.request_aad("req-0", "key-0") == b"iptv3-req:v1:req-0:key-0"
    message = TranslatorResponseMessage.from_json({
        "request_id": "req-0", "key_id": "key-0", "request_type": "translate_align",
        "consumed_units": 3, "object_id": base64.b64encode(b"\x56\x78").decode(), "maybe_encrypted_body": ""})
    assert mh.response_aad(message) == b"iptv3-rsp:v1:req-0:key-0:translate_align:3:Vng="
    message.object_id = None
    message.consumed_units = 0
    assert mh.response_aad(message) == b"iptv3-rsp:v1:req-0:key-0:translate_align:0:"
    # an unknown request type name from a newer service is bound verbatim
    message = TranslatorResponseMessage.from_json({
        "request_id": "r", "key_id": "k", "request_type": "future_type", "consumed_units": 1,
        "maybe_encrypted_body": ""})
    assert message.request_type is None
    assert mh.response_aad(message) == b"iptv3-rsp:v1:r:k:future_type:1:"


def test_build_encrypted_request():
    sut = mh.TranslatorClientMessageHandler(PUBLIC_KEY_BASE64)
    assert sut.is_encrypted
    request = sut.build_request(TranslatorRequestBody(scope_key="1", type=RequestType.probe, src_lang="en"))
    assert request.key_id == sut.key_id and len(request.key_id) == 32
    assert len(request.encrypted_key) == 1120
    assert len(request.entropy) == mh.GCM_NONCE_SIZE
    assert request.maybe_encrypted_body
    assert len(request.request_id) == 32
    wire = request.to_json()
    assert set(wire) == {"request_id", "key_id", "encrypted_key", "entropy", "maybe_encrypted_body"}
    assert base64.b64decode(wire["encrypted_key"]) == request.encrypted_key


def test_encrypted_body_is_confidential():
    sut = mh.TranslatorClientMessageHandler(PUBLIC_KEY_BASE64)
    secret = "VerySecretSourceText"
    request = sut.build_request(TranslatorRequestBody(
        scope_key="1", type=RequestType.translate, src_lang="en", trg_lang="de", src_text=[secret], trg_text=[""]))
    assert secret.encode() not in request.maybe_encrypted_body
    assert secret not in json.dumps(request.to_json())


def test_translate_document_request_serializes_to_python_shape():
    # the service side (reference decapsulation) opens the body and finds the
    # snake_case / string-enum shape test_message.py pins
    seed, public_key = xwing_ref.generate_key_pair()
    sut = mh.TranslatorClientMessageHandler(base64.b64encode(public_key).decode())
    doc_key = bytes(range(32))
    request = sut.build_request(TranslatorRequestBody(
        scope_key="1", type=RequestType.translate_document, src_lang="de", trg_lang="en", src_text=[],
        doc_job_id="job-42",
        doc_input_url="https://blobs/jobs/job-42/input?sig=in",
        doc_output_url="https://blobs/jobs/job-42/output?sig=out",
        doc_status_url="https://blobs/jobs/job-42/status?sig=st",
        doc_cancel_url="https://blobs/jobs/job-42/cancel?sig=cx",
        doc_key=doc_key, doc_finalize=True,
        doc_dict_url="https://blobs/jobs/job-42/dict?sig=dc", doc_dict_format="csv",
        doc_tm_urls=["https://blobs/jobs/job-42/tm0?sig=t0"]), "req-doc")
    assert request.request_id == "req-doc"
    assert base64.b64encode(doc_key).decode() not in json.dumps(request.to_json())

    session_key = xwing_ref.decrypt_key(seed, request.encrypted_key)
    body_json = AESGCM(session_key).decrypt(request.entropy, request.maybe_encrypted_body,
                                            mh.request_aad("req-doc", request.key_id)).decode("utf8")
    assert '"type":"translate_document"' in body_json
    assert '"doc_job_id":"job-42"' in body_json
    assert '"doc_key":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="' in body_json
    assert '"doc_finalize":true' in body_json
    assert '"doc_dict_format":"csv"' in body_json
    assert '"doc_tm_urls":["https://blobs/jobs/job-42/tm0?sig=t0"]' in body_json
    assert '"src_text":[]' in body_json
    assert "trg_text" not in body_json and "desired_beamwidth" not in body_json and "task" not in body_json


def _response_for(sut: mh.TranslatorClientMessageHandler, session_key: bytes, body: dict, **envelope):
    fields = {"request_id": "req-1", "key_id": sut.key_id, "request_type": "translate_document",
              "consumed_units": 5, "object_id": base64.b64encode(b"\x01\x02").decode()}
    fields.update(envelope)
    message = TranslatorResponseMessage.from_json({**fields, "maybe_encrypted_body": ""})
    nonce = os.urandom(12)
    encrypted = AESGCM(session_key).encrypt(nonce, json.dumps(body).encode(), mh.response_aad(message))
    return TranslatorResponseMessage.from_json({
        **fields, "entropy": base64.b64encode(nonce).decode(),
        "maybe_encrypted_body": base64.b64encode(encrypted).decode()})


def test_parse_response_roundtrip_and_tampering():
    seed, public_key = xwing_ref.generate_key_pair()
    sut = mh.TranslatorClientMessageHandler(base64.b64encode(public_key).decode())
    request = sut.build_request(TranslatorRequestBody(scope_key="1", type=RequestType.probe, src_lang="en"))
    session_key = xwing_ref.decrypt_key(seed, request.encrypted_key)

    python_json = {"result_type": "document", "document": {
        "job_id": "job-42", "state": "done", "total": 10, "translated": 9, "failed": 1, "tm_translated": 4}}
    body, request_id = sut.parse_response(_response_for(sut, session_key, python_json))
    assert request_id == "req-1"
    assert body.result_type == ResultType.document
    assert body.document.translated == 9 and body.document.tm_translated == 4
    assert body.raw == python_json

    # back-compat: an old worker's result without tm_translated still parses
    old = {"result_type": "document", "document": {
        "job_id": "job-42", "state": "done", "total": 10, "translated": 9, "failed": 1}}
    assert sut.parse_response(_response_for(sut, session_key, old))[0].document.tm_translated == 0

    # error bodies
    body, _ = sut.parse_response(_response_for(sut, session_key, {"result_type": "error", "error_details": "x"}))
    assert body.result_type == ResultType.error and body.error_details == "x"

    # envelope tampering: consumed_units is bound into the AAD
    message = _response_for(sut, session_key, python_json)
    message.consumed_units = 6
    with pytest.raises(EncryptionError, match="authentication failed"):
        sut.parse_response(message)

    with pytest.raises(EncryptionError, match="key_id"):
        sut.parse_response(_response_for(sut, session_key, python_json, key_id="other"))
    with pytest.raises(EncryptionError, match="unsafe"):
        sut.parse_response(_response_for(sut, session_key, python_json, unsafe_error="unsafe: boom"))
    message = _response_for(sut, session_key, python_json)
    message.entropy = b"\x00" * 11
    with pytest.raises(EncryptionError, match="nonce"):
        sut.parse_response(message)
    message = _response_for(sut, session_key, python_json)
    message.maybe_encrypted_body = b""
    with pytest.raises(EncryptionError):
        sut.parse_response(message)
    message = _response_for(sut, session_key, python_json)
    message.key_id = None  # unencrypted responses are never accepted
    with pytest.raises(EncryptionError):
        sut.parse_response(message)


def test_rejects_bad_public_keys():
    with pytest.raises(ValueError):
        mh.TranslatorClientMessageHandler("")
    with pytest.raises(ValueError):
        mh.TranslatorClientMessageHandler("not base64!")
    with pytest.raises(ValueError, match="1216"):
        mh.TranslatorClientMessageHandler(base64.b64encode(b"\x00" * 1215).decode())
