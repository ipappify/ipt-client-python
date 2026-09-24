"""Builds and parses IPTv3 messages. Bodies are encrypted with AES-256-GCM under
a key transported via the X-Wing KEM; the GCM associated data binds the
unencrypted envelope fields (``request_id``, ``key_id``, and on responses
``request_type`` / ``consumed_units`` / ``object_id``) so they cannot be
tampered with independently of the body.

Byte-identical with ``TranslatorClientMessageHandler`` (.NET client) and
``message.py`` (service); the AAD formats are pinned in all test suites.
"""

from __future__ import annotations

import base64
import json
import os
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import xwing
from .contracts import TranslatorRequestBody, TranslatorRequestMessage, TranslatorResponseBody, \
    TranslatorResponseMessage
from .errors import EncryptionError

GCM_NONCE_SIZE = 12  # AES-GCM nonce in ``entropy``
GCM_TAG_SIZE = 16


def encrypt_gcm(key: bytes, data: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """AES-256-GCM: returns ``(12-byte nonce, ciphertext || 16-byte tag)``. ``aad``
    is authenticated but not encrypted (binds envelope fields to the body)."""
    nonce = os.urandom(GCM_NONCE_SIZE)
    return nonce, AESGCM(key).encrypt(nonce, data, aad)


def decrypt_gcm(key: bytes, nonce: bytes, data: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, data, aad)
    except InvalidTag:
        raise EncryptionError(
            "message authentication failed: body or envelope metadata was tampered with") from None


def request_aad(request_id: str, key_id: str) -> bytes:
    return f"iptv3-req:v1:{request_id}:{key_id}".encode("utf8")


def response_aad(message: TranslatorResponseMessage) -> bytes:
    """Binds the billing-relevant unencrypted envelope fields to the response body."""
    object_id = base64.b64encode(message.object_id).decode("ascii") if message.object_id else ""
    request_type = message.request_type_raw if message.request_type_raw is not None else (
        message.request_type.value if message.request_type is not None else "")
    return (f"iptv3-rsp:v1:{message.request_id}:{message.key_id}:{request_type}:"
            f"{int(message.consumed_units)}:{object_id}").encode("utf8")


class TranslatorClientMessageHandler:
    """Session-scoped message encryption: one X-Wing encapsulation against the
    service public key yields the session AES key and the ``encrypted_key``
    sent with every message under a random ``key_id``.

    There is deliberately no unencrypted mode in this client."""

    def __init__(self, service_public_key_base64: str):
        if not service_public_key_base64:
            raise ValueError("the service public key is required (end-to-end encryption)")
        try:
            public_key = base64.b64decode(service_public_key_base64, validate=True)
        except (ValueError, TypeError):
            raise ValueError("service public key must be base64") from None
        if len(public_key) != xwing.PUBLIC_KEY_SIZE:
            raise ValueError(f"service public key must be {xwing.PUBLIC_KEY_SIZE} bytes")
        self._key_id = uuid.uuid4().hex
        self._key, self._encrypted_key = xwing.encrypt_key(public_key)

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def is_encrypted(self) -> bool:
        return True

    def build_request(self, body: TranslatorRequestBody, request_id: str | None = None) -> TranslatorRequestMessage:
        request_id = request_id or uuid.uuid4().hex
        encoded = json.dumps(body.to_json(), ensure_ascii=False, separators=(",", ":")).encode("utf8")
        entropy, encrypted = encrypt_gcm(self._key, encoded, request_aad(request_id, self._key_id))
        return TranslatorRequestMessage(
            request_id=request_id,
            key_id=self._key_id,
            encrypted_key=self._encrypted_key,
            entropy=entropy,
            maybe_encrypted_body=encrypted,
        )

    def parse_response(self, message: TranslatorResponseMessage) -> tuple[TranslatorResponseBody, str]:
        """Decrypt and authenticate a response; returns ``(body, request_id)``."""
        if message.unsafe_error:
            raise EncryptionError("service failed with: " + message.unsafe_error)
        if not message.maybe_encrypted_body:
            raise EncryptionError("maybe_encrypted_body must not be empty")
        if message.key_id is None:
            # this client never sends unencrypted requests, so an unencrypted
            # response cannot be authentic
            raise EncryptionError("response is not encrypted")
        if message.key_id != self._key_id:
            raise EncryptionError("key_id does not match")
        if message.entropy is None or len(message.entropy) != GCM_NONCE_SIZE:
            raise EncryptionError("entropy is not an AES-GCM nonce")
        data = decrypt_gcm(self._key, message.entropy, message.maybe_encrypted_body, response_aad(message))
        try:
            body = json.loads(data.decode("utf8"))
        except (ValueError, UnicodeDecodeError) as e:
            raise EncryptionError(f"response body is not JSON: {e}") from None
        return TranslatorResponseBody.from_json(body), message.request_id
