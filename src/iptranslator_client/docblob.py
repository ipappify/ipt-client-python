"""Document-blob encryption for asynchronous jobs (``iptd-doc:v1``).

A blob travels through blob storage AES-256-GCM-encrypted under a per-job key.
The client generates the key (:func:`new_key`) and transports it INSIDE the
encrypted request body (``doc_key``) — the web app relays the request unopened,
so only the client and the worker ever see it (same trust model as the message
bodies; no second KEM).

Blob layout: ``12-byte nonce || ciphertext || 16-byte tag``. The GCM AAD binds
job identity and blob slot, so a blob cannot be replayed in another slot or
under another job: ``iptd-doc:v1:{job_id}:{slot}``. Slots: ``in``/``out`` for
document-translation jobs, plus ``dict`` (dictionary file) and ``tm0..tmN``
(TMX translation memories) for their optional inputs; ``ctx0..ctxN`` (context
files) and ``out`` (result report) for genai jobs.

Must stay byte-identical with ``DocumentBlobCipher`` (.NET client) and
``ipt_service/docblob.py``; all test suites pin the same fixed-nonce vectors.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import EncryptionError

VERSION = "iptd-doc:v1"
KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16

DIRECTION_IN = "in"     # client -> worker (input document)
DIRECTION_OUT = "out"   # worker -> client (result document/report)
DICTIONARY_SLOT = "dict"  # client -> worker (optional dictionary file)


def context_slot(index: int) -> str:
    """Slot of the i-th genai context file (``ctx0..ctxN``)."""
    if index < 0:
        raise ValueError("index must be >= 0")
    return f"ctx{index}"


def translation_memory_slot(index: int) -> str:
    """Slot of the i-th translation-memory file (``tm0..tmN``)."""
    if index < 0:
        raise ValueError("index must be >= 0")
    return f"tm{index}"


def new_key() -> bytes:
    """Fresh per-job 256-bit blob key (client-side; never persisted server-side)."""
    return os.urandom(KEY_SIZE)


def _is_valid_indexed_slot(slot: str, prefix: str) -> bool:
    # {prefix}0..{prefix}N, no leading zeros
    if len(slot) < len(prefix) + 1 or not slot.startswith(prefix):
        return False
    digits = slot[len(prefix):]
    if len(digits) > 1 and digits[0] == "0":
        return False
    return digits.isascii() and digits.isdigit()


def _is_valid_slot(slot: str) -> bool:
    if slot in (DIRECTION_IN, DIRECTION_OUT, DICTIONARY_SLOT):
        return True
    return _is_valid_indexed_slot(slot, "ctx") or _is_valid_indexed_slot(slot, "tm")


def document_aad(job_id: str, slot: str) -> bytes:
    if not isinstance(slot, str) or not _is_valid_slot(slot):
        raise ValueError(f"slot must be '{DIRECTION_IN}', '{DIRECTION_OUT}', '{DICTIONARY_SLOT}', "
                         f"'ctx<i>' or 'tm<i>', got '{slot}'")
    if not job_id:
        raise ValueError("job_id is required")
    return f"{VERSION}:{job_id}:{slot}".encode("utf8")


def encrypt(key: bytes, job_id: str, slot: str, data: bytes, _nonce: bytes | None = None) -> bytes:
    """Encrypt ``data`` into blob format. ``_nonce`` is the test seam for the
    cross-language vectors; production callers must leave it None (random)."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")
    nonce = os.urandom(NONCE_SIZE) if _nonce is None else bytes(_nonce)
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"nonce must be {NONCE_SIZE} bytes")
    return nonce + AESGCM(key).encrypt(nonce, bytes(data), document_aad(job_id, slot))


def decrypt(key: bytes, job_id: str, slot: str, blob: bytes) -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")
    if blob is None or len(blob) < NONCE_SIZE + TAG_SIZE:
        raise ValueError(f"blob too short to be a {VERSION} document ({0 if blob is None else len(blob)} bytes)")
    aad = document_aad(job_id, slot)
    nonce, data = bytes(blob[:NONCE_SIZE]), bytes(blob[NONCE_SIZE:])
    try:
        return AESGCM(key).decrypt(nonce, data, aad)
    except InvalidTag:
        raise EncryptionError(
            "document authentication failed: wrong key, job_id, direction, or tampered blob") from None
