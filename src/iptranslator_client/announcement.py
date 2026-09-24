"""Signed announcements of the service's X-Wing public key, enabling key
rotation over an untrusted channel (the web app announces it via Ping, but
cannot forge it: the signing keys never leave the service operators).

The signature is a hybrid of Ed25519 and ML-DSA-65 (FIPS 204) over the same
payload; BOTH must verify. Ed25519 guards against lattice cryptanalysis
surprises, ML-DSA keeps the announcement unforgeable by a quantum attacker.

Wire format (JSON) and the signing payload are byte-identical with
``SignedKeyAnnouncement`` (.NET client) and ``announce.py`` (service)::

    payload = UTF8("iptr-key:v1:" + public_key + ":" + not_before + ":" + not_after)
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey

from .errors import EncryptionError

#: ed25519 pk (32) || ML-DSA-65 pk (1952)
VERIFICATION_KEY_SIZE = 1984
_ED25519_PK_SIZE = 32
PAYLOAD_PREFIX = "iptr-key:v1"


@dataclass
class SignedKeyAnnouncement:
    public_key: str  # base64 of the 1216-byte X-Wing public key
    not_before: int  # unix seconds
    not_after: int   # unix seconds
    sig_ed25519: str  # base64
    sig_mldsa65: str  # base64

    @classmethod
    def parse(cls, json_text: str) -> "SignedKeyAnnouncement":
        try:
            data = json.loads(json_text)
            announcement = cls(
                public_key=data["public_key"],
                not_before=int(data["not_before"]),
                not_after=int(data["not_after"]),
                sig_ed25519=data["sig_ed25519"],
                sig_mldsa65=data["sig_mldsa65"],
            )
        except (ValueError, TypeError, KeyError) as e:
            raise EncryptionError(f"malformed key announcement: {e}") from None
        if not (announcement.public_key and announcement.sig_ed25519 and announcement.sig_mldsa65):
            raise EncryptionError("malformed key announcement")
        return announcement

    def signing_payload(self) -> bytes:
        return f"{PAYLOAD_PREFIX}:{self.public_key}:{self.not_before}:{self.not_after}".encode("utf8")

    def verify_and_get_public_key(self, verification_key_base64: str, now: int | None = None) -> str:
        """Verify the validity window and both signatures; return the announced
        X-Wing public key (base64). Raises :class:`EncryptionError` if anything
        does not check out."""
        if not verification_key_base64:
            raise ValueError("verification key must be set")
        verification_key = base64.b64decode(verification_key_base64)
        if len(verification_key) != VERIFICATION_KEY_SIZE:
            raise EncryptionError(f"verification key must be {VERIFICATION_KEY_SIZE} bytes")

        now = int(time.time()) if now is None else int(now)
        if now < self.not_before or now > self.not_after:
            raise EncryptionError("key announcement is expired or not yet valid")

        payload = self.signing_payload()
        try:
            Ed25519PublicKey.from_public_bytes(verification_key[:_ED25519_PK_SIZE]).verify(
                base64.b64decode(self.sig_ed25519), payload)
        except (InvalidSignature, ValueError):
            raise EncryptionError("key announcement signature verification failed (Ed25519)") from None
        try:
            MLDSA65PublicKey.from_public_bytes(verification_key[_ED25519_PK_SIZE:]).verify(
                base64.b64decode(self.sig_mldsa65), payload)
        except (InvalidSignature, ValueError):
            raise EncryptionError("key announcement signature verification failed (ML-DSA-65)") from None

        return self.public_key
