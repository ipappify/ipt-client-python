"""Content-free management actions (Ping) and key resolution from the signed
announcement."""

from __future__ import annotations

from ._version import __version__
from .announcement import SignedKeyAnnouncement
from .contracts import EnvelopeRequest, PingRequest, PingResponse
from .defaults import SERVICE_URL, SERVICE_VERIFICATION_KEY
from .errors import EncryptionError, IPTranslatorError
from .request_handler import CLIENT_NAME, WebApiRequestHandler, raise_on_error


class ManagementClient:
    """Ping: connectivity check, license/quota state, and the announcement
    channel for the service's end-to-end encryption key. These actions never
    carry document content, so they are not end-to-end encrypted."""

    def __init__(self, request_handler: WebApiRequestHandler | str = SERVICE_URL, api_key: str | None = None):
        if isinstance(request_handler, str):
            request_handler = WebApiRequestHandler(request_handler, api_key)
        self.request_handler = request_handler
        self.client = CLIENT_NAME
        self.client_version = __version__

    def ping(self, request: PingRequest | None = None) -> PingResponse:
        request = request or PingRequest(self.client, self.client_version)
        envelope = EnvelopeRequest(client=self.client, client_version=self.client_version, ping=request)
        response = self.request_handler.send(envelope)
        raise_on_error(response)
        if response.ping is None:
            raise IPTranslatorError("the service answered without a Ping response")
        return response.ping

    def test_connection(self) -> bool:
        try:
            self.ping()
            return True
        except Exception:
            return False

    def resolve_service_public_key(self, verification_key_base64: str | None = None) -> str:
        """Obtain the service's X-Wing public key (base64) from the Ping
        response's signed announcement, verified against the hybrid
        verification key (default: the built-in production key). The web app
        cannot forge the announcement, so this is safe over the untrusted
        channel and survives key rotation."""
        ping = self.ping()
        if not ping.signed_service_public_key:
            raise EncryptionError("the service did not announce a signed public key (Ping)")
        return SignedKeyAnnouncement.parse(ping.signed_service_public_key).verify_and_get_public_key(
            verification_key_base64 or SERVICE_VERIFICATION_KEY)
