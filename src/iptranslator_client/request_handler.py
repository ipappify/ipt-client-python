"""The plaintext envelope transport of the web API (``POST {service}/translate``)."""

from __future__ import annotations

import json

from ._version import __version__
from .contracts import EnvelopeRequest, EnvelopeResponse
from .defaults import SERVICE_URL
from .errors import QuotaExceededError, ResponseCode, ServiceCanceledError, ServiceError, TransportError
from .transport import DEFAULT_TIMEOUT, Transport, UrllibTransport

CLIENT_NAME = "iptranslator-client"


class WebApiRequestHandler:
    """Sends envelopes to the service. ``api_key`` is sent as
    ``Authorization: ApiKey <key>``; ``transport`` defaults to the standard
    library (see :mod:`iptranslator_client.transport`)."""

    def __init__(self, service_url: str = SERVICE_URL, api_key: str | None = None,
                 transport: Transport | None = None, timeout: float = DEFAULT_TIMEOUT):
        self.service_url = service_url.rstrip("/")
        self.api_key = api_key
        self.transport: Transport = transport or UrllibTransport(f"{CLIENT_NAME}/{__version__}")
        self.timeout = timeout

    @property
    def translate_url(self) -> str:
        return f"{self.service_url}/translate"

    def send(self, request: EnvelopeRequest) -> EnvelopeResponse:
        """Send one envelope; returns the response envelope (any code)."""
        headers = {"Authorization": f"ApiKey {self.api_key}"} if self.api_key else {}
        text = self.transport.post_json(self.translate_url, json.dumps(request.to_json(), ensure_ascii=False),
                                        headers, self.timeout)
        try:
            return EnvelopeResponse.from_json(json.loads(text))
        except ValueError as e:  # e.g. a firewall's HTML block page
            raise TransportError(f"Unexpected response from url '{self.translate_url}'. "
                                 f"Please, check that your firewall allows access to this url.",
                                 url=self.translate_url) from e


def raise_on_error(response: EnvelopeResponse) -> None:
    """Translate a non-OK envelope code into an exception."""
    code = ResponseCode(response.code)
    if code == ResponseCode.OK:
        return
    if code == ResponseCode.CANCELED:
        raise ServiceCanceledError(response.message)
    if code == ResponseCode.QUOTA_EXCEEDED:
        raise QuotaExceededError(response.message, response.resolve_error_uri)
    raise ServiceError(response.code, response.message, response.resolve_error_uri)
