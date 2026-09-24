"""HTTP transport: a small protocol so tests (and users with their own HTTP
stack) can substitute the standard-library implementation."""

from __future__ import annotations

import http.client
import urllib.error
import urllib.request
from typing import Mapping, Protocol

from .errors import TransportError

DEFAULT_TIMEOUT = 100.0  # seconds; the service holds a poll for at most 25 s


class Transport(Protocol):
    def post_json(self, url: str, body: str, headers: Mapping[str, str], timeout: float) -> str:
        """POST ``body`` (JSON text) and return the response text; raise
        :class:`TransportError` on a non-2xx status."""

    def put_blob(self, url: str, data: bytes, timeout: float) -> None:
        """PUT ``data`` to a blob SAS URL (Azure block blob)."""

    def get_blob(self, url: str, timeout: float) -> bytes:
        """GET the bytes behind a blob SAS URL."""


def _describe(e: urllib.error.HTTPError) -> str:
    try:
        snippet = e.read(200).decode("utf8", "replace")
    except Exception:
        snippet = ""
    return f"HTTP {e.code} {e.reason}" + (f": {snippet.strip()}" if snippet.strip() else "")


class UrllibTransport:
    """Standard-library transport (``urllib.request``); no extra dependencies."""

    def __init__(self, user_agent: str = "iptranslator-client"):
        self.user_agent = user_agent

    def _send(self, request: urllib.request.Request, timeout: float) -> bytes:
        request.add_header("User-Agent", self.user_agent)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as e:
            raise TransportError(_describe(e), status=e.code, url=request.full_url) from None
        except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError) as e:
            raise TransportError(f"request to {request.full_url} failed: {e}", url=request.full_url) from e

    def post_json(self, url: str, body: str, headers: Mapping[str, str], timeout: float) -> str:
        request = urllib.request.Request(url, data=body.encode("utf8"), method="POST")
        request.add_header("Content-Type", "text/json; charset=utf-8")
        for name, value in headers.items():
            request.add_header(name, value)
        return self._send(request, timeout).decode("utf8")

    def put_blob(self, url: str, data: bytes, timeout: float) -> None:
        request = urllib.request.Request(url, data=data, method="PUT")
        request.add_header("x-ms-blob-type", "BlockBlob")
        request.add_header("Content-Type", "application/octet-stream")
        self._send(request, timeout)

    def get_blob(self, url: str, timeout: float) -> bytes:
        return self._send(urllib.request.Request(url, method="GET"), timeout)
