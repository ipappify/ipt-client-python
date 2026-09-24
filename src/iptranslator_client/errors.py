"""Exception types raised by the client."""

from __future__ import annotations

from enum import IntEnum


class ResponseCode(IntEnum):
    """Envelope response codes of the web API (similar to HTTP status codes).
    Mirror of ``IPTranslator.Contracts.ResponseCode``."""

    OK = 200
    CANCELED = 300
    NOT_READY = 301
    BAD_REQUEST = 400
    NOT_FOUND = 404
    NO_SUCH_MODEL = 405
    QUOTA_EXCEEDED = 419
    SERVICE_ERROR = 500
    UNKNOWN = -1

    @classmethod
    def _missing_(cls, value):  # unknown codes from a newer service
        return cls.UNKNOWN


class IPTranslatorError(Exception):
    """Base class of all errors raised by this package."""


class ServiceError(IPTranslatorError):
    """The service answered with a non-OK envelope code."""

    def __init__(self, code: ResponseCode | int, message: str | None = None,
                 resolve_error_uri: str | None = None):
        self.code = ResponseCode(code)
        self.resolve_error_uri = resolve_error_uri
        super().__init__(message or f"service responded with {self.code.name} ({int(code)})")


class QuotaExceededError(ServiceError):
    """The API key's quota is exhausted; ``upgrade_uri`` points to the upgrade page."""

    def __init__(self, message: str | None, upgrade_uri: str | None):
        super().__init__(ResponseCode.QUOTA_EXCEEDED, message, upgrade_uri)
        self.upgrade_uri = upgrade_uri


class ServiceCanceledError(ServiceError):
    """The service reported the operation as canceled (envelope code 300)."""

    def __init__(self, message: str | None = None):
        super().__init__(ResponseCode.CANCELED, message or "canceled by the service")


class TransportError(IPTranslatorError):
    """HTTP-level failure (non-2xx status, connection problem, unparsable body)."""

    def __init__(self, message: str, status: int | None = None, url: str | None = None):
        super().__init__(message)
        self.status = status
        self.url = url


class EncryptionError(IPTranslatorError):
    """End-to-end encryption failure: authentication failed, a key or
    announcement did not verify, or a message is malformed."""
