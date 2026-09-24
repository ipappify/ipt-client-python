"""Python client for the IP.Translator document translation job API: batch
translation of ``.docx`` documents, end-to-end encrypted.

Quick start::

    import iptranslator_client as ipt

    client = ipt.connect(api_key="...")
    handle = client.submit("patent.docx", open("patent.docx", "rb").read(), "de", "en")
    status = client.wait(handle, on_progress=print)
    if status.state == ipt.DocumentJobState.done:
        result = client.get_result(handle)
        open("patent.en.docx", "wb").write(result.document)
"""

from ._version import __version__
from .announcement import SignedKeyAnnouncement
from .contracts import (DocumentJobLimits, DocumentJobState, DocumentResult, GetDocumentJobResponse,
                        PingRequest, PingResponse, RequestType, ResultType)
from .defaults import SERVICE_URL, SERVICE_VERIFICATION_KEY
from .document_job_client import (DocumentJobClient, DocumentJobHandle, DocumentJobResult,
                                  JobNotDoneError, connect)
from .errors import (EncryptionError, IPTranslatorError, QuotaExceededError, ResponseCode,
                     ServiceCanceledError, ServiceError, TransportError)
from .management_client import ManagementClient
from .message_handler import TranslatorClientMessageHandler
from .request_handler import WebApiRequestHandler
from .transport import Transport, UrllibTransport

__all__ = [
    "__version__",
    "connect",
    "DocumentJobClient", "DocumentJobHandle", "DocumentJobResult", "JobNotDoneError",
    "ManagementClient", "WebApiRequestHandler", "TranslatorClientMessageHandler",
    "SignedKeyAnnouncement",
    "Transport", "UrllibTransport",
    "DocumentJobLimits", "DocumentJobState", "DocumentResult", "GetDocumentJobResponse",
    "PingRequest", "PingResponse", "RequestType", "ResultType",
    "SERVICE_URL", "SERVICE_VERIFICATION_KEY",
    "IPTranslatorError", "ServiceError", "QuotaExceededError", "ServiceCanceledError",
    "TransportError", "EncryptionError", "ResponseCode",
]
