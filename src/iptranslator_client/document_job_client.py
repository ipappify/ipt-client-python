"""Client for batch whole-document translation jobs, end-to-end encrypted."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from . import docblob
from ._version import __version__
from .contracts import (CancelDocumentJobRequest, CreateDocumentJobRequest, DocumentJobLimits,
                        DocumentJobState, DocumentResult, EnvelopeRequest, GetDocumentJobRequest,
                        GetDocumentJobResponse, RequestType, ResultType, SubmitDocumentJobRequest,
                        TranslatorRequestBody)
from .defaults import SERVICE_URL, SERVICE_VERIFICATION_KEY
from .errors import EncryptionError, IPTranslatorError, ResponseCode, ServiceError
from .management_client import ManagementClient
from .message_handler import TranslatorClientMessageHandler
from .request_handler import CLIENT_NAME, WebApiRequestHandler, raise_on_error
from .transport import Transport


@dataclass(frozen=True)
class DocumentJobHandle:
    job_id: uuid.UUID
    #: The per-job blob key (the client's own secret).
    document_key: bytes

    @property
    def job_id_wire(self) -> str:
        """The job id as it appears inside the messages (``request_id``, blob AAD):
        32 hex digits, no dashes — the .NET ``Guid.ToString("N")`` form."""
        return self.job_id.hex


@dataclass
class DocumentJobResult:
    #: The translated document (decrypted .docx bytes).
    document: bytes
    #: The worker's decrypted job summary (verified end-to-end).
    summary: Optional[DocumentResult]
    #: Billed units from the response envelope (GCM-AAD-bound).
    consumed_units: int


class JobNotDoneError(IPTranslatorError):
    """``get_result`` was called on a job that is not in state ``done``."""

    def __init__(self, status: GetDocumentJobResponse):
        self.status = status
        state = status.state.value if status.state else "unknown"
        super().__init__(f"Document job {status.job_id} is {state}, not done"
                         + (f" ({status.error_code})." if status.error_code else "."))


class DocumentJobClient:
    """The document is encrypted with a fresh per-job blob key
    (:mod:`iptranslator_client.docblob`, ``iptd-doc:v1``) and uploaded straight to
    blob storage; the job message carries the key and the worker-facing SAS
    URLs INSIDE its encrypted body, relayed unopened by the web app.

    Session-scoped: results can only be fetched through the same instance that
    submitted the job (the response envelope is bound to this session's message
    key, and the blob key lives in the returned handle).
    """

    def __init__(self, request_handler: WebApiRequestHandler, service_public_key_base64: str,
                 blob_transport: Transport | None = None):
        """
        :param request_handler: envelope transport (carries the API key).
        :param service_public_key_base64: the service's X-Wing public key —
            pinned, or obtained via :meth:`ManagementClient.resolve_service_public_key`.
        :param blob_transport: transport for the direct blob uploads/downloads
            (SAS URLs); defaults to the request handler's transport.
        """
        if request_handler is None:
            raise ValueError("request_handler is required")
        self.request_handler = request_handler
        self.message_handler = TranslatorClientMessageHandler(service_public_key_base64)
        self.blob_transport: Transport = blob_transport or request_handler.transport
        self.client = CLIENT_NAME
        self.client_version = __version__

    # ---------- public API ----------

    def submit(self, document_name: str, document_bytes: bytes,
               source_language: str, target_language: str,
               finalize: bool = True, task: str | None = None, beam_width: int | None = None,
               document_custom_ref: str | None = None,
               dictionary: bytes | None = None, dictionary_format: str | None = None,
               translation_memories: Sequence[bytes] | None = None) -> DocumentJobHandle:
        """Create a job, upload the encrypted document, and submit the encrypted
        job message. Returns the handle for polling / fetching.

        ``document_name`` / ``document_custom_ref`` are informational (usage
        report); the BILLING identity is read from (or minted into) the
        document's IP.Translator binding by the worker. ``dictionary`` is an
        optional csv/tsv/xlsx file (``dictionary_format`` required with it);
        ``translation_memories`` are optional TMX files — exact source matches
        are applied directly (unbilled), the rest becomes translation context.
        """
        if not document_bytes:
            raise ValueError("document_bytes required")
        if dictionary is not None and dictionary_format not in DocumentJobLimits.DICTIONARY_FORMATS:
            raise ValueError("dictionary_format must be csv, tsv or xlsx")
        if dictionary is None and dictionary_format is not None:
            raise ValueError("dictionary_format requires dictionary")
        translation_memories = list(translation_memories or [])
        if len(translation_memories) > DocumentJobLimits.MAX_TRANSLATION_MEMORIES:
            raise ValueError(f"At most {DocumentJobLimits.MAX_TRANSLATION_MEMORIES} translation memories are supported")
        if not source_language or not target_language:
            raise ValueError("source_language and target_language are required")

        # 1. create: job id + SAS URLs (incl. the optional-input slots)
        created = self._send(EnvelopeRequest(create_document_job=CreateDocumentJobRequest(
            with_dictionary=dictionary is not None,
            translation_memory_count=len(translation_memories),
        ))).create_document_job
        if created is None or not created.job_id:
            raise ServiceError(ResponseCode.SERVICE_ERROR, "CreateDocumentJob returned no job.")
        job_id = uuid.UUID(created.job_id)
        job_id_wire = job_id.hex
        if dictionary is not None and not (created.dictionary_upload_url and created.worker_dictionary_url):
            raise ServiceError(ResponseCode.SERVICE_ERROR, "the service issued no dictionary upload slot.")
        if translation_memories and (
                len(created.translation_memory_upload_urls or []) < len(translation_memories)
                or len(created.worker_translation_memory_urls or []) < len(translation_memories)):
            raise ServiceError(ResponseCode.SERVICE_ERROR, "the service issued too few translation-memory slots.")

        # 2. encrypt + upload the document (slot 'in') and the optional inputs,
        # each sealed under its own AAD slot with the same job key
        document_key = docblob.new_key()
        self._upload(created.input_upload_url,
                     docblob.encrypt(document_key, job_id_wire, docblob.DIRECTION_IN, document_bytes))
        if dictionary is not None:
            self._upload(created.dictionary_upload_url,
                         docblob.encrypt(document_key, job_id_wire, docblob.DICTIONARY_SLOT, dictionary))
        for i, tm in enumerate(translation_memories):
            self._upload(created.translation_memory_upload_urls[i],
                         docblob.encrypt(document_key, job_id_wire, docblob.translation_memory_slot(i), tm))

        # 3. encrypted job message: blob key + worker URLs travel inside the body.
        # scope_key is only the worker's hash-scope FALLBACK — the binding's
        # document key read/minted by DocTool takes precedence.
        body = TranslatorRequestBody(
            scope_key=job_id_wire,
            type=RequestType.translate_document,
            task=task or "",
            desired_beamwidth=beam_width,
            src_lang=source_language,
            trg_lang=target_language,
            src_text=[],
            doc_job_id=job_id_wire,
            doc_input_url=created.worker_input_url,
            doc_output_url=created.worker_output_url,
            doc_status_url=created.worker_status_url,
            doc_cancel_url=created.worker_cancel_url,
            doc_usage_url=created.worker_usage_url,
            doc_key=document_key,
            doc_finalize=finalize,
            doc_dict_url=created.worker_dictionary_url if dictionary is not None else None,
            doc_dict_format=dictionary_format if dictionary is not None else None,
            doc_tm_urls=list(created.worker_translation_memory_urls[:len(translation_memories)])
            if translation_memories else None,
        )
        # correlation contract: request_id == JobId ("N")
        message = self.message_handler.build_request(body, job_id_wire)

        self._send(EnvelopeRequest(submit_document_job=SubmitDocumentJobRequest(
            job_id=str(job_id),
            document_name=document_name,
            document_custom_ref=document_custom_ref,
            message=message,
        )))
        return DocumentJobHandle(job_id=job_id, document_key=document_key)

    def get_status(self, handle: DocumentJobHandle, wait_seconds: int = 0) -> GetDocumentJobResponse:
        """Current job state and progress. ``wait_seconds`` (0–25) asks the
        server to hold the call until something changes — the polling loop stays
        responsive without tight polling."""
        if not 0 <= wait_seconds <= DocumentJobLimits.MAX_WAIT_SECONDS:
            raise ValueError(f"wait_seconds must be 0..{DocumentJobLimits.MAX_WAIT_SECONDS}")
        response = self._send(EnvelopeRequest(get_document_job=GetDocumentJobRequest(
            job_id=str(handle.job_id), wait_seconds=wait_seconds)))
        if response.get_document_job is None:
            raise ServiceError(ResponseCode.SERVICE_ERROR, "GetDocumentJob returned no status.")
        return response.get_document_job

    def wait(self, handle: DocumentJobHandle, wait_seconds: int = 20,
             on_progress: Callable[[GetDocumentJobResponse], None] | None = None,
             should_cancel: Callable[[], bool] | None = None,
             poll_interval: float = 0.0) -> GetDocumentJobResponse:
        """Poll until the job reaches a terminal state. ``on_progress`` is called
        whenever state or progress changes; ``should_cancel`` is checked after
        every poll and, when true, asks the service to cancel the job (the
        terminal status is still returned). ``poll_interval`` adds a client-side
        pause between polls (not needed with a server-side hold)."""
        last = (None, -1)
        while True:
            status = self.get_status(handle, wait_seconds)
            key = (status.state, status.progress_done)
            if key != last and on_progress is not None:
                on_progress(status)
            last = key
            if status.state is not None and status.state.is_terminal:
                return status
            if should_cancel is not None and should_cancel():
                self.cancel(handle)
                wait_seconds = min(wait_seconds, 5)
            if poll_interval > 0:
                time.sleep(poll_interval)

    def get_result(self, handle: DocumentJobHandle) -> DocumentJobResult:
        """Download and decrypt the result of a DONE job, decrypt the worker's
        job summary from the response envelope, and verify the id echo."""
        status = self.get_status(handle, 0)
        if status.state != DocumentJobState.done:
            raise JobNotDoneError(status)
        if not status.result_url or status.message is None:
            raise ServiceError(ResponseCode.SERVICE_ERROR,
                               "Job is done but result URL or response message is missing.")

        # end-to-end verification: decrypt the response body with the session
        # key — the GCM AAD binds request_id, consumed_units and object_id
        body, request_id = self.message_handler.parse_response(status.message)
        if (request_id or "").lower() != handle.job_id_wire:
            raise EncryptionError("Response request id does not match the job.")
        if body.result_type == ResultType.error:
            raise ServiceError(ResponseCode.SERVICE_ERROR, f"Service failed with: {body.error_details}")

        encrypted = self.blob_transport.get_blob(status.result_url, self.request_handler.timeout)
        document = docblob.decrypt(handle.document_key, handle.job_id_wire, docblob.DIRECTION_OUT, encrypted)
        return DocumentJobResult(document=document, summary=body.document,
                                 consumed_units=status.message.consumed_units)

    def cancel(self, handle: DocumentJobHandle) -> bool:
        """Request cancellation; True when the job was still cancellable."""
        response = self._send(EnvelopeRequest(cancel_document_job=CancelDocumentJobRequest(str(handle.job_id))))
        return bool(response.cancel_document_job and response.cancel_document_job.cancelling)

    # ---------- internals ----------

    def _send(self, request: EnvelopeRequest):
        request.client = self.client
        request.client_version = self.client_version
        response = self.request_handler.send(request)
        raise_on_error(response)
        return response

    def _upload(self, sas_url: str | None, blob: bytes) -> None:
        if not sas_url:
            raise ServiceError(ResponseCode.SERVICE_ERROR, "the service issued no upload URL.")
        self.blob_transport.put_blob(sas_url, blob, self.request_handler.timeout)


def connect(service_url: str = SERVICE_URL, api_key: str | None = None, *,
            service_public_key: str | None = None,
            verification_key: str = SERVICE_VERIFICATION_KEY,
            transport: Transport | None = None, timeout: float | None = None) -> DocumentJobClient:
    """Convenience constructor: builds the request handler and resolves the
    service's encryption key. A pinned ``service_public_key`` (base64 X-Wing key)
    is used as is; otherwise the key is taken from the Ping response's signed
    announcement, verified against ``verification_key`` (default: the built-in
    production verification key)."""
    kwargs = {} if timeout is None else {"timeout": timeout}
    request_handler = WebApiRequestHandler(service_url, api_key, transport, **kwargs)
    if not service_public_key:
        service_public_key = ManagementClient(request_handler).resolve_service_public_key(verification_key)
    return DocumentJobClient(request_handler, service_public_key)
