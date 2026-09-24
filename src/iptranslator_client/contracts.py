"""Wire contracts of the web API, trimmed to what this client needs.

Two JSON conventions meet here, exactly as in the .NET client:

* the plaintext transport **envelope** and its actions (Ping, the document-job
  actions) use PascalCase member names (``CorrelationId``, ``JobId`` ...);
* the end-to-end encrypted **messages** (``TranslatorRequestMessage`` /
  ``TranslatorResponseMessage`` and their bodies) use snake_case, string enums
  and base64 for binary fields — the service mirrors them as strict pydantic
  models.

Unknown members are ignored on parsing and ``None`` members are omitted on
serialization, so the client stays wire-safe against a newer service.
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# enums (member names are the wire contract; never reorder)
# ---------------------------------------------------------------------------

class RequestType(str, Enum):
    translate = "translate"
    translate_align = "translate_align"
    translate_document = "translate_document"  # batch whole-document job
    align = "align"
    evaluate = "evaluate"
    embed = "embed"
    replace = "replace"
    split = "split"
    probe = "probe"
    unreadable = "unreadable"


class ResultType(str, Enum):
    translations_top_k = "translations_top_k"
    translations_segments = "translations_segments"
    translation_alignment = "translation_alignment"
    document = "document"  # summary result of a translate_document job
    alignments = "alignments"
    evaluations = "evaluations"
    embeddings = "embeddings"
    status = "status"
    error = "error"


class DocumentJobState(str, Enum):
    queued = "queued"
    running = "running"
    done = "done"
    failed = "failed"
    cancelled = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in (DocumentJobState.done, DocumentJobState.failed, DocumentJobState.cancelled)


def _enum(cls, value, default=None):
    """Parse an enum from its wire name; tolerate ordinals (some relay paths
    serialize enums as int) and unknown values."""
    if value is None:
        return default
    if isinstance(value, cls):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        members = list(cls)
        return members[value] if 0 <= value < len(members) else default
    try:
        return cls(str(value))
    except ValueError:
        return default


def _b64(data: Optional[bytes]) -> Optional[str]:
    return None if data is None else base64.b64encode(data).decode("ascii")


def _unb64(text: Optional[str]) -> Optional[bytes]:
    return None if text is None else base64.b64decode(text)


def _drop_none(d: dict) -> dict:
    return {k: v for k, v in d.items() if v is not None}


# ---------------------------------------------------------------------------
# limits shared with the service
# ---------------------------------------------------------------------------

class DocumentJobLimits:
    MAX_TRANSLATION_MEMORIES = 16
    DICTIONARY_FORMATS = ("csv", "tsv", "xlsx")
    MAX_WAIT_SECONDS = 25


# ---------------------------------------------------------------------------
# end-to-end encrypted messages (snake_case)
# ---------------------------------------------------------------------------

@dataclass
class TranslatorRequestBody:
    """The encrypted body of a request. Only the members a document job uses
    are modelled; ``src_text`` is ``[]`` for document jobs (the document lives in
    blob storage — claim-check pattern)."""

    scope_key: str
    type: RequestType
    src_lang: str
    trg_lang: Optional[str] = None
    task: Optional[str] = None
    desired_beamwidth: Optional[int] = None
    src_text: list[str] = field(default_factory=list)
    trg_text: Optional[list[Optional[str]]] = None
    doc_job_id: Optional[str] = None
    doc_input_url: Optional[str] = None    # SAS, read: encrypted input document (slot 'in')
    doc_output_url: Optional[str] = None   # SAS, create+write: encrypted result (slot 'out')
    doc_status_url: Optional[str] = None   # SAS, create+write: plaintext, content-free progress
    doc_cancel_url: Optional[str] = None   # SAS, read: blob existence = cancel requested
    doc_usage_url: Optional[str] = None    # SAS, create+write: plaintext, content-free usage
    doc_key: Optional[bytes] = None        # 32-byte blob key; confidential — only ever inside the encrypted body
    doc_finalize: Optional[bool] = None
    doc_dict_url: Optional[str] = None     # SAS, read: encrypted dictionary file (slot 'dict')
    doc_dict_format: Optional[str] = None  # 'csv' | 'tsv' | 'xlsx'; required with doc_dict_url
    doc_tm_urls: Optional[list[str]] = None  # SAS, read: encrypted TMX files (slots 'tm0'..)

    def to_json(self) -> dict:
        return _drop_none({
            "scope_key": self.scope_key,
            "type": self.type.value,
            "task": self.task,
            "desired_beamwidth": self.desired_beamwidth,
            "src_lang": self.src_lang,
            "trg_lang": self.trg_lang,
            "src_text": list(self.src_text),
            "trg_text": None if self.trg_text is None else list(self.trg_text),
            "doc_job_id": self.doc_job_id,
            "doc_input_url": self.doc_input_url,
            "doc_output_url": self.doc_output_url,
            "doc_status_url": self.doc_status_url,
            "doc_cancel_url": self.doc_cancel_url,
            "doc_usage_url": self.doc_usage_url,
            "doc_key": _b64(self.doc_key),
            "doc_finalize": self.doc_finalize,
            "doc_dict_url": self.doc_dict_url,
            "doc_dict_format": self.doc_dict_format,
            "doc_tm_urls": None if self.doc_tm_urls is None else list(self.doc_tm_urls),
        })


@dataclass
class DocumentResult:
    """Summary of a translate_document job (encrypted response body). Per-segment
    content stays inside the output blob; this only carries counts and state."""

    job_id: str
    state: Optional[DocumentJobState]
    total: int = 0          # segments in the document
    translated: int = 0     # segments translated by this job (incl. tm_translated)
    failed: int = 0         # segments that failed individually (job still completes)
    tm_translated: int = 0  # of translated: applied from an exact TM match (unbilled)

    @classmethod
    def from_json(cls, d: dict) -> "DocumentResult":
        return cls(
            job_id=d.get("job_id") or "",
            state=_enum(DocumentJobState, d.get("state")),
            total=int(d.get("total") or 0),
            translated=int(d.get("translated") or 0),
            failed=int(d.get("failed") or 0),
            tm_translated=int(d.get("tm_translated") or 0),
        )


@dataclass
class TranslatorResponseBody:
    result_type: Optional[ResultType]
    error_details: Optional[str] = None
    allowed_beamwidth: Optional[int] = None
    document: Optional[DocumentResult] = None
    raw: dict = field(default_factory=dict, repr=False)  # the full decrypted body

    @classmethod
    def from_json(cls, d: dict) -> "TranslatorResponseBody":
        doc = d.get("document")
        return cls(
            result_type=_enum(ResultType, d.get("result_type")),
            error_details=d.get("error_details"),
            allowed_beamwidth=d.get("allowed_beamwidth"),
            document=None if doc is None else DocumentResult.from_json(doc),
            raw=d,
        )


@dataclass
class TranslatorRequestMessage:
    request_id: str
    maybe_encrypted_body: bytes
    key_id: Optional[str] = None
    encrypted_key: Optional[bytes] = None
    entropy: Optional[bytes] = None

    def to_json(self) -> dict:
        return _drop_none({
            "request_id": self.request_id,
            "key_id": self.key_id,
            "encrypted_key": _b64(self.encrypted_key),
            "entropy": _b64(self.entropy),
            "maybe_encrypted_body": _b64(self.maybe_encrypted_body),
        })


@dataclass
class TranslatorResponseMessage:
    request_id: str
    request_type: Optional[RequestType]
    object_id: Optional[bytes]
    consumed_units: int
    maybe_encrypted_body: bytes
    time_ms: float = 0.0
    node: Optional[str] = None
    model: Optional[str] = None
    task: Optional[str] = None
    src_lang: Optional[str] = None
    trg_lang: Optional[str] = None
    unsafe_error: Optional[str] = None
    key_id: Optional[str] = None
    entropy: Optional[bytes] = None
    request_type_raw: Optional[str] = None  # the wire name, as bound into the AAD

    @classmethod
    def from_json(cls, d: dict) -> "TranslatorResponseMessage":
        raw_type = d.get("request_type")
        return cls(
            request_id=d.get("request_id") or "",
            request_type=_enum(RequestType, raw_type),
            request_type_raw=None if raw_type is None else str(raw_type),
            object_id=_unb64(d.get("object_id")),
            consumed_units=int(d.get("consumed_units") or 0),
            maybe_encrypted_body=_unb64(d.get("maybe_encrypted_body")) or b"",
            time_ms=float(d.get("time_ms") or 0.0),
            node=d.get("node"),
            model=d.get("model"),
            task=d.get("task"),
            src_lang=d.get("src_lang"),
            trg_lang=d.get("trg_lang"),
            unsafe_error=d.get("unsafe_error"),
            key_id=d.get("key_id"),
            entropy=_unb64(d.get("entropy")),
        )


# ---------------------------------------------------------------------------
# envelope actions (PascalCase)
# ---------------------------------------------------------------------------

@dataclass
class PingRequest:
    client: Optional[str] = None
    client_version: Optional[str] = None

    def to_json(self) -> dict:
        return _drop_none({"Client": self.client, "ClientVersion": self.client_version})


@dataclass
class PingResponse:
    instance_id: Optional[str] = None
    has_license: bool = False
    licensee_name: Optional[str] = None
    is_quota_exceeded: bool = False
    subscribe_uri: Optional[str] = None
    upgrade_uri: Optional[str] = None
    #: Base64 of the service's 1216-byte X-Wing public key; clients that pin a
    #: key MUST prefer the pinned key over this value.
    service_public_key: Optional[str] = None
    #: JSON of the hybrid-signed announcement of the X-Wing public key; see
    #: :class:`iptranslator_client.announcement.SignedKeyAnnouncement`.
    signed_service_public_key: Optional[str] = None

    @classmethod
    def from_json(cls, d: dict) -> "PingResponse":
        return cls(
            instance_id=d.get("InstanceId"),
            has_license=bool(d.get("HasLicense", False)),
            licensee_name=d.get("LicenseeName"),
            is_quota_exceeded=bool(d.get("IsQuotaExceeded", False)),
            subscribe_uri=d.get("SubscribeUri"),
            upgrade_uri=d.get("UpgradeUri"),
            service_public_key=d.get("ServicePublicKey"),
            signed_service_public_key=d.get("SignedServicePublicKey"),
        )


@dataclass
class CreateDocumentJobRequest:
    with_dictionary: bool = False
    translation_memory_count: int = 0

    def to_json(self) -> dict:
        return {"WithDictionary": self.with_dictionary,
                "TranslationMemoryCount": self.translation_memory_count}


@dataclass
class CreateDocumentJobResponse:
    job_id: str
    input_upload_url: Optional[str] = None      # client-facing SAS: PUT the encrypted input here
    worker_input_url: Optional[str] = None      # worker-facing SAS URLs: copied VERBATIM into the
    worker_output_url: Optional[str] = None     # encrypted job message
    worker_status_url: Optional[str] = None
    worker_cancel_url: Optional[str] = None
    worker_usage_url: Optional[str] = None
    dictionary_upload_url: Optional[str] = None
    worker_dictionary_url: Optional[str] = None
    translation_memory_upload_urls: Optional[list[str]] = None
    worker_translation_memory_urls: Optional[list[str]] = None

    @classmethod
    def from_json(cls, d: dict) -> "CreateDocumentJobResponse":
        return cls(
            job_id=str(d.get("JobId") or ""),
            input_upload_url=d.get("InputUploadUrl"),
            worker_input_url=d.get("WorkerInputUrl"),
            worker_output_url=d.get("WorkerOutputUrl"),
            worker_status_url=d.get("WorkerStatusUrl"),
            worker_cancel_url=d.get("WorkerCancelUrl"),
            worker_usage_url=d.get("WorkerUsageUrl"),
            dictionary_upload_url=d.get("DictionaryUploadUrl"),
            worker_dictionary_url=d.get("WorkerDictionaryUrl"),
            translation_memory_upload_urls=d.get("TranslationMemoryUploadUrls"),
            worker_translation_memory_urls=d.get("WorkerTranslationMemoryUrls"),
        )


@dataclass
class SubmitDocumentJobRequest:
    job_id: str
    message: TranslatorRequestMessage
    document_name: Optional[str] = None       # informational (usage report)
    document_custom_ref: Optional[str] = None  # informational (usage report)

    def to_json(self) -> dict:
        return _drop_none({
            "JobId": self.job_id,
            "DocumentName": self.document_name,
            "DocumentCustomRef": self.document_custom_ref,
            "Message": self.message.to_json(),
        })


@dataclass
class SubmitDocumentJobResponse:
    job_id: str

    @classmethod
    def from_json(cls, d: dict) -> "SubmitDocumentJobResponse":
        return cls(job_id=str(d.get("JobId") or ""))


@dataclass
class GetDocumentJobRequest:
    job_id: str
    wait_seconds: int = 0  # server-side hold (0–25): returns early on any change

    def to_json(self) -> dict:
        return {"JobId": self.job_id, "WaitSeconds": self.wait_seconds}


@dataclass
class GetDocumentJobResponse:
    job_id: str
    state: Optional[DocumentJobState]
    created: Optional[str] = None     # ISO 8601 as sent by the service
    completed: Optional[str] = None
    progress_done: int = 0
    progress_total: int = 0
    error_code: Optional[str] = None  # content-free, when state == failed
    consumed_units: int = 0           # from the completion envelope (terminal states only)
    document_id: Optional[str] = None  # binding identity usage was registered under (done only)
    result_url: Optional[str] = None  # read SAS for the encrypted result (done only)
    message: Optional[TranslatorResponseMessage] = None  # worker response envelope (terminal only)

    @classmethod
    def from_json(cls, d: dict) -> "GetDocumentJobResponse":
        msg = d.get("Message")
        return cls(
            job_id=str(d.get("JobId") or ""),
            state=_enum(DocumentJobState, d.get("State")),
            created=d.get("Created"),
            completed=d.get("Completed"),
            progress_done=int(d.get("ProgressDone") or 0),
            progress_total=int(d.get("ProgressTotal") or 0),
            error_code=d.get("ErrorCode") or None,
            consumed_units=int(d.get("ConsumedUnits") or 0),
            document_id=d.get("DocumentId"),
            result_url=d.get("ResultUrl"),
            message=None if msg is None else TranslatorResponseMessage.from_json(msg),
        )


@dataclass
class CancelDocumentJobRequest:
    job_id: str

    def to_json(self) -> dict:
        return {"JobId": self.job_id}


@dataclass
class CancelDocumentJobResponse:
    job_id: str
    cancelling: bool = False  # True when the request reached a non-terminal job

    @classmethod
    def from_json(cls, d: dict) -> "CancelDocumentJobResponse":
        return cls(job_id=str(d.get("JobId") or ""), cancelling=bool(d.get("Cancelling", False)))


# ---------------------------------------------------------------------------
# envelope
# ---------------------------------------------------------------------------

@dataclass
class EnvelopeRequest:
    """The plaintext transport envelope (one action per request)."""

    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    client: Optional[str] = None
    client_version: Optional[str] = None
    ping: Optional[PingRequest] = None
    create_document_job: Optional[CreateDocumentJobRequest] = None
    submit_document_job: Optional[SubmitDocumentJobRequest] = None
    get_document_job: Optional[GetDocumentJobRequest] = None
    cancel_document_job: Optional[CancelDocumentJobRequest] = None

    @property
    def action(self) -> str:
        for name in ("ping", "create_document_job", "submit_document_job",
                     "get_document_job", "cancel_document_job"):
            if getattr(self, name) is not None:
                return name
        return "empty"

    def to_json(self) -> dict:
        return _drop_none({
            "CorrelationId": self.correlation_id,
            "Client": self.client,
            "ClientVersion": self.client_version,
            "Ping": None if self.ping is None else self.ping.to_json(),
            "CreateDocumentJob": None if self.create_document_job is None else self.create_document_job.to_json(),
            "SubmitDocumentJob": None if self.submit_document_job is None else self.submit_document_job.to_json(),
            "GetDocumentJob": None if self.get_document_job is None else self.get_document_job.to_json(),
            "CancelDocumentJob": None if self.cancel_document_job is None else self.cancel_document_job.to_json(),
        })


@dataclass
class EnvelopeResponse:
    correlation_id: Optional[str] = None
    code: int = 200
    message: Optional[str] = None
    resolve_error_uri: Optional[str] = None
    ping: Optional[PingResponse] = None
    create_document_job: Optional[CreateDocumentJobResponse] = None
    submit_document_job: Optional[SubmitDocumentJobResponse] = None
    get_document_job: Optional[GetDocumentJobResponse] = None
    cancel_document_job: Optional[CancelDocumentJobResponse] = None
    instance_id: Optional[str] = None
    compute_time_sec: float = 0.0
    trip_time_sec: float = 0.0
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_json(cls, d: dict) -> "EnvelopeResponse":
        if not isinstance(d, dict):
            raise ValueError("envelope response must be a JSON object")

        def sub(name: str, parser):
            value = d.get(name)
            return None if value is None else parser(value)

        code = d.get("Code", 200)
        if isinstance(code, str):  # tolerate a name instead of the number
            from .errors import ResponseCode
            wanted = code.replace("_", "").upper()
            code = next((m.value for name, m in ResponseCode.__members__.items()
                         if name.replace("_", "") == wanted), ResponseCode.UNKNOWN.value)
        return cls(
            correlation_id=d.get("CorrelationId"),
            code=int(code),
            message=d.get("Message"),
            resolve_error_uri=d.get("ResolveErrorUri"),
            ping=sub("Ping", PingResponse.from_json),
            create_document_job=sub("CreateDocumentJob", CreateDocumentJobResponse.from_json),
            submit_document_job=sub("SubmitDocumentJob", SubmitDocumentJobResponse.from_json),
            get_document_job=sub("GetDocumentJob", GetDocumentJobResponse.from_json),
            cancel_document_job=sub("CancelDocumentJob", CancelDocumentJobResponse.from_json),
            instance_id=d.get("InstanceId"),
            compute_time_sec=float(d.get("ComputeTimeSec") or 0.0),
            trip_time_sec=float(d.get("TripTimeSec") or 0.0),
            raw=d,
        )
