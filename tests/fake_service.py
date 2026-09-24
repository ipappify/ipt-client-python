"""An in-memory stand-in for the web app + blob storage + GPU worker, driven
through the client's Transport protocol. It holds the service's X-Wing private
key (reference decapsulation) and a hybrid signing key, so it can play the
whole protocol: Ping with a signed announcement, CreateDocumentJob with SAS
URLs, the worker decrypting the submitted job message and the blobs, and the
end-to-end verified completion envelope."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from iptranslator_client import docblob
from iptranslator_client.errors import TransportError
from iptranslator_client.message_handler import request_aad
from tests import xwing_ref


class FakeService:
    def __init__(self, api_key: str = "test-api-key", consumed_units: int = 7,
                 polls_until_done: int = 2, translate=lambda doc: b"translated:" + doc):
        self.api_key = api_key
        self.consumed_units = consumed_units
        self.polls_until_done = polls_until_done
        self.translate = translate

        self.seed, public_key = xwing_ref.generate_key_pair()
        self.public_key_base64 = base64.b64encode(public_key).decode("ascii")
        self._ed = Ed25519PrivateKey.generate()
        self._ml = MLDSA65PrivateKey.generate()
        self.verification_key_base64 = base64.b64encode(
            self._ed.public_key().public_bytes_raw() + self._ml.public_key().public_bytes_raw()).decode("ascii")

        self.blobs: dict[str, bytes] = {}
        self.jobs: dict[str, dict] = {}
        self.requests: list[dict] = []   # every envelope the client sent (parsed)
        self.headers: list[dict] = []
        self.worker_inputs: dict[str, dict] = {}  # what the "worker" decrypted per job
        self.fail_next: dict | None = None  # {"Code": .., "Message": .., "ResolveErrorUri": ..}
        self.worker_error: str | None = None  # make the job fail with this error code
        self.tamper_status = None  # callable(status_dict) -> status_dict

    # ---- announcement ----

    def signed_announcement(self, not_before=None, not_after=None) -> str:
        now = int(time.time())
        not_before = now - 3600 if not_before is None else not_before
        not_after = now + 3600 if not_after is None else not_after
        payload = f"iptr-key:v1:{self.public_key_base64}:{not_before}:{not_after}".encode("utf8")
        return json.dumps({
            "public_key": self.public_key_base64,
            "not_before": not_before,
            "not_after": not_after,
            "sig_ed25519": base64.b64encode(self._ed.sign(payload)).decode("ascii"),
            "sig_mldsa65": base64.b64encode(self._ml.sign(payload)).decode("ascii"),
        })

    # ---- Transport protocol ----

    def post_json(self, url: str, body: str, headers, timeout: float) -> str:
        assert url.endswith("/translate"), url
        self.headers.append(dict(headers))
        if headers.get("Authorization") != f"ApiKey {self.api_key}":
            raise TransportError("HTTP 401 Unauthorized", status=401, url=url)
        envelope = json.loads(body)
        self.requests.append(envelope)
        response = {"CorrelationId": envelope.get("CorrelationId"), "Code": 200, "Message": None,
                    "InstanceId": str(uuid.uuid4()), "ComputeTimeSec": 0.01, "TripTimeSec": 0.02}
        if self.fail_next is not None:
            response.update(self.fail_next)
            self.fail_next = None
            return json.dumps(response)
        if "Ping" in envelope:
            response["Ping"] = self._ping(envelope["Ping"])
        elif "CreateDocumentJob" in envelope:
            response["CreateDocumentJob"] = self._create(envelope["CreateDocumentJob"])
        elif "SubmitDocumentJob" in envelope:
            response["SubmitDocumentJob"] = self._submit(envelope["SubmitDocumentJob"])
        elif "GetDocumentJob" in envelope:
            response["GetDocumentJob"] = self._get(envelope["GetDocumentJob"])
        elif "CancelDocumentJob" in envelope:
            response["CancelDocumentJob"] = self._cancel(envelope["CancelDocumentJob"])
        else:
            response.update({"Code": 400, "Message": "no action"})
        return json.dumps(response)

    def put_blob(self, url: str, data: bytes, timeout: float) -> None:
        assert "?sas=upload" in url, f"upload to a non-upload URL: {url}"
        self.blobs[url.split("?")[0]] = bytes(data)

    def get_blob(self, url: str, timeout: float) -> bytes:
        assert "?sas=result" in url, f"download from a non-result URL: {url}"
        try:
            return self.blobs[url.split("?")[0]]
        except KeyError:
            raise TransportError("HTTP 404 Not Found", status=404, url=url) from None

    # ---- actions ----

    def _ping(self, request: dict) -> dict:
        return {"InstanceId": str(uuid.uuid4()), "HasLicense": True, "LicenseeName": "Test GmbH",
                "IsQuotaExceeded": False, "ServicePublicKey": self.public_key_base64,
                "SignedServicePublicKey": self.signed_announcement()}

    def _create(self, request: dict) -> dict:
        job_id = str(uuid.uuid4())
        base = f"https://blobs.test/jobs/{job_id}"
        job = {"state": "queued", "polls": 0, "with_dictionary": bool(request.get("WithDictionary")),
               "tm_count": int(request.get("TranslationMemoryCount") or 0), "base": base,
               "created": "2026-09-24T10:00:00+00:00", "completed": None, "done": 0, "total": 0,
               "consumed_units": 0, "error_code": None, "message": None}
        self.jobs[job_id] = job
        response = {
            "JobId": job_id,
            "InputUploadUrl": f"{base}/in?sas=upload",
            "WorkerInputUrl": f"{base}/in?sas=worker-read",
            "WorkerOutputUrl": f"{base}/out?sas=worker-write",
            "WorkerStatusUrl": f"{base}/status.json?sas=worker-write",
            "WorkerCancelUrl": f"{base}/cancel?sas=worker-read",
            "WorkerUsageUrl": f"{base}/usage.json?sas=worker-write",
            "DictionaryUploadUrl": None, "WorkerDictionaryUrl": None,
            "TranslationMemoryUploadUrls": None, "WorkerTranslationMemoryUrls": None,
        }
        if job["with_dictionary"]:
            response["DictionaryUploadUrl"] = f"{base}/dict?sas=upload"
            response["WorkerDictionaryUrl"] = f"{base}/dict?sas=worker-read"
        if job["tm_count"]:
            response["TranslationMemoryUploadUrls"] = [f"{base}/tm{i}?sas=upload" for i in range(job["tm_count"])]
            response["WorkerTranslationMemoryUrls"] = [f"{base}/tm{i}?sas=worker-read" for i in range(job["tm_count"])]
        return response

    def _submit(self, request: dict) -> dict:
        job = self.jobs[request["JobId"]]
        message = request["Message"]
        job_id_wire = uuid.UUID(request["JobId"]).hex
        assert message["request_id"] == job_id_wire, "correlation contract: request_id == JobId (N)"
        job["document_name"] = request.get("DocumentName")
        job["document_custom_ref"] = request.get("DocumentCustomRef")
        job["submit_json"] = json.dumps(request)

        # --- the worker: decapsulate the session key, open the body ---
        session_key = xwing_ref.decrypt_key(self.seed, base64.b64decode(message["encrypted_key"]))
        body = json.loads(AESGCM(session_key).decrypt(
            base64.b64decode(message["entropy"]), base64.b64decode(message["maybe_encrypted_body"]),
            request_aad(message["request_id"], message["key_id"])))
        assert body["type"] == "translate_document"
        assert body["doc_job_id"] == job_id_wire
        assert body["src_text"] == []
        assert body["doc_input_url"] == f"{job['base']}/in?sas=worker-read"
        assert body["doc_output_url"] == f"{job['base']}/out?sas=worker-write"
        assert body["doc_status_url"] == f"{job['base']}/status.json?sas=worker-write"
        assert body["doc_cancel_url"] == f"{job['base']}/cancel?sas=worker-read"
        assert body["doc_usage_url"] == f"{job['base']}/usage.json?sas=worker-write"
        doc_key = base64.b64decode(body["doc_key"])
        document = docblob.decrypt(doc_key, job_id_wire, docblob.DIRECTION_IN, self.blobs[f"{job['base']}/in"])
        inputs = {"body": body, "document": document, "dictionary": None, "translation_memories": []}
        if body.get("doc_dict_url"):
            assert body["doc_dict_url"] == f"{job['base']}/dict?sas=worker-read"
            inputs["dictionary"] = docblob.decrypt(doc_key, job_id_wire, docblob.DICTIONARY_SLOT,
                                                   self.blobs[f"{job['base']}/dict"])
        for i, url in enumerate(body.get("doc_tm_urls") or []):
            assert url == f"{job['base']}/tm{i}?sas=worker-read"
            inputs["translation_memories"].append(docblob.decrypt(
                doc_key, job_id_wire, docblob.translation_memory_slot(i), self.blobs[f"{job['base']}/tm{i}"]))
        self.worker_inputs[request["JobId"]] = inputs

        # --- the worker's completion: result blob + AAD-bound response envelope ---
        job["total"] = 10
        if self.worker_error:
            job["final_state"] = "failed"
            job["error_code"] = self.worker_error
            result = {"result_type": "error", "error_details": "worker said no"}
            units, object_id = 0, b""
        else:
            job["final_state"] = "done"
            self.blobs[f"{job['base']}/out"] = docblob.encrypt(
                doc_key, job_id_wire, docblob.DIRECTION_OUT, self.translate(document))
            result = {"result_type": "document", "document": {
                "job_id": job_id_wire, "state": "done", "total": 10, "translated": 9, "failed": 1,
                "tm_translated": len(inputs["translation_memories"])}}
            units, object_id = self.consumed_units, hashlib.sha256(job_id_wire.encode()).digest()
        oid = base64.b64encode(object_id).decode("ascii") if object_id else ""
        aad = (f"iptv3-rsp:v1:{message['request_id']}:{message['key_id']}:translate_document:"
               f"{units}:{oid}").encode("utf8")
        entropy = os.urandom(12)
        encrypted = AESGCM(session_key).encrypt(entropy, json.dumps(result).encode("utf8"), aad)
        job["consumed_units"] = units
        job["message"] = {
            "request_id": message["request_id"], "request_type": "translate_document",
            "object_id": oid or None, "consumed_units": units, "time_ms": 1234.5,
            "node": "batch-1", "model": "test", "task": body.get("task"),
            "src_lang": body["src_lang"], "trg_lang": body["trg_lang"], "unsafe_error": None,
            "key_id": message["key_id"], "entropy": base64.b64encode(entropy).decode("ascii"),
            "maybe_encrypted_body": base64.b64encode(encrypted).decode("ascii"),
        }
        return {"JobId": request["JobId"]}

    def _get(self, request: dict) -> dict:
        job = self.jobs[request["JobId"]]
        assert 0 <= int(request.get("WaitSeconds", 0)) <= 25
        if job["state"] in ("queued", "running") and job.get("message") is not None:
            job["polls"] += 1
            if job["polls"] >= self.polls_until_done:
                job["state"] = job["final_state"]
                job["done"] = job["total"]
                job["completed"] = "2026-09-24T10:05:00+00:00"
            else:
                job["state"] = "running"
                job["done"] = 3
        terminal = job["state"] in ("done", "failed", "cancelled")
        status = {
            "JobId": request["JobId"], "State": job["state"], "Created": job["created"],
            "Completed": job["completed"], "ProgressDone": job["done"], "ProgressTotal": job["total"],
            "ErrorCode": job["error_code"], "ConsumedUnits": job["consumed_units"] if terminal else 0,
            "DocumentId": "00000000-0000-0000-0000-000000000000" if job["state"] != "done" else str(uuid.uuid4()),
            "ResultUrl": f"{job['base']}/out?sas=result" if job["state"] == "done" else None,
            # a fresh copy per poll, like a real JSON response (tampering must not stick)
            "Message": json.loads(json.dumps(job["message"])) if terminal and job["state"] != "cancelled" else None,
        }
        if self.tamper_status is not None:
            status = self.tamper_status(status)
        return status

    def _cancel(self, request: dict) -> dict:
        job = self.jobs[request["JobId"]]
        cancelling = job["state"] in ("queued", "running")
        if cancelling:
            job["state"] = "cancelled"
            job["completed"] = "2026-09-24T10:01:00+00:00"
        return {"JobId": request["JobId"], "Cancelling": cancelling}
