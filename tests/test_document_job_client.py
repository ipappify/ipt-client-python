import base64
import uuid

import pytest

from iptranslator_client import (DocumentJobClient, DocumentJobState, EncryptionError, JobNotDoneError,
                                 ManagementClient, QuotaExceededError, ServiceCanceledError,
                                 ServiceError, TransportError, WebApiRequestHandler, connect)
from iptranslator_client.errors import ResponseCode
from tests.fake_service import FakeService

DOC = b"PK\x03\x04 fake docx " * 100


@pytest.fixture
def service():
    return FakeService()


@pytest.fixture
def client(service):
    handler = WebApiRequestHandler("https://service.test/", service.api_key, transport=service)
    return DocumentJobClient(handler, service.public_key_base64)


def test_full_flow_with_optional_inputs(service, client):
    tms = [b"<tmx>1</tmx>", b"<tmx>2</tmx>"]
    handle = client.submit("patent.docx", DOC, "de", "en", finalize=True, task="patent", beam_width=4,
                           document_custom_ref="case-42", dictionary=b"a;b\n", dictionary_format="csv",
                           translation_memories=tms)

    # what the worker decrypted equals what the client sealed, slot by slot
    inputs = service.worker_inputs[str(handle.job_id)]
    assert inputs["document"] == DOC
    assert inputs["dictionary"] == b"a;b\n"
    assert inputs["translation_memories"] == tms
    body = inputs["body"]
    assert body["scope_key"] == handle.job_id_wire
    assert body["task"] == "patent" and body["desired_beamwidth"] == 4
    assert body["src_lang"] == "de" and body["trg_lang"] == "en"
    assert body["doc_finalize"] is True and body["doc_dict_format"] == "csv"
    assert base64.b64decode(body["doc_key"]) == handle.document_key

    # the blob key never appears in plaintext on the wire
    job = service.jobs[str(handle.job_id)]
    assert base64.b64encode(handle.document_key).decode() not in job["submit_json"]
    assert job["document_name"] == "patent.docx" and job["document_custom_ref"] == "case-42"
    # envelope conventions: PascalCase, client stamp, API key header
    create = service.requests[0]
    assert create["CreateDocumentJob"] == {"WithDictionary": True, "TranslationMemoryCount": 2}
    assert create["Client"] == "iptranslator-client" and create["ClientVersion"]
    assert all(h["Authorization"] == "ApiKey test-api-key" for h in service.headers)

    progress = []
    status = client.wait(handle, wait_seconds=20, on_progress=progress.append)
    assert status.state == DocumentJobState.done
    assert [(s.state, s.progress_done) for s in progress] == [
        (DocumentJobState.running, 3), (DocumentJobState.done, 10)]
    assert status.consumed_units == 7 and status.result_url and status.document_id

    result = client.get_result(handle)
    assert result.document == b"translated:" + DOC
    assert result.consumed_units == 7
    assert result.summary.translated == 9 and result.summary.failed == 1 and result.summary.tm_translated == 2
    assert result.summary.state == DocumentJobState.done and result.summary.job_id == handle.job_id_wire


def test_minimal_submit_has_no_optional_slots(service, client):
    handle = client.submit("a.docx", DOC, "en", "de", finalize=False)
    body = service.worker_inputs[str(handle.job_id)]["body"]
    assert body["doc_finalize"] is False and body["task"] == ""
    assert "doc_dict_url" not in body and "doc_dict_format" not in body and "doc_tm_urls" not in body
    assert "desired_beamwidth" not in body
    assert service.requests[0]["CreateDocumentJob"] == {"WithDictionary": False, "TranslationMemoryCount": 0}
    assert "DocumentCustomRef" not in service.requests[1]["SubmitDocumentJob"]
    assert client.wait(handle).state == DocumentJobState.done
    assert client.get_result(handle).document == b"translated:" + DOC


def test_tampered_billing_fields_are_detected(service, client):
    handle = client.submit("a.docx", DOC, "de", "en")
    client.wait(handle)

    def inflate(status):
        status["Message"]["consumed_units"] += 1
        return status
    service.tamper_status = inflate
    with pytest.raises(EncryptionError, match="authentication failed"):
        client.get_result(handle)

    def swap_request_id(status):
        status["Message"]["request_id"] = uuid.uuid4().hex
        return status
    service.tamper_status = swap_request_id
    with pytest.raises(EncryptionError):
        client.get_result(handle)

    def swap_object_id(status):
        status["Message"]["object_id"] = base64.b64encode(b"\x00" * 32).decode()
        return status
    service.tamper_status = swap_object_id
    with pytest.raises(EncryptionError, match="authentication failed"):
        client.get_result(handle)

    service.tamper_status = None
    assert client.get_result(handle).document == b"translated:" + DOC


def test_result_from_another_session_is_rejected(service, client):
    handle = client.submit("a.docx", DOC, "de", "en")
    client.wait(handle)
    other = DocumentJobClient(client.request_handler, service.public_key_base64)
    with pytest.raises(EncryptionError, match="key_id"):
        other.get_result(handle)


def test_get_result_before_done(service, client):
    service.polls_until_done = 100
    handle = client.submit("a.docx", DOC, "de", "en")
    with pytest.raises(JobNotDoneError, match="running, not done"):
        client.get_result(handle)


def test_failed_job(service, client):
    service.worker_error = "unsupported_document"
    handle = client.submit("a.docx", DOC, "de", "en")
    status = client.wait(handle)
    assert status.state == DocumentJobState.failed and status.error_code == "unsupported_document"
    with pytest.raises(JobNotDoneError, match=r"failed, not done \(unsupported_document\)"):
        client.get_result(handle)


def test_cancel(service, client):
    service.polls_until_done = 100
    handle = client.submit("a.docx", DOC, "de", "en")
    polls = iter([False, True, True, True])
    status = client.wait(handle, should_cancel=lambda: next(polls))
    assert status.state == DocumentJobState.cancelled
    assert client.cancel(handle) is False  # already terminal
    with pytest.raises(JobNotDoneError):
        client.get_result(handle)


def test_envelope_errors(service, client):
    service.fail_next = {"Code": 419, "Message": "quota", "ResolveErrorUri": "https://upgrade"}
    with pytest.raises(QuotaExceededError) as e:
        client.submit("a.docx", DOC, "de", "en")
    assert e.value.upgrade_uri == "https://upgrade" and e.value.code == ResponseCode.QUOTA_EXCEEDED

    service.fail_next = {"Code": 300, "Message": "stop"}
    with pytest.raises(ServiceCanceledError):
        client.submit("a.docx", DOC, "de", "en")

    service.fail_next = {"Code": 404, "Message": "no such job"}
    with pytest.raises(ServiceError) as e:
        client.submit("a.docx", DOC, "de", "en")
    assert e.value.code == ResponseCode.NOT_FOUND and "no such job" in str(e.value)

    service.fail_next = {"Code": 999, "Message": "from the future"}
    with pytest.raises(ServiceError) as e:
        client.submit("a.docx", DOC, "de", "en")
    assert e.value.code == ResponseCode.UNKNOWN

    handler = WebApiRequestHandler("https://service.test", "wrong key", transport=service)
    with pytest.raises(TransportError) as e:
        ManagementClient(handler).ping()
    assert e.value.status == 401


def test_argument_validation(client):
    with pytest.raises(ValueError):
        client.submit("a.docx", b"", "de", "en")
    with pytest.raises(ValueError, match="dictionary_format"):
        client.submit("a.docx", DOC, "de", "en", dictionary=b"x", dictionary_format="pdf")
    with pytest.raises(ValueError, match="requires dictionary"):
        client.submit("a.docx", DOC, "de", "en", dictionary_format="csv")
    with pytest.raises(ValueError, match="16"):
        client.submit("a.docx", DOC, "de", "en", translation_memories=[b"x"] * 17)
    with pytest.raises(ValueError):
        client.submit("a.docx", DOC, "", "en")
    with pytest.raises(ValueError):
        DocumentJobClient(client.request_handler, "")
    with pytest.raises(ValueError):
        DocumentJobClient(client.request_handler, base64.b64encode(b"\x00" * 100).decode())
    with pytest.raises(ValueError):
        DocumentJobClient(None, client.message_handler and "x")


def test_connect_pins_or_verifies(service):
    pinned = connect("https://service.test", service.api_key, service_public_key=service.public_key_base64,
                     transport=service)
    assert not any("Ping" in r for r in service.requests)
    handle = pinned.submit("a.docx", DOC, "de", "en")
    assert pinned.wait(handle).state == DocumentJobState.done

    verified = connect("https://service.test", service.api_key, verification_key=service.verification_key_base64,
                       transport=service, timeout=30)
    assert any("Ping" in r for r in service.requests)
    assert verified.request_handler.timeout == 30
    handle = verified.submit("a.docx", DOC, "de", "en")
    assert verified.wait(handle).state == DocumentJobState.done

    # the built-in production verification key must NOT accept the fake's announcement
    with pytest.raises(EncryptionError, match="signature"):
        connect("https://service.test", service.api_key, transport=service)


def test_management_ping(service):
    handler = WebApiRequestHandler("https://service.test", service.api_key, transport=service)
    management = ManagementClient(handler)
    ping = management.ping()
    assert ping.has_license and ping.licensee_name == "Test GmbH"
    assert ping.service_public_key == service.public_key_base64
    assert management.test_connection()
    assert management.resolve_service_public_key(service.verification_key_base64) == service.public_key_base64
    assert service.requests[0]["Ping"] == {"Client": "iptranslator-client",
                                          "ClientVersion": service.requests[0]["ClientVersion"]}
    assert ManagementClient("https://service.test", "x").request_handler.api_key == "x"


def test_status_shape(service, client):
    handle = client.submit("a.docx", DOC, "de", "en")
    status = client.get_status(handle, wait_seconds=25)
    assert status.job_id == str(handle.job_id)
    assert status.created == "2026-09-24T10:00:00+00:00"
    assert status.state == DocumentJobState.running and status.progress_total == 10
    assert status.message is None and status.result_url is None
    with pytest.raises(ValueError):
        client.get_status(handle, wait_seconds=26)
    status = client.wait(handle)
    assert status.message.request_type.value == "translate_document"
    assert status.message.consumed_units == 7 and status.completed
