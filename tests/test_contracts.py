import json

from iptranslator_client import contracts as c


def test_envelope_request_shape():
    envelope = c.EnvelopeRequest(client="x", client_version="1",
                                 get_document_job=c.GetDocumentJobRequest("id-1", wait_seconds=20))
    assert envelope.action == "get_document_job"
    wire = envelope.to_json()
    assert set(wire) == {"CorrelationId", "Client", "ClientVersion", "GetDocumentJob"}
    assert wire["GetDocumentJob"] == {"JobId": "id-1", "WaitSeconds": 20}
    assert c.EnvelopeRequest().action == "empty"
    assert c.EnvelopeRequest(ping=c.PingRequest()).to_json()["Ping"] == {}
    assert c.EnvelopeRequest(cancel_document_job=c.CancelDocumentJobRequest("j")).to_json()["CancelDocumentJob"] == {"JobId": "j"}


def test_submit_request_shape():
    message = c.TranslatorRequestMessage(request_id="r", maybe_encrypted_body=b"\x01", key_id="k",
                                         encrypted_key=b"\x02", entropy=b"\x03")
    wire = c.SubmitDocumentJobRequest("j", message, document_name="n").to_json()
    assert wire == {"JobId": "j", "DocumentName": "n", "Message": {
        "request_id": "r", "key_id": "k", "encrypted_key": "Ag==", "entropy": "Aw==", "maybe_encrypted_body": "AQ=="}}


def test_envelope_response_parsing_tolerates_unknowns():
    response = c.EnvelopeResponse.from_json({
        "CorrelationId": "c", "Code": 200, "Message": None, "SomethingNew": {"x": 1},
        "GetDocumentJob": {"JobId": "j", "State": "done", "Created": "2026-01-01T00:00:00+00:00",
                           "ProgressDone": 1, "ProgressTotal": 2, "ErrorCode": "", "ConsumedUnits": 3,
                           "DocumentId": "d", "ResultUrl": "u", "Message": None, "Future": 1},
        "Ping": {"HasLicense": True, "ServicePublicKey": "pk"},
        "ComputeTimeSec": 0.5})
    assert response.code == 200 and response.compute_time_sec == 0.5
    job = response.get_document_job
    assert job.state == c.DocumentJobState.done and job.state.is_terminal
    assert job.error_code is None and job.consumed_units == 3 and job.result_url == "u"
    assert response.ping.has_license and response.ping.service_public_key == "pk"
    assert response.create_document_job is None and response.cancel_document_job is None
    assert response.raw["SomethingNew"] == {"x": 1}

    # enum ordinals (some relay paths serialize enums as int) and names as codes
    assert c.EnvelopeResponse.from_json({"GetDocumentJob": {"State": 1}}).get_document_job.state == c.DocumentJobState.running
    assert c.EnvelopeResponse.from_json({"GetDocumentJob": {"State": "unknown"}}).get_document_job.state is None
    assert c.EnvelopeResponse.from_json({"Code": "QuotaExceeded"}).code == 419
    assert c.EnvelopeResponse.from_json({"Code": "nonsense"}).code == -1


def test_create_response_parsing():
    created = c.CreateDocumentJobResponse.from_json({
        "JobId": "j", "InputUploadUrl": "in", "WorkerInputUrl": "wi", "WorkerOutputUrl": "wo",
        "WorkerStatusUrl": "ws", "WorkerCancelUrl": "wc", "WorkerUsageUrl": "wu",
        "DictionaryUploadUrl": None, "TranslationMemoryUploadUrls": ["t0"], "WorkerTranslationMemoryUrls": ["w0"]})
    assert created.worker_usage_url == "wu" and created.dictionary_upload_url is None
    assert created.translation_memory_upload_urls == ["t0"]


def test_python_shapes():
    # exactly what ipt_service.message models emit
    body = c.TranslatorResponseBody.from_json(json.loads(
        '{"result_type":"document","document":{"job_id":"job-42","state":"done","total":10,'
        '"translated":9,"failed":1,"tm_translated":4}}'))
    assert body.result_type == c.ResultType.document and body.document.tm_translated == 4
    message = c.TranslatorResponseMessage.from_json(json.loads(
        '{"request_id":"r","request_type":"translate_document","object_id":null,"consumed_units":0,'
        '"time_ms":1.5,"key_id":"k","entropy":"AAAAAAAAAAAAAAAA","maybe_encrypted_body":"AQID"}'))
    assert message.object_id is None and message.entropy == b"\x00" * 12 and message.maybe_encrypted_body == b"\x01\x02\x03"
    assert message.request_type == c.RequestType.translate_document and message.time_ms == 1.5


def test_request_body_omits_none_and_keeps_empty_lists():
    body = c.TranslatorRequestBody(scope_key="s", type=c.RequestType.translate_document, src_lang="de",
                                   trg_lang="en", task="", src_text=[], doc_finalize=False)
    assert body.to_json() == {"scope_key": "s", "type": "translate_document", "task": "", "src_lang": "de",
                              "trg_lang": "en", "src_text": [], "doc_finalize": False}


def test_wire_enum_names_are_stable():
    assert [m.value for m in c.RequestType] == ["translate", "translate_align", "translate_document", "align",
                                                "evaluate", "embed", "replace", "split", "probe", "unreadable"]
    assert [m.value for m in c.DocumentJobState] == ["queued", "running", "done", "failed", "cancelled"]
    assert c.DocumentJobLimits.MAX_TRANSLATION_MEMORIES == 16
    assert c.DocumentJobLimits.DICTIONARY_FORMATS == ("csv", "tsv", "xlsx")
