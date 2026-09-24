import base64

import pytest

from iptranslator_client import cli
from iptranslator_client.request_handler import WebApiRequestHandler
from tests.fake_service import FakeService

DOC = b"PK\x03\x04 cli docx"


@pytest.fixture
def service(monkeypatch):
    service = FakeService()

    class Handler(WebApiRequestHandler):  # route the CLI's HTTP through the fake
        def __init__(self, service_url, api_key=None, transport=None, timeout=100.0):
            super().__init__(service_url, api_key, service, timeout)

    monkeypatch.setattr(cli, "WebApiRequestHandler", Handler)
    monkeypatch.setenv(cli.API_KEY_ENV_VAR, service.api_key)
    return service


@pytest.fixture
def files(tmp_path):
    (tmp_path / "in.docx").write_bytes(DOC)
    (tmp_path / "terms.csv").write_bytes(b"a;b\n")
    (tmp_path / "mem.tmx").write_bytes(b"<tmx/>")
    return tmp_path


def test_run_with_pinned_xwing_key(service, files, capsys):
    (files / "svc.xwing").write_bytes(base64.b64decode(service.public_key_base64))  # raw
    rc = cli.main([str(files / "in.docx"), str(files / "out.docx"), str(files / "svc.xwing"),
                   "--src", "de", "--trg", "en", "-f", "-d", str(files / "terms.csv"),
                   "-m", str(files / "mem.tmx"), "-s", "https://service.test"])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert (files / "out.docx").read_bytes() == b"translated:" + DOC
    assert "job " in out and "state: running, progress: 3/10" in out and "consumed units: 7." in out
    assert "summary: 9/10 translated, 1 failed." in out
    assert not any("Ping" in r for r in service.requests)
    inputs = next(iter(service.worker_inputs.values()))
    assert inputs["dictionary"] == b"a;b\n" and inputs["translation_memories"] == [b"<tmx/>"]
    assert inputs["body"]["doc_finalize"] is True and inputs["body"]["doc_dict_format"] == "csv"


def test_run_with_hybrid_key_file_uses_announcement(service, files, capsys):
    (files / "svc.hybrid").write_text("﻿" + service.verification_key_base64 + "\n")  # base64 text + BOM
    rc = cli.main([str(files / "in.docx"), str(files / "out.docx"), str(files / "svc.hybrid"),
                   "--src", "de", "--trg", "en", "-k", service.api_key])
    assert rc == 0, capsys.readouterr()
    assert any("Ping" in r for r in service.requests)
    assert "verified signed announcement" in capsys.readouterr().out


def test_run_without_key_file_uses_builtin_verification_key(service, files, capsys):
    # the fake's announcement is not signed by the production key -> fails safe
    rc = cli.main([str(files / "in.docx"), str(files / "out.docx"), "--src", "de", "--trg", "en"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "ERROR" in err and "signature" in err


def test_failed_job_exit_code(service, files, capsys):
    service.worker_error = "not_prepared"
    (files / "svc.xwing").write_text(service.public_key_base64)
    rc = cli.main([str(files / "in.docx"), str(files / "out.docx"), str(files / "svc.xwing"),
                   "--src", "de", "--trg", "en"])
    assert rc == 3
    assert "job ended failed (not_prepared)." in capsys.readouterr().err


def test_usage_errors(service, files, capsys):
    base = [str(files / "in.docx"), str(files / "out.docx"), "--src", "de", "--trg", "en"]
    assert cli.main([str(files / "missing.docx"), str(files / "out.docx"), "--src", "de", "--trg", "en"]) == 2
    assert cli.main(base + ["-d", str(files / "in.docx")]) == 2  # dictionary must be csv/tsv/xlsx
    assert cli.main(base + ["-m", str(files / "terms.csv")]) == 2  # tm must be .tmx
    assert cli.main(base + ["-m", str(files / "mem.tmx")] * 17) == 2
    assert cli.main(base + [str(files / "terms.csv")]) == 2  # unsupported key extension
    (files / "bad.xwing").write_bytes(b"\x00" * 10)
    assert cli.main(base + [str(files / "bad.xwing")]) == 2
    assert cli.main([str(files / "in.docx"), str(files / "out.docx")]) == 2  # --src/--trg required
    assert cli.main(["--version"]) == 0
    assert "2." in capsys.readouterr().out
