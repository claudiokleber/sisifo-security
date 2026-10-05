import io
import json
import tarfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from defusedxml.common import DefusedXmlException
from requests.exceptions import ReadTimeout
from typer.testing import CliRunner

from sisifo.cli.main import app
from sisifo.core import ai_analyzer, orchestrator, session
from sisifo.core.importer import import_nmap
from sisifo.core.report import build_report, compare_sessions
from sisifo.core.schema import Finding
from sisifo.modules.nikto import module as nikto
from sisifo.modules.nmap import module as nmap

XML = (Path(__file__).parent / "fixtures/nmap.xml").read_bytes()


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("SISIFO_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("SISIFO_TOOL_NETWORK", raising=False)


def imported(tmp_path, content=XML):
    f = tmp_path / "source.xml"
    f.write_bytes(content)
    return import_nmap(f, "192.0.2.10", "lab")


@pytest.mark.parametrize("target", ["192.0.2.1", "192.0.2.0/24", "2001:db8::1", "lab.example"])
def test_target_and_uuid(target):
    nmap.validate_target(target)
    s = session.create_session(target)
    assert len(s.id) == 32 and "/" not in s.id and ":" not in s.id
    assert session.load_session(s.id).target == target


@pytest.mark.parametrize("target", ["-iL", "http://host/", "name;cmd", "../../test", ""])
def test_bad_nmap_target(target):
    with pytest.raises(ValueError):
        nmap.command(target)


@pytest.mark.parametrize("sid", ["../outside", "C:/test", "a" * 31, "A" * 32])
def test_confined_ids(sid):
    with pytest.raises(ValueError):
        session.load_session(sid)


def test_missing_session():
    with pytest.raises(ValueError, match="não encontrada"):
        ai_analyzer.prepare_input("a" * 32)


def test_nmap_xml():
    findings = nmap.parse(XML, "x", "raw_output/nmap.xml")
    assert len(findings) == 1
    assert findings[0].target == "192.0.2.10"
    assert findings[0].port == 80 and findings[0].category == "observation"
    assert findings[0].severity == "info"


@pytest.mark.parametrize(
    "bad",
    [
        b"<x/>",
        b"<nmaprun/>",
        XML.replace(b'exit="success"', b'exit="error"'),
        b'<!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><nmaprun>&a;</nmaprun>',
    ],
)
def test_reject_bad_xml(bad):
    with pytest.raises((ValueError, DefusedXmlException)):
        nmap.parse(bad, "x", "raw_output/nmap.xml")


def test_single_writer_datetime_and_raw(tmp_path):
    s = imported(tmp_path)
    findings = session.read_findings(s.id)
    session.write_findings(s.id, findings)
    session.write_findings(s.id, findings)
    assert len(session.read_findings(s.id)) == 1
    assert (session.session_dir(s.id) / "raw_output/nmap.xml").read_bytes() == XML
    assert findings[0].timestamp.tzinfo is not None


def test_cli_show_and_report(tmp_path):
    s = imported(tmp_path)
    result = CliRunner().invoke(app, ["session", "show", s.id])
    assert result.exit_code == 0, result.output
    assert s.id in result.output
    report = build_report(s.id)
    assert len(report["findings"]) == 1
    assert (session.session_dir(s.id) / "reports/report.md").is_file()


def test_unknown_module_no_session():
    with pytest.raises(ValueError):
        orchestrator.scan("192.0.2.10", "unknown")
    assert not (session.data_root() / "sessions").exists()


def test_duplicate_module():
    with pytest.raises(ValueError):
        orchestrator.scan("192.0.2.10", "nmap,nmap")


def fake_container(monkeypatch, *, exit_code=0, data=XML, timeout=False):
    c = MagicMock()
    c.wait.return_value = {"StatusCode": exit_code}
    if timeout:
        c.wait.side_effect = ReadTimeout("test")
    c.logs.side_effect = lambda **kw: data if kw.get("stdout") else b"error details"
    client = MagicMock()
    client.images.get.return_value.id = "sha256:fixture"
    client.containers.run.return_value = c
    monkeypatch.setattr(orchestrator.docker, "from_env", lambda **kw: client)
    return c, client


def test_executor_failure_not_success(monkeypatch):
    c, client = fake_container(monkeypatch, exit_code=1, data=b"")
    s = orchestrator.scan("192.0.2.10")
    assert s.status == "failed" and s.runs[0].exit_code == 1
    assert session.read_findings(s.id) == []
    assert (session.session_dir(s.id) / s.runs[0].stderr).read_bytes() == b"error details"
    c.remove.assert_called_once_with(force=True)
    assert "volumes" not in client.containers.run.call_args.kwargs


def test_timeout_cleanup(monkeypatch):
    c, _ = fake_container(monkeypatch, timeout=True)
    s = orchestrator.scan("192.0.2.10", timeout=1)
    assert s.status == "failed" and s.runs[0].status == "timeout"
    c.kill.assert_called_once()
    c.remove.assert_called_once()


def test_executor_success(monkeypatch):
    fake_container(monkeypatch)
    s = orchestrator.scan("192.0.2.10")
    assert s.status == "completed"
    assert s.tools_run == ["nmap"]
    assert len(session.read_findings(s.id)) == 1
    assert s.runs[0].artifact_sha256


def test_cancel_cleanup(monkeypatch):
    c, _ = fake_container(monkeypatch)
    c.wait.side_effect = KeyboardInterrupt
    s = orchestrator.scan("192.0.2.10")
    assert s.status == "cancelled"
    c.kill.assert_called_once()
    c.remove.assert_called_once()


def test_invalid_tool_output_fails(monkeypatch):
    fake_container(monkeypatch, data=b"<not-nmap/>")
    s = orchestrator.scan("192.0.2.10")
    assert s.status == "failed"


def test_no_docker_report(monkeypatch):
    def fail(**kw):
        raise RuntimeError("Docker offline")

    monkeypatch.setattr(orchestrator.docker, "from_env", fail)
    s = orchestrator.scan("192.0.2.10")
    assert s.status == "failed"
    assert "Docker offline" in build_report(s.id)["session"]["runs"][0]["error"]


def test_nikto():
    data = b'{"vulnerabilities":[{"id":"1","url":"/","msg":"Review header"}]}'
    f = nikto.parse(data, "http://lab", "raw_output/nikto.json")
    assert len(f) == 1 and f[0].category == "potential_issue"
    assert nikto.command("http://lab:80")[1] == "http://lab:80"


@pytest.mark.parametrize(
    "url",
    [
        "file:///x",
        "http://user:pass@host",
        "http://host/path",
        "http://host?q=x",
        "http://host:99999",
    ],
)
def test_bad_nikto_url(url):
    with pytest.raises(ValueError):
        nikto.command(url)


def test_archive_without_extracting(monkeypatch):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as t:
        info = tarfile.TarInfo("nikto.json")
        info.size = 2
        t.addfile(info, io.BytesIO(b"{}"))
    c = MagicMock()
    c.get_archive.return_value = ([stream.getvalue()], {})
    assert orchestrator.archive_file(c, "/tmp/nikto.json") == b"{}"


def test_ai_coverage_and_priority(tmp_path):
    s = imported(tmp_path)
    items = [
        Finding(
            tool="nmap",
            target="lab",
            finding=str(i),
            severity="critical" if i == 200 else "info",
            evidence="raw_output/nmap.xml",
            fingerprint=str(i),
        )
        for i in range(201)
    ]
    s.findings_sha256 = session.write_findings(s.id, items)
    s.runs[0].findings_count = len(items)
    session.save_session(s)
    data = ai_analyzer.prepare_input(s.id, max_chars=200000)
    assert data["coverage"]["omitted"] == 1
    assert data["evidence"][0]["severity"] == "critical"
    assert ai_analyzer.analyze_session(s.id)["mode"] == "export"


def ai_reply(monkeypatch, sid, *, unknown=False):
    evidence = session.read_findings(sid)[0].id
    body = {
        "summary": "Resumo",
        "reviewed_evidence_ids": [evidence],
        "recommendations": [
            {
                "evidence_ids": ["f" * 32 if unknown else evidence],
                "assessment": "Revisar exposição",
                "measures": ["Revisar configuração"],
                "verification": "Repetir avaliação",
                "confidence": "low",
            }
        ],
        "limitations": ["Somente observações"],
    }
    monkeypatch.setattr(
        ai_analyzer.providers, "complete", lambda *a, **kw: (json.dumps(body), {"model": "fixture"})
    )


def test_ai_good_response(tmp_path, monkeypatch):
    s = imported(tmp_path)
    ai_reply(monkeypatch, s.id)
    result = ai_analyzer.analyze_session(s.id, "fixture", provider="ollama")
    assert Path(result["path"]).is_file()


def test_ai_unknown_evidence_keeps_report(tmp_path, monkeypatch):
    s = imported(tmp_path)
    ai_reply(monkeypatch, s.id, unknown=True)
    with pytest.raises(ValueError, match="desconhecida"):
        ai_analyzer.analyze_session(s.id, "fixture", provider="ollama")
    assert (session.session_dir(s.id) / "reports/report.md").is_file()
    metadata = list((session.session_dir(s.id) / "analysis").glob("*/metadata.json"))
    assert json.loads(metadata[0].read_text())["status"] == "failed"


def test_compare(tmp_path):
    a = imported(tmp_path)
    b = imported(tmp_path, XML.replace(b'portid="80"', b'portid="8080"'))
    diff = compare_sessions(a.id, b.id)
    assert len(diff["new"]) == 1 and len(diff["not_observed_again"]) == 1


def test_compare_rejects_failure(tmp_path):
    a, b = imported(tmp_path), imported(tmp_path)
    b.status = "failed"
    session.save_session(b)
    with pytest.raises(ValueError):
        compare_sessions(a.id, b.id)


def test_corrupted_jsonl(tmp_path):
    s = imported(tmp_path)
    (session.session_dir(s.id) / "logs/findings.jsonl").write_text("bad json")
    with pytest.raises(ValueError, match="linha 1"):
        build_report(s.id)


def test_wrapped_timeout(monkeypatch):
    from requests.exceptions import ConnectionError as RequestsConnectionError
    from urllib3.exceptions import ReadTimeoutError

    c, _ = fake_container(monkeypatch)
    c.wait.side_effect = RequestsConnectionError(ReadTimeoutError(None, "/wait", "timeout"))
    s = orchestrator.scan("192.0.2.10", timeout=1)
    assert s.runs[0].status == "timeout"
    c.kill.assert_called_once()
    c.remove.assert_called_once()


def test_vault_export_preserves_user_edit(tmp_path):
    from sisifo.core.vault import export_vault

    s = imported(tmp_path)
    vault = tmp_path / "vault"
    (vault / ".obsidian").mkdir(parents=True)
    path = export_vault(s.id, vault)
    assert export_vault(s.id, vault) == path
    path.write_text("minha nota", encoding="utf-8")
    with pytest.raises(ValueError, match="diferente"):
        export_vault(s.id, vault)
    assert path.read_text(encoding="utf-8") == "minha nota"


def test_combined_target_and_partial(monkeypatch):
    from sisifo.core.schema import RunResult

    calls = []

    def execute(module, target, sid, timeout, **kwargs):
        calls.append((module.name, target))
        return RunResult(
            tool=module.name,
            image=module.image,
            status="completed" if module.name == "nmap" else "failed",
        ), []

    monkeypatch.setattr(orchestrator, "execute", execute)
    s = orchestrator.scan("http://lab:8080", "nmap,nikto")
    assert calls == [("nmap", "lab"), ("nikto", "http://lab:8080")]
    assert s.status == "partial"
