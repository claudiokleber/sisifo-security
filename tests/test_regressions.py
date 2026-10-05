import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from markdown_it import MarkdownIt
from pydantic import ValidationError
from typer.testing import CliRunner

from sisifo.cli.main import app
from sisifo.core import ai_analyzer, orchestrator, session
from sisifo.core.importer import import_nmap
from sisifo.core.report import build_report, compare_sessions, plain
from sisifo.core.schema import Finding, RunResult, Session
from sisifo.modules.metasploit import module as metasploit

XML = (Path(__file__).parent / "fixtures/nmap.xml").read_bytes()


def imported(tmp_path, raw=XML):
    path = tmp_path / "source.xml"
    path.write_bytes(raw)
    return import_nmap(path, "192.0.2.10", "lab")


@pytest.mark.parametrize(
    "old,new",
    [
        (b"-p 80,443,8080", b"-p 80"),
        (b'version="7.98"', b'version="7.99"'),
        (b'services="80,443,8080"', b'services="80"'),
        (b'protocol="tcp"', b'protocol="udp"'),
    ],
)
def test_incompatible_imports_rejected(tmp_path, old, new):
    a, b = imported(tmp_path), imported(tmp_path, XML.replace(old, new))
    with pytest.raises(ValueError, match="Cobertura diferente"):
        compare_sessions(a.id, b.id)


def test_unknown_import_coverage_rejected(tmp_path):
    unknown = XML.replace(b'args="nmap -sT -p 80,443,8080 192.0.2.10"', b'args=""')
    a, b = imported(tmp_path, unknown), imported(tmp_path, unknown)
    with pytest.raises(ValueError, match="desconhecida"):
        compare_sessions(a.id, b.id)


def test_banner_change_has_stable_identity(tmp_path):
    a = imported(tmp_path)
    b = imported(
        tmp_path,
        XML.replace(b'product="Example" version="1.0"', b'product="Example" version="2.0"'),
    )
    result = compare_sessions(a.id, b.id)
    assert len(result["changed"]) == 1
    assert not result["new"] and not result["not_observed_again"]


def test_import_preserves_original_observation_time(tmp_path):
    s = imported(tmp_path)
    finding = session.verified_findings(s)[0]
    assert finding.observed_at.timestamp() == 1700000010
    assert finding.timestamp > finding.observed_at
    assert s.runs[0].imported_at > finding.observed_at


@pytest.mark.parametrize("damage", ["missing", "changed", "count", "artifact", "outside"])
def test_integrity_prevents_report_and_ai(tmp_path, damage, monkeypatch):
    s = imported(tmp_path)
    directory = session.session_dir(s.id)
    if damage == "missing":
        (directory / "logs/findings.jsonl").unlink()
    elif damage == "changed":
        with (directory / "logs/findings.jsonl").open("a") as stream:
            stream.write("\n")
    elif damage == "count":
        s.runs[0].findings_count += 1
        session.save_session(s)
    elif damage == "artifact":
        (directory / "raw_output/nmap.xml").write_bytes(b"changed")
    else:
        s.runs[0].artifact = "../other.xml"
        session.save_session(s)
    transport = MagicMock()
    monkeypatch.setattr(ai_analyzer.providers, "complete", transport)
    with pytest.raises(ValueError, match="Integridade"):
        build_report(s.id)
    with pytest.raises(ValueError, match="Integridade"):
        ai_analyzer.analyze_session(s.id, provider="nvidia")
    transport.assert_not_called()


def test_legacy_v2_without_new_hash_is_readable(tmp_path):
    s = imported(tmp_path)
    s.findings_sha256 = None
    session.save_session(s)
    assert len(build_report(s.id)["findings"]) == 1


def test_running_session_not_reported(tmp_path):
    s = session.create_session("lab")
    with pytest.raises(ValueError, match="execução"):
        build_report(s.id)


def test_run_is_persisted_before_container_starts(monkeypatch):
    client, container = MagicMock(), MagicMock()
    client.images.get.return_value.id = "sha256:fixture"
    client.containers.run.return_value = container
    container.id = "container-id"
    container.wait.return_value = {"StatusCode": 0}
    container.logs.side_effect = lambda **kw: XML if kw.get("stdout") else b""
    monkeypatch.setattr(orchestrator.docker, "from_env", lambda **kw: client)

    def during_start(*args, **kwargs):
        sid = kwargs["labels"]["sisifo.session"]
        state = session.load_session(sid)
        assert state.runs[0].status == "running"
        assert state.runs[0].image_id == "sha256:fixture"
        assert args[0] == "sha256:fixture"
        return container

    client.containers.run.side_effect = during_start
    s = orchestrator.scan("192.0.2.10")
    assert s.status == "completed"
    assert s.runs[0].container_id == "container-id"
    assert len(session.verified_findings(s)) == 1


def test_recovery_never_restarts_or_kills(monkeypatch):
    s = session.create_session("lab")
    s.runs = [RunResult(tool="nmap", image="fixture")]
    session.save_session(s)
    client = MagicMock()
    client.containers.list.return_value = []
    monkeypatch.setattr(orchestrator.docker, "from_env", lambda **kw: client)
    recovered = orchestrator.recover_session(s.id)
    assert recovered.status == "interrupted"
    assert recovered.runs[0].status == "interrupted"
    client.containers.run.assert_not_called()
    assert session.verified_findings(recovered) == []


def test_recovery_refuses_active_writer():
    s = session.create_session("lab")
    with session.session_lock(s.id):
        with pytest.raises(ValueError, match="escritor ativo"):
            orchestrator.recover_session(s.id)


def test_recovery_refuses_active_container(monkeypatch):
    s = session.create_session("lab")
    client, container = MagicMock(), MagicMock()
    container.status = "running"
    client.containers.list.return_value = [container]
    monkeypatch.setattr(orchestrator.docker, "from_env", lambda **kw: client)
    with pytest.raises(ValueError, match="container ativo"):
        orchestrator.recover_session(s.id)
    container.kill.assert_not_called()
    assert session.load_session(s.id).status == "running"


@pytest.mark.parametrize(
    "payload",
    [
        "![image](https://example.invalid/image.png)",
        "[click](https://example.invalid)",
        "![[private-note]]",
        '<img src="https://example.invalid">',
        "# heading\n- list",
        "[x]: https://example.invalid",
        "**bold** `code` &lt;img&gt;",
    ],
)
def test_report_renders_untrusted_text_literally(payload):
    rendered = MarkdownIt().render(plain(payload))
    for tag in ("<img", "<a ", "<h1", "<ul", "<strong", "<code"):
        assert tag not in rendered
    assert "![[" not in plain(payload)


def msf_result(**changes):
    result = {
        "schema_version": 1,
        "status": "completed",
        "module": metasploit.PROFILE,
        "framework_version": "test",
        "target": "http://lab",
        "resolved_hosts": ["192.0.2.10"],
        "services": [{"host": "192.0.2.10", "port": 80, "protocol": "http", "info": "nginx"}],
    }
    result.update(changes)
    return result


def test_metasploit_valid_and_deduplicated():
    data = msf_result()
    data["services"] *= 2
    results = metasploit.parse(
        json.dumps(data).encode(), "http://lab", "raw_output/metasploit.json"
    )
    assert len(results) == 1 and results[0].category == "observation"


@pytest.mark.parametrize(
    "changes",
    [
        {"target": "http://other"},
        {"services": []},
        {"status": "failed"},
        {"resolved_hosts": ["192.0.2.20"]},
        {"services": [{"host": "192.0.2.10", "port": 443, "protocol": "https", "info": "x"}]},
    ],
)
def test_metasploit_rejects_inconsistent_results(changes):
    with pytest.raises(ValueError):
        metasploit.parse(
            json.dumps(msf_result(**changes)).encode(), "http://lab", "raw_output/msf.json"
        )


def test_doctor_default_does_not_require_metasploit(monkeypatch):
    import docker

    client = MagicMock()
    monkeypatch.setattr(docker, "from_env", lambda **kw: client)
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 0
    calls = [c.args[0] for c in client.images.get.call_args_list]
    assert len(calls) == 2 and not any("metasploit" in value for value in calls)


@pytest.mark.parametrize("port", [0, 65536])
def test_schema_rejects_invalid_ports(port):
    with pytest.raises(ValidationError):
        Finding(tool="nmap", target="lab", port=port, finding="x", evidence="raw", fingerprint="x")


def test_schema_rejects_future_version():
    with pytest.raises(ValidationError):
        Session(target="lab", schema_version=999)
