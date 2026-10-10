import io
import json
from pathlib import Path
from unittest.mock import MagicMock
from urllib.error import HTTPError, URLError

import pytest
from typer.testing import CliRunner

from sisifo.cli.main import app
from sisifo.core import ai_analyzer, config, providers, session
from sisifo.core.importer import import_nmap
from sisifo.core.schema import Finding

XML = (Path(__file__).parent / "fixtures/nmap.xml").read_bytes()


def populated(tmp_path, count=1):
    path = tmp_path / "input.xml"
    path.write_bytes(XML)
    s = import_nmap(path, "192.0.2.10", "synthetic-test")
    findings = [
        Finding(
            tool="nmap",
            target="192.0.2.10",
            port=80,
            service="http",
            finding=f"Observação {i}",
            evidence="raw_output/nmap.xml",
            fingerprint=str(i),
            details={"url": "/example", "id": str(i)},
        )
        for i in range(count)
    ]
    s.runs[0].findings_count = count
    s.findings_sha256 = session.write_findings(s.id, findings)
    session.save_session(s)
    return s


def reply(evidence):
    return json.dumps(
        {
            "summary": "Observações requerem revisão.",
            "reviewed_evidence_ids": [f["id"] for f in evidence],
            "recommendations": [
                {
                    "evidence_ids": [f["id"]],
                    "assessment": "Exposição observada, sem vulnerabilidade confirmada.",
                    "measures": ["Revisar necessidade do serviço."],
                    "verification": "Conferir configuração.",
                    "confidence": "low",
                }
                for f in evidence
            ],
            "limitations": ["Somente evidências fornecidas."],
        }
    )


def test_setup_hides_key_and_preserves_local_only_files(tmp_path, monkeypatch):
    key = "nvapi-synthetic-test-key"
    from sisifo.core import ai_connection
    monkeypatch.setattr(ai_connection, "request", lambda endpoint, path, key, body=None, control=None:
        {"data": [{"id": "test-model"}]} if path == "/models" else
        {"choices": [{"finish_reason": "stop", "message": {"content": "OK"}}]})
    result = CliRunner().invoke(app, ["setup"], input=f"1\nhttps://api.example/v1\n{key}\n1\ny\n")
    assert result.exit_code == 0, result.output
    assert key not in result.output
    assert ai_connection.connection()["api_key"] == key
    assert "nvapi" not in (config.config_dir() / "config.json").read_text()
    assert config.load_config()["provider"] == "api"
    status = CliRunner().invoke(app, ["ai-status"])
    assert status.exit_code == 0 and key not in status.output


def test_setup_export_does_not_ask_key():
    result = CliRunner().invoke(app, ["setup"], input="2\n")
    assert result.exit_code == 0
    assert "Chave de API" not in result.output
    assert not (config.config_dir() / "nvidia.key").exists()


def test_missing_key_has_actionable_error():
    with pytest.raises(ValueError, match="setup"):
        config.nvidia_key()


def test_explicit_export_never_calls_provider(tmp_path, monkeypatch):
    config.save_config("nvidia", config.NVIDIA_MODEL, "nvapi-test")
    s = populated(tmp_path)
    transport = MagicMock()
    monkeypatch.setattr(providers, "complete", transport)
    result = ai_analyzer.analyze_session(s.id, provider="export")
    assert result["mode"] == "export"
    transport.assert_not_called()


def test_full_batch_coverage_and_structured_fields(tmp_path, monkeypatch):
    s = populated(tmp_path, 45)
    calls = []

    def complete(provider, model, system, data, endpoint):
        calls.append(data)
        assert data["evidence"][0]["port"] == 80
        assert data["evidence"][0]["details"]["url"] == "/example"
        return reply(data["evidence"]), {"model": "fixture"}

    monkeypatch.setattr(providers, "complete", complete)
    result = ai_analyzer.analyze_session(s.id, provider="nvidia")
    assert len(calls) == 3
    assert result["coverage"]["included"] == 45 and result["coverage"]["omitted"] == 0
    assert result["status"] == "completed"


def test_batch_limit_is_explicit_partial(tmp_path, monkeypatch):
    s = populated(tmp_path, 25)
    monkeypatch.setattr(providers, "complete", lambda p, m, s, d, e: (reply(d["evidence"]), {}))
    result = ai_analyzer.analyze_session(s.id, provider="nvidia", max_batches=1)
    assert result["status"] == "partial"
    assert result["coverage"]["included"] == 20 and result["coverage"]["omitted"] == 5


def test_partial_provider_failure_keeps_successful_batch(tmp_path, monkeypatch):
    s = populated(tmp_path, 21)

    def complete(p, m, prompt, data, endpoint):
        if data["batch"] == 2:
            raise ValueError("Limite da API atingido (HTTP 429).")
        return reply(data["evidence"]), {}

    monkeypatch.setattr(providers, "complete", complete)
    with pytest.raises(ValueError, match="429"):
        ai_analyzer.analyze_session(s.id, provider="nvidia")
    meta = next((session.session_dir(s.id) / "analysis").glob("*/metadata.json"))
    data = json.loads(meta.read_text())
    assert data["status"] == "partial" and data["coverage"]["included"] == 20
    assert (meta.parent / "batch-1-validated.json").exists()
    assert (session.session_dir(s.id) / "reports/report.md").exists()


@pytest.mark.parametrize("change", ["unknown", "missing_review", "invalid_json", "empty_measures"])
def test_ai_rejects_invalid_answers(tmp_path, change):
    s = populated(tmp_path)
    evidence = ai_analyzer.prepare_batches(s.id)["batches"][0]
    body = json.loads(reply(evidence))
    if change == "unknown":
        body["recommendations"][0]["evidence_ids"] = ["f" * 32]
    elif change == "missing_review":
        body["reviewed_evidence_ids"] = []
    elif change == "empty_measures":
        body["recommendations"][0]["measures"] = []
    content = "not-json" if change == "invalid_json" else json.dumps(body)
    with pytest.raises(ValueError):
        ai_analyzer.validate_response(content, evidence)


def test_auth_header_not_in_prompt_and_only_official_host(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test-secret")
    seen = {}

    def request(url, body, headers):
        seen.update(url=url, body=body, headers=headers)
        return {"choices": [{"finish_reason": "stop", "message": {"content": "{}"}}]}

    monkeypatch.setattr(providers, "request_json", request)
    providers.complete("nvidia", config.NVIDIA_MODEL, "system", {"evidence": []})
    assert seen["url"] == config.NVIDIA_ENDPOINT + "/chat/completions"
    assert seen["headers"]["Authorization"] == "Bearer nvapi-test-secret"
    assert "nvapi" not in json.dumps(seen["body"])
    with pytest.raises(ValueError, match="oficial"):
        providers.complete("nvidia", "model", "", {}, "https://example.invalid")
    assert (
        providers.NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.invalid")
        is None
    )


@pytest.mark.parametrize("code,attempts", [(401, 1), (403, 1), (302, 1), (429, 3), (503, 3)])
def test_http_errors_sanitized_and_retries_bounded(monkeypatch, code, attempts):
    opener = MagicMock()
    opener.open.side_effect = lambda *a, **k: (_ for _ in ()).throw(
        HTTPError("https://example.invalid", code, "nvapi-sensitive", {}, io.BytesIO(b"sensitive"))
    )
    monkeypatch.setattr(providers, "build_opener", lambda *a: opener)
    monkeypatch.setattr(providers.time, "sleep", lambda *a: None)
    with pytest.raises(ValueError) as error:
        providers.request_json("https://example.invalid", {})
    assert "sensitive" not in str(error.value)
    assert opener.open.call_count == attempts


@pytest.mark.parametrize("error", [URLError("private details"), TimeoutError("private details")])
def test_network_error_is_safe(monkeypatch, error):
    opener = MagicMock()
    opener.open.side_effect = error
    monkeypatch.setattr(providers, "build_opener", lambda *a: opener)
    with pytest.raises(ValueError, match="indisponível"):
        providers.request_json("https://example.invalid", {})


def test_http_response_size_limited(monkeypatch):
    opener = MagicMock()
    opener.open.return_value = io.BytesIO(b"x" * 2_000_001)
    monkeypatch.setattr(providers, "build_opener", lambda *a: opener)
    with pytest.raises(ValueError, match="2 MB"):
        providers.request_json("https://example.invalid", {})


def test_incomplete_generation_rejected(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test")
    monkeypatch.setattr(
        providers,
        "request_json",
        lambda *a: {"choices": [{"finish_reason": "length", "message": {"content": "{}"}}]},
    )
    with pytest.raises(ValueError, match="incompleta"):
        providers.complete("nvidia", "model", "", {})


def test_zero_evidence_does_not_call_api(tmp_path, monkeypatch):
    s = populated(tmp_path, 0)
    transport = MagicMock()
    monkeypatch.setattr(providers, "complete", transport)
    result = ai_analyzer.analyze_session(s.id, provider="nvidia")
    assert result["coverage"]["total"] == 0
    transport.assert_not_called()
