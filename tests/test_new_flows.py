import asyncio
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from sisifo.core import config
from sisifo.osint.contract import QueryType
from sisifo.osint.dummy import DummyConnector
from sisifo.osint.executor import OsintExecutionError, OsintExecutor, run_query


def test_legacy_password_migrates_only_after_valid_login():
    config.save_service_config("web", {"password": "legacy-fake", "other": 1})
    assert config.web_password_configured()
    assert not config.verify_web_password("wrong")
    assert "password" in config.load_service_config("web")
    assert config.verify_web_password("legacy-fake")
    cfg = config.load_service_config("web")
    assert "password" not in cfg
    assert cfg["other"] == 1
    assert config.verify_web_password("legacy-fake")


def test_long_password_not_silently_truncated():
    prefix = "a" * 80
    config.set_web_password(prefix + "one")
    assert config.verify_web_password(prefix + "one")
    assert not config.verify_web_password(prefix + "two")


@pytest.mark.parametrize("service", ["../outside", "web/../../secret", "..", "C:\\secret"])
def test_service_path_rejected(service):
    with pytest.raises(ValueError):
        config.save_service_config(service, {"fake": "value"})


def test_menu_configuration_and_invalid_selection(monkeypatch):
    from sisifo.cli.commands import menu, setup_web
    from sisifo.cli.main import app
    monkeypatch.setattr(menu, "existing_web", lambda port: False)
    called = []
    monkeypatch.setattr(setup_web, "set_password", lambda: called.append("password"))
    result = CliRunner().invoke(app, ["menu"], input="7\n2\n0\n5\n99\n0\n")
    assert result.exit_code == 0, result.output
    assert called == ["password"]
    assert "Seleção inválida" in result.output


def test_noninteractive_help_and_commands():
    from sisifo.cli.main import app
    assert CliRunner().invoke(app, []).exit_code == 0
    assert CliRunner().invoke(app, ["modules"]).exit_code == 0
    assert CliRunner().invoke(app, ["agent", "--help"]).exit_code == 0


def test_osint_shared_rate_limit():
    conn = DummyConnector()
    conn.meta = conn.meta.model_copy(update={"id": "rate-test", "limits": {"rate_per_minute": 1}})
    assert OsintExecutor(conn)._check_rate_limit()
    assert not OsintExecutor(conn)._check_rate_limit()


def test_osint_rejects_invalid_query_and_type():
    for value, qt in [("invalid domain!", QueryType.DOMAIN), ("https://example.com", QueryType.URL)]:
        with pytest.raises(OsintExecutionError):
            run_query(DummyConnector(), value, qt, {"api_key": "fake"})


def test_osint_stream_limit_without_length_and_client_close():
    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"x" * 40
            yield b"x" * 40
    async def run():
        conn = DummyConnector()
        conn.meta = conn.meta.model_copy(update={"id": "stream-test", "limits": {"max_response_size": 50}})
        executor = OsintExecutor(conn)
        executor._client = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, stream=Stream())))
        try:
            with pytest.raises(OsintExecutionError) as error:
                await executor.execute_http_query("https://api.example.com/search")
            assert error.value.code == "RESPONSE_TOO_LARGE"
        finally:
            await executor.close()
        assert executor._client.is_closed
    asyncio.run(run())


def test_osint_retry_after_beyond_budget_does_not_retry(monkeypatch):
    waits = []
    async def sleep(seconds):
        waits.append(seconds)
    monkeypatch.setattr("sisifo.osint.executor.asyncio.sleep", sleep)
    async def run():
        conn = DummyConnector()
        conn.meta = conn.meta.model_copy(update={"id": "retry-test"})
        executor = OsintExecutor(conn)
        executor._client = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(429, headers={"Retry-After": "999999"})))
        try:
            with pytest.raises(OsintExecutionError):
                await executor.execute_http_query("https://api.example.com/search")
        finally:
            await executor.close()
    asyncio.run(run())
    assert waits == []


def test_web_config_csrf_jobs_and_secret_errors(monkeypatch):
    from fastapi.testclient import TestClient

    from sisifo.web.server import app
    monkeypatch.setenv("SISIFO_WEB_PASSWORD", "test-password-only")
    with TestClient(app, base_url="http://127.0.0.1") as client:
        assert client.post("/login", data={"password": "test-password-only"}).status_code == 200
        csrf = {"X-CSRF-Token": client.cookies["sisifo_csrf"]}
        assert client.post("/api/config/ai", json={"provider": "export"}).status_code == 403
        response = client.post("/api/config/ai", headers=csrf, json={"provider": "invalid", "nvidia_key": "nvapi-fake-secret"})
        assert response.status_code == 422
        assert "fake-secret" not in response.text
        assert client.post("/api/config/ai", headers=csrf, json={"provider": "export"}).status_code == 200
        assert client.get("/api/jobs").json() == {"jobs": []}
        response = client.post("/api/config/osint/dummy", headers=csrf, json={"api_key": "fake-key"})
        assert response.status_code == 200
        assert "fake-key" not in client.get("/api/config/status").text
        xml = (Path(__file__).parent / "fixtures/nmap.xml").read_bytes()
        response = client.post("/api/import-nmap", headers=csrf,
                               files={"file": ("../../outside.xml", xml, "application/xml")},
                               data={"target": "192.0.2.10", "project": "test"})
        assert response.status_code == 200, response.text
        session_id = response.json()["session_id"]
        preview = client.post("/api/analyze/preview", headers=csrf, json={"session_id": session_id})
        assert preview.status_code == 200
        assert "redaction" in preview.json()
        assert client.post("/api/analyze/preview", json={"session_id": session_id}).status_code == 403
        assert client.post("/login", content=b"x" * (128 * 1024 + 1)).status_code == 413
        assert client.post("/api/analyze", headers=csrf, json={"session_id": session_id, "endpoint": "http://unapproved.example"}).status_code == 400
        assert client.get(f"/api/sessions/{session_id}/export-vault?vault=/tmp").status_code == 405


def test_jobs_endpoint_persists_between_lifespans(monkeypatch):
    from fastapi.testclient import TestClient

    from sisifo.web.server import app
    monkeypatch.setenv("SISIFO_WEB_PASSWORD", "test-password-only")
    with TestClient(app, base_url="http://127.0.0.1") as client:
        client.post("/login", data={"password": "test-password-only"})
        job_id = app.state.jobs.submit("local", {}, lambda control: {"status": "partial"})
    with TestClient(app, base_url="http://127.0.0.1") as client:
        client.post("/login", data={"password": "test-password-only"})
        response = client.get(f"/api/jobs/{job_id}")
        assert response.status_code == 200
        assert response.json()["status"] in {"partial", "cancelled"}
