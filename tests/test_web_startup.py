import socket

import pytest
from typer.testing import CliRunner


def test_login_and_sessions(monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sisifo.web.server import app

    monkeypatch.setenv("SISIFO_WEB_PASSWORD", "test-password-only")
    with TestClient(app, base_url="http://127.0.0.1") as client:
        assert client.get("/health").status_code == 200
        assert client.get("/", follow_redirects=False).headers["location"] == "/login"
        assert client.get("/login").status_code == 200
        assert client.post("/login", data={"password": "wrong"}).status_code == 401
        assert client.post("/login", data={"password": "test-password-only"}).status_code == 200
        assert client.get("/api/sessions").json() == {"sessions": []}
        assert client.get("/api/config/status").json()["web_password_configured"]
        assert (
            client.get(
                "/health", headers={"Host": "evil.test", "Origin": "http://127.0.0.1"}
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/login",
                data={"password": "test-password-only"},
                headers={"Origin": "https://evil.test"},
            ).status_code
            == 403
        )
        assert client.post("/api/scan", json={"target": "localhost"}).status_code == 403


def test_occupied_port_is_failure():
    pytest.importorskip("fastapi")
    from sisifo.cli.main import app

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        result = CliRunner().invoke(
            app, ["web", "--no-browser", "--port", str(sock.getsockname()[1])]
        )
        assert result.exit_code == 1
        assert "Servidor web rodando" not in result.output


def test_sibling_path_is_rejected(tmp_path):
    pytest.importorskip("fastapi")
    from fastapi import HTTPException

    from sisifo.web.security import validate_path

    base = tmp_path / "data"
    base.mkdir()
    sibling = tmp_path / "data-other"
    sibling.mkdir()
    (sibling / "secret").write_text("fake")
    with pytest.raises(HTTPException) as error:
        validate_path(base, "../data-other/secret")
    assert error.value.status_code == 403


def test_menu_terminal_returns():
    from sisifo.cli.main import app

    result = CliRunner().invoke(app, ["menu"], input="0\n")
    assert result.exit_code == 0
    assert "Escolha" in result.output
    assert result.output.count("Escolha") == 1


def test_menu_reuses_web(monkeypatch):
    from sisifo.cli import main
    from sisifo.cli.commands import menu as menu_mod

    opened = []
    monkeypatch.setattr(menu_mod, "existing_web", lambda port: True)
    monkeypatch.setattr(main.webbrowser, "open", lambda url: opened.append(url) or True)

    def unexpected(**kwargs):
        raise AssertionError("must not start another server")

    monkeypatch.setattr(main, "web", unexpected)
    result = CliRunner().invoke(main.app, ["menu"], input="6\ns\n")
    assert result.exit_code == 0
    assert opened == ["http://127.0.0.1:8000"]
