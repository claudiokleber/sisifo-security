"""Disposable test server. Never imported by the production application."""

import asyncio
import json
import os
import secrets
import socket
import sys
from pathlib import Path

import httpx
import uvicorn


def main():
    root = Path(sys.argv[1]).resolve()
    options = json.loads(sys.argv[2])
    root.mkdir(parents=True, exist_ok=True)
    for key in list(os.environ):
        if key.startswith("SISIFO_") or key == "NVIDIA_API_KEY":
            os.environ.pop(key)
    os.environ.update(
        SISIFO_DATA_DIR=str(root / "data"),
        SISIFO_CONFIG_DIR=str(root / "config"),
        SISIFO_WEB_PASSWORD="synthetic-test-password",
    )

    from sisifo.core import ai_connection
    from sisifo.core.config import save_config, save_service_config
    from sisifo.osint import executor

    counters = {"pid": os.getpid(), "hibp": 0, "ai": 0, "cancelled": 0, "ai_contains_email": False}

    async def external(request):
        if request.url.host == "haveibeenpwned.com":
            counters["hibp"] += 1
            query = request.url.path.rsplit("/", 1)[-1]
            if "slow" in query:
                try:
                    await asyncio.sleep(120)
                except asyncio.CancelledError:
                    counters["cancelled"] += 1
                    raise
            if "empty" in query:
                return httpx.Response(404)
            if "auth" in query:
                return httpx.Response(401)
            if "rate" in query:
                return httpx.Response(429, headers={"Retry-After": "120"})
            if "timeout" in query:
                raise httpx.ReadTimeout("Synthetic timeout", request=request)
            title = "<img src=x onerror=window.__xss=1>" if "xss" in query else "Test Breach"
            return httpx.Response(
                200,
                json=[
                    {
                        "Name": "TestBreach",
                        "Title": title,
                        "Domain": "example.com",
                        "BreachDate": "2023-01-01",
                        "AddedDate": "2023-01-02T00:00:00Z",
                        "DataClasses": ["Email addresses"],
                        "IsVerified": True,
                    }
                ],
            )
        if request.url.host == "ai.example.invalid":
            counters["ai"] += 1
            counters["ai_contains_email"] = b"@example.com" in request.content
            return httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {
                                "content": "Interpretação sintética com referência ao resultado-1."
                            },
                        }
                    ]
                },
            )
        raise AssertionError("Unexpected destination in isolated test transport")

    # Preserve production HTTP client construction, timeout arguments, connector,
    # executor and AI code. Replace only the socket transport; no external IO.
    real_client = httpx.AsyncClient

    class IsolatedClient(real_client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(external)
            super().__init__(*args, **kwargs)

    executor.httpx.AsyncClient = IsolatedClient
    ai_connection.AsyncClient = IsolatedClient
    if options.get("configured", True):
        save_service_config("osint_hibp", {"api_key": "a" * 32})
    if options.get("ai", True):
        save_service_config(
            "ai_connection",
            {"endpoint": "https://ai.example.invalid/v1", "model": "synthetic", "api_key": ""},
        )
        save_config("api", "synthetic")

    from fastapi import HTTPException, Request

    from sisifo.web.server import app

    token = secrets.token_hex(24)

    @app.get("/__test/state")
    async def test_state(request: Request):
        if request.headers.get("X-Test-Token") != token:
            raise HTTPException(403)
        return counters.copy()

    # Bind once to port zero and pass the same socket to Uvicorn: no allocation race.
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        info = {
            "url": f"http://127.0.0.1:{sock.getsockname()[1]}",
            "token": token,
            "pid": os.getpid(),
        }
        temp = root / "ready.tmp"
        temp.write_text(json.dumps(info), encoding="utf-8")
        temp.replace(root / "ready.json")
        uvicorn.Server(uvicorn.Config(app, log_level="warning")).run(sockets=[sock])


if __name__ == "__main__":
    main()
