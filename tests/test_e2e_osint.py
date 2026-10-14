"""Opt-in real-browser tests; external HTTP only is simulated."""

import json
import os
import re
import shutil
import subprocess
import sys
import time
from contextlib import ExitStack
from pathlib import Path

import httpx
import pytest

pytestmark = pytest.mark.e2e
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def web_server(tmp_path, request):
    options = getattr(request, "param", {})
    env = {k: v for k, v in os.environ.items() if not k.startswith("SISIFO_")}
    env.pop("NVIDIA_API_KEY", None)
    env["PYTHONPATH"] = str(ROOT)
    ready = tmp_path / "ready.json"
    command = [
        sys.executable,
        str(ROOT / "tests/support/osint_server.py"),
        str(tmp_path),
        json.dumps(options),
    ]
    with (tmp_path / "server.log").open("wb") as log:
        proc = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 20
            with httpx.Client(trust_env=False, timeout=0.5) as client:
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        pytest.fail("Test server exited; inspect server.log")
                    if ready.exists():
                        info = json.loads(ready.read_text())
                        try:
                            response = client.get(
                                info["url"] + "/__test/state",
                                headers={"X-Test-Token": info["token"]},
                            )
                            # On Windows the venv launcher may own a child Python process.
                            if (
                                response.status_code == 200
                                and response.json()["pid"] == info["pid"]
                            ):
                                break
                        except httpx.TransportError:
                            pass
                    time.sleep(0.05)
                else:
                    pytest.fail("Test server did not become ready; inspect server.log")
            yield info
        finally:
            if proc.poll() is None:
                if os.name == "nt":
                    # Terminate only this owned test process tree (venv launcher + child).
                    subprocess.run(
                        ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                        check=True,
                        stdout=subprocess.DEVNULL,
                    )
                else:
                    proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            log.flush()
            report = getattr(request.node, "rep_call", None)
            if report is None or report.failed:
                artifacts = Path(os.getenv("SISIFO_E2E_ARTIFACTS", str(tmp_path / "artifacts")))
                artifacts.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(
                    tmp_path / "server.log", artifacts / (artifact_name(request) + "-server.log")
                )


def artifact_name(request):
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", request.node.name)


@pytest.fixture
def page(web_server, request, tmp_path):
    from playwright.sync_api import sync_playwright

    artifacts = Path(os.getenv("SISIFO_E2E_ARTIFACTS", str(tmp_path / "artifacts")))
    artifacts.mkdir(parents=True, exist_ok=True)
    name = artifact_name(request)
    with sync_playwright() as playwright, ExitStack() as cleanup:
        browser = playwright.chromium.launch(headless=True)
        cleanup.callback(browser.close)
        context = browser.new_context(viewport={"width": 390, "height": 844})
        cleanup.callback(context.close)
        context.tracing.start(screenshots=True, snapshots=True, sources=True)
        tab = context.new_page()
        try:
            tab.goto(web_server["url"] + "/login")
            tab.locator('input[name="password"]').fill("synthetic-test-password")
            tab.locator('button[type="submit"]').click()
            tab.wait_for_url(web_server["url"] + "/")
            tab.locator('button[data-tab="osint"]').click()
            yield tab
        finally:
            report = getattr(request.node, "rep_call", None)
            if report is None or report.failed:
                try:
                    tab.screenshot(path=str(artifacts / f"{name}.png"), full_page=True)
                finally:
                    context.tracing.stop(path=str(artifacts / f"{name}.zip"))
            else:
                context.tracing.stop()


def state(server):
    with httpx.Client(trust_env=False) as client:
        response = client.get(
            server["url"] + "/__test/state", headers={"X-Test-Token": server["token"]}
        )
        response.raise_for_status()
        return response.json()


def submit(page, email="test@example.com", accept=True):
    page.locator("#osint-query").fill(email)
    page.once("dialog", lambda dialog: dialog.accept() if accept else dialog.dismiss())
    page.locator('#osint-query-form button[type="submit"]').click()


def expect_jobs(page, text):
    from playwright.sync_api import expect

    expect(page.locator("#osint-jobs")).to_contain_text(text, timeout=15000)


@pytest.mark.parametrize("web_server", [{"configured": False}], indirect=True)
def test_configuration_and_keyboard(page, web_server):
    from playwright.sync_api import expect

    button = page.locator('#osint-query-form button[type="submit"]')
    expect(button).to_be_disabled()
    page.get_by_role("button", name="Configurar — Have I Been Pwned").click()
    page.locator('dialog input[name="api_key"]').fill("a" * 32)
    page.get_by_role("button", name="Salvar", exact=True).click()
    expect(button).to_be_enabled()
    expect(page.locator("#osint-query-type")).to_have_value("email")
    field = page.locator("#osint-query")
    field.focus()
    page.keyboard.type("test@example.com")
    expect(field).to_have_value("test@example.com")
    assert state(web_server)["hibp"] == 0
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")


def test_invalid_input_and_declined_confirmation(page, web_server):
    page.locator("#osint-query").fill("invalid-email")
    page.locator('#osint-query-form button[type="submit"]').click()
    assert not page.locator("#osint-query").evaluate("el => el.checkValidity()")
    submit(page, accept=False)
    assert state(web_server)["hibp"] == 0
    assert page.locator("#osint-jobs .job-item").count() == 0


@pytest.mark.parametrize(
    "email,text",
    [
        ("test@example.com", "Test Breach"),
        ("empty@example.com", "não garante"),
        ("auth@example.com", "A chave foi recusada"),
        ("rate@example.com", "limite"),
        ("timeout@example.com", "Não foi possível conectar"),
    ],
)
def test_results_and_errors(page, web_server, email, text):
    submit(page, email)
    expect_jobs(page, text)
    assert state(web_server)["hibp"] >= 1


def test_cancellation(page, web_server):
    submit(page, "slow@example.com")
    expect_jobs(page, "Cancelar consulta")
    deadline = time.monotonic() + 10
    while state(web_server)["hibp"] == 0:
        assert time.monotonic() < deadline
        time.sleep(0.05)
    page.get_by_role("button", name="Cancelar consulta").click()
    expect_jobs(page, "Cancelada por você")
    assert state(web_server)["cancelled"] == 1


def test_ai_consent_and_xss(page, web_server):
    submit(page, "xss@example.com")
    expect_jobs(page, "<img src=x onerror=")
    assert page.locator("#osint-jobs img").count() == 0
    assert page.evaluate("window.__xss === undefined")
    page.locator('#osint-jobs input[type="checkbox"]').first.check()
    page.get_by_role("button", name="Revisar dados para a IA").click()
    authorize = page.get_by_role("button", name="Autorizar envio desta prévia à IA")
    authorize.wait_for(state="visible")
    assert state(web_server)["ai"] == 0
    authorize.click()
    expect_jobs(page, "Interpretação sintética")
    assert state(web_server)["ai"] == 1
    assert state(web_server)["ai_contains_email"] is False


@pytest.mark.parametrize("web_server", [{"ai": False}], indirect=True)
def test_ai_not_configured(page, web_server):
    submit(page)
    expect_jobs(page, "Test Breach")
    page.locator('#osint-jobs input[type="checkbox"]').first.check()
    page.get_by_role("button", name="Revisar dados para a IA").click()
    from playwright.sync_api import expect

    expect(page.get_by_text("A IA ainda não está configurada.", exact=False)).to_be_visible()
    assert state(web_server)["ai"] == 0


def test_repeated_approval_reuses_job(page, web_server):
    # Capture the actual UI approval, then replay it with the same browser session.
    with page.expect_response(
        lambda response: (
            response.url.endswith("/api/osint/query") and response.request.method == "POST"
        )
    ) as observed:
        submit(page)
    response = observed.value
    assert response.ok
    first = response.json()
    csrf = next(
        cookie["value"] for cookie in page.context.cookies() if cookie["name"] == "sisifo_csrf"
    )
    replay = page.request.post(
        web_server["url"] + "/api/osint/query",
        headers={"X-CSRF-Token": csrf, "Origin": web_server["url"]},
        data=response.request.post_data_json,
    )
    assert replay.ok
    assert replay.json()["job_id"] == first["job_id"]
    expect_jobs(page, "Test Breach")
    assert state(web_server)["hibp"] == 1
