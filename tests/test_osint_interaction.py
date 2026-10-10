import asyncio
import time

import httpx
import pytest
from typer.testing import CliRunner

from sisifo.core.execution import BudgetExceeded, Cancelled, Control
from sisifo.osint.contract import QueryType
from sisifo.osint.executor import OsintExecutionError, OsintExecutor
from sisifo.osint.hibp import HibpConnector
from sisifo.osint.interaction import Proposals, ai_preview


@pytest.mark.asyncio
@pytest.mark.parametrize('status,expected', [(401, 'AUTHENTICATION_FAILED'), (403, 'ACCESS_FORBIDDEN'), (429, 'RATE_LIMIT_EXCEEDED'), (404, None)])
async def test_executor_http_contract(status, expected):
    executor = OsintExecutor(HibpConnector())
    executor.meta = executor.meta.model_copy(deep=True)
    executor.meta.limits['max_retries'] = 0
    executor._rate_buckets.clear()
    executor._client = httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(status, json={}, request=req)))
    try:
        if expected:
            with pytest.raises(OsintExecutionError) as error:
                await executor.execute_query('test@example.com', QueryType.EMAIL, {'api_key': '0' * 32})
            assert error.value.code == expected
        else:
            assert await executor.execute_query('test@example.com', QueryType.EMAIL, {'api_key': '0' * 32}) == []
        assert len(executor._rate_buckets['hibp']) == 1
    finally:
        await executor.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('during_retry', [False, True])
@pytest.mark.parametrize('cancel', [False, True])
async def test_real_transport_interrupts_inflight_and_backoff(during_retry, cancel):
    executor = OsintExecutor(HibpConnector())
    executor._rate_buckets.clear()
    entered = asyncio.Event()
    closed = asyncio.Event()
    async def handler(request):
        entered.set()
        if during_retry:
            return httpx.Response(429, headers={'Retry-After': '1'}, request=request)
        try:
            await asyncio.sleep(10)
        finally:
            closed.set()
    executor._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    control = Control(seconds=2 if cancel else 0.15)
    async def interrupt():
        await entered.wait()
        await asyncio.sleep(0.08)
        if cancel:
            control.cancelled.set()
    timer = asyncio.create_task(interrupt())
    started = time.monotonic()
    try:
        with pytest.raises(Cancelled if cancel else (OsintExecutionError if during_retry else BudgetExceeded)):
            await executor.execute_query('test@example.com', QueryType.EMAIL, {'api_key': '0' * 32}, control)
        assert time.monotonic() - started < 1.5
        if not during_retry:
            assert closed.is_set()
    finally:
        await timer
        await executor.close()


def test_proposal_owner_expiry_immutable_and_replay():
    store = Proposals()
    data = {'query': 'first@example.com'}
    token = store.create('a', 'query', data)
    data['query'] = 'changed@example.com'
    with pytest.raises(ValueError):
        store.execute(token, 'b', 'query', lambda _: {})
    with pytest.raises(ValueError):
        store.execute(token, 'a', 'ai', lambda _: {})
    calls = []
    def action(payload):
        calls.append(payload)
        return {'job_id': 'same'}
    assert store.execute(token, 'a', 'query', action) == store.execute(token, 'a', 'query', action)
    assert calls == [{'query': 'first@example.com'}]
    store.items[token]['expires'] = 0
    with pytest.raises(ValueError):
        store.execute(token, 'a', 'query', action)


def test_preview_omits_query_secrets_and_unselected_results():
    results = [{'query': 'person@example.com', 'source': 'hibp', 'evidence': {
        'hibp_breach_name': 'Selected', 'password': 'hidden', 'hibp_title': 'person@example.com'}},
        {'source': 'hibp', 'evidence': {'hibp_breach_name': 'Unselected'}}]
    preview = ai_preview(results, [0])
    assert 'Selected' in preview and 'resultado-1' in preview
    assert all(s not in preview for s in ['person@example.com', 'hidden', 'Unselected'])
    for indices in ([], [-1], [0, 0], [2]):
        with pytest.raises(ValueError):
            ai_preview(results, indices)


def test_cli_terminal_and_help(monkeypatch):
    from sisifo.cli.commands import osint
    from sisifo.cli.main import app
    called = []
    monkeypatch.setattr(osint, '_interactive_loop', lambda: called.append(True))
    runner = CliRunner()
    assert runner.invoke(app, ['osint', 'terminal']).exit_code == 0
    assert called == [True]
    result = runner.invoke(app, ['help'])
    assert result.exit_code == 0
    assert 'sisifo osint terminal' in result.output
    assert 'terminal' in runner.invoke(app, ['osint', '--help']).output


def test_web_javascript_proposal_contract():
    import shutil
    import subprocess
    from pathlib import Path
    node = shutil.which('node')
    if not node:
        pytest.skip('Node indisponível')
    subprocess.run([node, 'tests/osint_ui.cjs'], cwd=Path(__file__).parents[1], check=True)


def test_cli_interpretation_requires_separate_consent(monkeypatch):
    from sisifo.cli.commands import osint
    from sisifo.core import ai_connection
    monkeypatch.setattr(ai_connection, 'public_status', lambda: {'configured': True, 'endpoint': 'https://example.invalid', 'model': 'fake'})
    monkeypatch.setattr(osint.Prompt, 'ask', lambda *a, **kw: '1')
    monkeypatch.setattr(osint.Confirm, 'ask', lambda *a, **kw: False)
    sent = []
    monkeypatch.setattr(osint, 'interpret', lambda preview: sent.append(preview) or {'content': 'Sintético'})
    results = [{'source': 'hibp', 'query': 'test@example.com', 'evidence': {'hibp_breach_name': 'Synthetic'}}]
    osint._offer_interpretation(results)
    assert sent == []
    monkeypatch.setattr(osint.Confirm, 'ask', lambda *a, **kw: True)
    osint._offer_interpretation(results)
    assert len(sent) == 1 and 'test@example.com' not in sent[0]


def test_web_consent_and_selected_ai_preview(monkeypatch):
    from starlette.testclient import TestClient

    from sisifo.core.config import save_service_config
    from sisifo.osint.hibp import HibpConnector
    from sisifo.web import server
    monkeypatch.setenv('SISIFO_WEB_PASSWORD', 'synthetic-password')
    save_service_config('osint_hibp', {'api_key': '0' * 32})
    results = HibpConnector().normalize([{'Name': 'Synthetic', 'DataClasses': ['Email addresses']}], 'test@example.com')
    controls = []
    def query(conn, value, qt, cfg, control):
        controls.append(control)
        return results
    monkeypatch.setattr(server, 'run_query', query)
    sent = []
    def interpret(preview, control=None):
        sent.append(preview)
        return {'content': 'Interpretação de teste'}
    monkeypatch.setattr(server, 'interpret', interpret)
    monkeypatch.setattr('sisifo.core.ai_connection.public_status', lambda: {'configured': True, 'endpoint': 'http://127.0.0.1/test'})
    with TestClient(server.app, base_url='http://127.0.0.1') as client:
        client.post('/login', data={'password': 'synthetic-password'})
        headers = {'X-CSRF-Token': client.cookies['sisifo_csrf']}
        body = {'connector_id': 'hibp', 'query': 'test@example.com', 'query_type': 'email'}
        assert client.post('/api/osint/query', headers=headers, json=body).status_code == 422
        proposal = client.post('/api/osint/proposals', headers=headers, json=body).json()
        assert not controls
        approval = {'proposal_id': proposal['proposal_id'], 'confirmed': True}
        assert client.post('/api/osint/query', json=approval).status_code == 403
        assert client.post('/api/osint/query', headers=headers, json=approval | {'query': 'changed@example.com'}).status_code == 422
        first = client.post('/api/osint/query', headers=headers, json=approval).json()
        assert first == client.post('/api/osint/query', headers=headers, json=approval).json()
        job_id = first['job_id']
        for _ in range(100):
            if server.app.state.jobs.get(job_id)['status'] == 'completed':
                break
            time.sleep(0.01)
        assert len(controls) == 1 and isinstance(controls[0], Control)
        preview = client.post('/api/osint/ai/preview', headers=headers, json={'job_id': job_id, 'indices': [0]}).json()
        assert 'test@example.com' not in preview['preview']
        assert not sent
        approval = {'proposal_id': preview['proposal_id'], 'confirmed': True}
        answer = client.post('/api/osint/ai/interpret', headers=headers, json=approval)
        assert answer.status_code == 200, answer.text
        for _ in range(100):
            if sent:
                break
            time.sleep(0.01)
        assert sent == [preview['preview']]


def test_beginner_terminal_numeric_selection_and_portuguese_confirmation():
    from sisifo.cli.main import app
    from sisifo.core.config import save_service_config
    save_service_config('osint_dummy', {'api_key': 'synthetic'})
    result = CliRunner().invoke(app, ['osint', 'terminal'], input='1\n1\nexample.com\ns\n0\n')
    assert result.exit_code == 0
    assert 'Consulta concluída' in result.output
    assert 'Resultado simulado' in result.output
    assert 'Configurar' in result.output
    assert 'ConnectorStatus.' not in result.output
