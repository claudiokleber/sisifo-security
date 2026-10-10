import asyncio
import json
import threading
import time
from unittest.mock import Mock

import httpx
import pytest

from sisifo.core.execution import BudgetExceeded, Cancelled, Control
from sisifo.core.integration import CapabilityCatalog, ExecutionRequest, IntegrationExecutionService
from sisifo.osint.executor import OsintExecutionError, OsintExecutor
from sisifo.osint.hibp import HibpConnector
from sisifo.osint.integration import register_hibp_integration
from sisifo.osint.interaction import ai_preview, interpret


def test_generic_hibp_rejects_even_forged_approval(tmp_path):
    from sisifo.core.config import save_service_config
    save_service_config('osint_hibp', {'api_key': '0' * 32})
    catalog = CapabilityCatalog()
    register_hibp_integration(catalog)
    jobs = Mock()
    service = IntegrationExecutionService(catalog, jobs, tmp_path)
    request = ExecutionRequest(integration_id='osint_hibp', capability='query',
        inputs={'query': 'test@example.com'}, approval_ref='invented')
    with pytest.raises(ValueError, match='aprovação'):
        service.submit(request)
    jobs.submit.assert_not_called()


def test_catalog_reflects_saved_and_removed_credentials():
    from sisifo.core.config import delete_service_config, save_service_config
    catalog = CapabilityCatalog()
    register_hibp_integration(catalog)
    assert catalog.get('osint_hibp').status == 'not_configured'
    save_service_config('osint_hibp', {'api_key': '0' * 32})
    assert catalog.get('osint_hibp').status == 'available'
    assert catalog.list()[0].status == 'available'
    delete_service_config('osint_hibp')
    assert catalog.get_status('osint_hibp') == 'not_configured'


def test_preview_contract_per_connector():
    result = {'source': 'dummy', 'evidence': {'simulated': True, 'domain': 'example.com', 'password': 'secret'}}
    preview = json.loads(ai_preview([result], [0]))
    assert preview[0]['evidence'] == {'simulated': True, 'domain': 'example.com'}
    with pytest.raises(ValueError, match='evidências'):
        ai_preview([{'source': 'dummy', 'evidence': {'password': 'secret'}}], [0])
    with pytest.raises(ValueError, match='Fonte'):
        ai_preview([{'source': 'unknown', 'evidence': {'domain': 'example.com'}}], [0])


@pytest.mark.parametrize('cancel', [True, False])
def test_ai_interpretation_interrupts_waiting_transport(monkeypatch, cancel):
    from sisifo.core import ai_connection as ai
    entered = threading.Event()
    closed = threading.Event()
    async def handler(request):
        entered.set()
        try:
            await asyncio.sleep(10)
        finally:
            closed.set()
    original = httpx.AsyncClient
    monkeypatch.setattr(ai, 'AsyncClient', lambda **kw: original(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr(ai, 'connection', lambda: {'endpoint': 'https://example.invalid', 'api_key': '', 'model': 'test'})
    control = Control(2 if cancel else 0.15)
    def stop():
        if entered.wait(2) and cancel:
            control.cancelled.set()
    thread = threading.Thread(target=stop)
    thread.start()
    start = time.monotonic()
    try:
        with pytest.raises(Cancelled if cancel else BudgetExceeded):
            interpret('[]', control=control)
        assert time.monotonic() - start < 1.5
        assert closed.is_set()
    finally:
        thread.join(3)


@pytest.mark.asyncio
async def test_retry_after_120_is_not_shortened(monkeypatch):
    executor = OsintExecutor(HibpConnector())
    executor._rate_buckets.clear()
    calls = []
    waits = []
    def handler(request):
        calls.append(request)
        return httpx.Response(429, headers={'Retry-After': '120'}) if len(calls) == 1 else httpx.Response(200, json=[])
    async def sleep(seconds):
        waits.append(seconds)
    executor._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr('sisifo.osint.executor.asyncio.sleep', sleep)
    try:
        await executor._execute_http_query('https://haveibeenpwned.com/api/v3/test')
        assert waits == [120]
        calls.clear()
        with pytest.raises(OsintExecutionError) as error:
            await executor._execute_http_query('https://haveibeenpwned.com/api/v3/test', control=Control(10))
        assert error.value.details['retry_after'] == 120
        assert len(calls) == 1
    finally:
        await executor.close()
