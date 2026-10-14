from sisifo.osint import get_connector, list_connectors
from sisifo.osint.contract import ConnectorStatus, QueryType


def test_list_connectors():
    connectors = list_connectors()
    assert "dummy" in connectors
    meta = connectors["dummy"]
    assert meta["id"] == "dummy"
    assert meta["status"] == ConnectorStatus.EXPERIMENTAL.value
    assert QueryType.DOMAIN.value in meta["query_types"]


def test_dummy_connector_query():
    conn = get_connector("dummy")
    config = {"api_key": "test-key"}
    assert conn.validate_config(config)
    diag = conn.diagnose(config)
    assert diag["ok"] is True
    results = conn.query("example.com", QueryType.DOMAIN, config)
    assert len(results) == 1
    r = results[0]
    assert r.source == "dummy"
    assert r.query == "example.com"
    assert r.evidence["simulated"] is True
    assert "Resultado simulado" in r.warnings[0]
