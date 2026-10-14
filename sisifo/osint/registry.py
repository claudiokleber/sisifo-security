from typing import Dict, Type

from sisifo.osint.contract import BaseConnector
from sisifo.osint.dummy import DummyConnector
from sisifo.osint.hibp import HibpConnector

_registry: Dict[str, Type[BaseConnector]] = {
    "dummy": DummyConnector,
    "hibp": HibpConnector,
}


def get_connector(connector_id: str) -> BaseConnector:
    cls = _registry.get(connector_id)
    if not cls:
        raise KeyError(f"Connector {connector_id} não encontrado")
    return cls()


def list_connectors() -> Dict[str, Dict]:
    return {cid: cls().meta.model_dump() for cid, cls in _registry.items()}
