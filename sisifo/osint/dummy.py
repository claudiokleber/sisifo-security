from datetime import datetime, timezone
from typing import Any, Dict, List

from sisifo.osint.contract import (
    BaseConnector,
    ConnectorConfig,
    ConnectorMeta,
    ConnectorResult,
    ConnectorStatus,
    CredentialField,
    QueryType,
)


class DummyConnector(BaseConnector):
    simulated = True
    ai_evidence_fields = frozenset({"simulated", "query_type", "domain", "ip"})
    meta = ConnectorMeta(
        id="dummy",
        name="Dummy Connector",
        description="Conector de referência para testes, não faz requisições reais.",
        version="0.1.0",
        query_types=[QueryType.DOMAIN, QueryType.IP],
        config=ConnectorConfig(
            fields=[
                CredentialField(name="api_key", description="Chave de API fictícia", secret=True)
            ]
        ),
        allowed_destinations=["api.example.com"],
        capabilities=["lookup"],
        limits={"rate_per_minute": 60, "max_retries": 2, "read_timeout": 10.0},
        status=ConnectorStatus.EXPERIMENTAL,
    )

    def validate_config(self, config: Dict[str, Any]) -> bool:
        return bool(isinstance(config.get("api_key"), str) and config["api_key"].strip())

    def diagnose(self, config: Dict[str, Any]) -> Dict[str, Any]:
        if not self.validate_config(config):
            return {
                "ok": False,
                "reason": "api_key ausente ou inválida",
                "will_call_external": False,
            }
        return {
            "ok": True,
            "detail": "Configuração válida (simulado).",
            "will_call_external": False,
        }

    def query(
        self, query: str, query_type: QueryType, config: Dict[str, Any]
    ) -> List[ConnectorResult]:
        if not self.validate_config(config):
            raise ValueError("Configuração inválida")
        if not self.validate_query(query, query_type):
            raise ValueError(f"Consulta inválida para tipo {query_type.value}")
        # Simulated result
        return [
            ConnectorResult(
                source=self.meta.id,
                query=query,
                query_type=query_type,
                collected_at=datetime.now(timezone.utc).isoformat(),
                evidence={"simulated": True, "query_type": query_type.value},
                reference_url=None,
                warnings=["Resultado simulado, não consultar serviço real."],
                limitations=["Apenas demonstração."],
            )
        ]

    def normalize(self, raw: Any, original_query: str = "") -> List[ConnectorResult]:
        # For dummy, raw is already ConnectorResult list
        if isinstance(raw, list):
            return raw
        return []
