import asyncio
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx
from pydantic import ValidationError

from sisifo.core.config import delete_service_config, load_service_config, save_service_config
from sisifo.osint.contract import (
    BaseConnector,
    ConnectorResult,
    ConnectorStatus,
    QueryType,
)


class OsintExecutionError(Exception):
    def __init__(self, message: str, code: str = "EXECUTION_ERROR", details: Optional[Dict] = None):
        super().__init__(message)
        self.code = code
        self.details = details or {}


class OsintExecutor:
    """Execution layer that enforces connector-declared rules."""

    def __init__(self, connector: BaseConnector):
        self.connector = connector
        self.meta = connector.meta
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            limits = self.meta.limits
            timeout = httpx.Timeout(
                connect=limits.get("connect_timeout", 10.0),
                read=limits.get("read_timeout", 30.0),
                write=limits.get("write_timeout", 10.0),
                pool=limits.get("pool_timeout", 5.0),
            )
            limits_config = httpx.Limits(
                max_connections=limits.get("max_connections", 10),
                max_keepalive_connections=limits.get("max_keepalive", 5),
            )
            self._client = httpx.AsyncClient(timeout=timeout, limits=limits_config, follow_redirects=False, trust_env=False)
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    def _validate_destination(self, url: str) -> bool:
        """Validate URL against allowed destinations."""
        if not self.meta.allowed_destinations:
            return False
        try:
            parsed = urlparse(url)
            if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in (None, 443):
                return False
            host = parsed.hostname or ""
            for allowed in self.meta.allowed_destinations:
                if allowed.startswith("*."):
                    if host.endswith(allowed[1:]) or host == allowed[2:]:
                        return True
                elif host == allowed:
                    return True
            return False
        except Exception:
            return False

    _rate_buckets: Dict[str, List[float]] = {}
    _rate_lock = threading.Lock()

    def _check_rate_limit(self) -> bool:
        rate = max(1, min(600, int(self.meta.limits.get("rate_per_minute", 60))))
        with self._rate_lock:
            now = time.monotonic()
            bucket = self._rate_buckets.setdefault(self.meta.id, [])
            bucket[:] = [t for t in bucket if now - t < 60]
            if len(bucket) >= rate:
                return False
            bucket.append(now)
            return True

    async def execute_query(
        self,
        query: str,
        query_type: QueryType,
        config: Dict[str, Any],
    ) -> List[ConnectorResult]:
        """Execute a query with full validation and enforcement."""
        # 1. Validate connector configuration
        if not self.connector.validate_config(config):
            raise OsintExecutionError(
                "Configuração do conector inválida",
                code="INVALID_CONFIG",
            )

        # 2. Validate query type support
        if query_type not in self.meta.query_types:
            raise OsintExecutionError(
                f"Tipo de consulta {query_type.value} não suportado por este conector",
                code="UNSUPPORTED_QUERY_TYPE",
                details={"supported_types": [qt.value for qt in self.meta.query_types]},
            )

        # 3. Validate query format
        if not self.connector.validate_query(query, query_type):
            raise OsintExecutionError(
                f"Formato de consulta inválido para tipo {query_type.value}",
                code="INVALID_QUERY_FORMAT",
            )

        # 4. Check rate limits
        if not self._check_rate_limit():
            raise OsintExecutionError(
                "Limite de taxa excedido",
                code="RATE_LIMIT_EXCEEDED",
            )

        # 5. Execute the query
        try:
            if getattr(self.connector, "simulated", False):
                raw_results = self.connector.query(query, query_type, config)
            else:
                # Real connectors must explicitly use this transport; no legacy direct query fallback.
                raw_results = await self.connector.query_with_transport(query, query_type, config, self)
        except Exception as e:
            raise OsintExecutionError(
                "Erro na execução da consulta",
                code="QUERY_EXECUTION_FAILED",
                details={},
            ) from e

        # 6. Normalize results
        try:
            normalized = self.connector.normalize(raw_results)
        except Exception as e:
            raise OsintExecutionError(
                "Erro na normalização dos resultados",
                code="NORMALIZATION_FAILED",
                details={},
            ) from e

        # 7. Validate each result
        validated_results = []
        for result in normalized:
            try:
                validated = ConnectorResult.model_validate(result.model_dump() if isinstance(result, ConnectorResult) else result)
                if validated.source != self.meta.id or validated.query != query or validated.query_type != query_type:
                    raise ValueError("Proveniência divergente")
                validated_results.append(validated)
            except (ValidationError, ValueError) as e:
                raise OsintExecutionError(
                    f"Resultado inválido após normalização: {e}",
                    code="INVALID_RESULT",
                ) from e

        return validated_results

    async def execute_http_query(self, url, method="GET", headers=None, params=None,
                                 json_data=None, config=None):
        if not self._validate_destination(url):
            raise OsintExecutionError("Destino não permitido", code="DESTINATION_NOT_ALLOWED")
        if method not in {"GET", "POST"}:
            raise OsintExecutionError("Método não permitido")
        client = await self._get_client()
        request_headers = {"User-Agent": "Sisifo-OSINT", "Accept": "application/json", **(headers or {})}
        retries = min(3, max(0, int(self.meta.limits.get("max_retries", 2)))) if method == "GET" else 0
        max_size = min(10 * 1024 * 1024, max(1, int(self.meta.limits.get("max_response_size", 1024 * 1024))))
        for attempt in range(retries + 1):
            if not self._check_rate_limit():
                raise OsintExecutionError("Limite de taxa atingido", code="RATE_LIMIT_EXCEEDED")
            try:
                async with client.stream(method, url, headers=request_headers, params=params, json=json_data) as response:
                    code = response.status_code
                    if code in {429, 502, 503, 504} and attempt < retries:
                        value = response.headers.get("Retry-After", "")
                        wait = min(30, int(value)) if value.isdigit() else 2 ** attempt
                    else:
                        if code >= 300:
                            raise OsintExecutionError(f"Serviço retornou HTTP {code}", code="HTTP_ERROR")
                        body = bytearray()
                        async for chunk in response.aiter_bytes(chunk_size=16384):
                            body.extend(chunk)
                            if len(body) > max_size:
                                raise OsintExecutionError("Resposta excede limite", code="RESPONSE_TOO_LARGE")
                        result = httpx.Response(code, headers=response.headers, content=bytes(body), request=response.request)
                        try:
                            result.json()
                        except (ValueError, UnicodeError):
                            raise OsintExecutionError("Resposta JSON inválida", code="INVALID_JSON") from None
                        return result
                await asyncio.sleep(wait)
            except httpx.RequestError:
                if attempt == retries:
                    raise OsintExecutionError("Falha de rede ou timeout", code="NETWORK_ERROR") from None
                await asyncio.sleep(2 ** attempt)
        raise OsintExecutionError("Tentativas esgotadas")


def run_query(connector, query, query_type, config):
    """Synchronous facade shared by CLI, agent and job workers."""
    async def run():
        executor = OsintExecutor(connector)
        try:
            return await executor.execute_query(query, query_type, config)
        finally:
            await executor.close()
    return asyncio.run(run())


def load_osint_config(connector_id):
    return load_service_config(f"osint_{connector_id}")


def save_osint_config(connector_id, config):
    save_service_config(f"osint_{connector_id}", config)


def delete_osint_config(connector_id):
    return delete_service_config(f"osint_{connector_id}")


def get_connector_status(connector_id):
    from .registry import get_connector
    connector = get_connector(connector_id)
    if connector.meta.status in {ConnectorStatus.EXPERIMENTAL, ConnectorStatus.PLANNED}:
        return connector.meta.status
    return ConnectorStatus.AVAILABLE if connector.validate_config(load_osint_config(connector_id)) else ConnectorStatus.NOT_CONFIGURED
