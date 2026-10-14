from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class ConnectorStatus(str, Enum):
    AVAILABLE = "available"
    NOT_CONFIGURED = "not_configured"
    EXPERIMENTAL = "experimental"
    PLANNED = "planned"


class QueryType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"


class CredentialField(BaseModel):
    name: str
    description: str
    secret: bool = True


class ConnectorConfig(BaseModel):
    fields: List[CredentialField] = Field(default_factory=list)
    extra: Dict[str, Any] = Field(default_factory=dict)


class ConnectorMeta(BaseModel):
    id: str
    name: str
    description: str
    version: str
    query_types: List[QueryType]
    config: ConnectorConfig
    allowed_destinations: List[str] = Field(default_factory=list)
    capabilities: List[str] = Field(default_factory=list)
    limits: Dict[str, Any] = Field(default_factory=dict)
    status: ConnectorStatus = ConnectorStatus.NOT_CONFIGURED


class ConnectorResult(BaseModel):
    source: str
    query: str
    query_type: QueryType
    collected_at: str  # ISO datetime
    original_timestamp: Optional[str] = None
    evidence: Dict[str, Any]
    reference_url: Optional[str] = None
    warnings: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)

    @field_validator("collected_at", "original_timestamp", mode="before")
    @classmethod
    def validate_datetime(cls, v):
        if v is None:
            return v
        if isinstance(v, datetime):
            return v.isoformat()
        if isinstance(v, str):
            # Validate ISO format
            try:
                parsed = datetime.fromisoformat(v.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    raise ValueError("Timezone ausente")
                return v
            except ValueError:
                raise ValueError("Timestamp deve estar no formato ISO 8601")
        raise ValueError("Timestamp inválido")


class BaseConnector:
    """Base class for OSINT connectors."""

    meta: ConnectorMeta
    simulated = False
    ai_evidence_fields = frozenset()

    async def query_with_transport(self, query, query_type, config, transport, control=None):
        raise NotImplementedError("Conector real deve implementar query_with_transport")

    def validate_config(self, config: Dict[str, Any]) -> bool:
        raise NotImplementedError

    def diagnose(self, config: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    def query(
        self, query: str, query_type: QueryType, config: Dict[str, Any]
    ) -> List[ConnectorResult]:
        raise NotImplementedError

    def normalize(self, raw: Any, original_query: str = "") -> List[ConnectorResult]:
        raise NotImplementedError

    def validate_query(self, query: str, query_type: QueryType) -> bool:
        """Validate query format based on query type."""
        if query_type == QueryType.DOMAIN:
            import re

            return bool(
                len(query) <= 253
                and all(
                    re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                    for part in query.split(".")
                )
            )
        elif query_type == QueryType.IP:
            import ipaddress

            try:
                ipaddress.ip_address(query)
                return True
            except ValueError:
                return False
        elif query_type == QueryType.URL:
            from urllib.parse import urlparse

            try:
                result = urlparse(query)
                return all([result.scheme in ("http", "https"), result.netloc])
            except Exception:
                return False
        elif query_type == QueryType.HASH:
            return bool(
                query
                and len(query) in (32, 40, 64)
                and all(c in "0123456789abcdefABCDEF" for c in query)
            )
        elif query_type == QueryType.EMAIL:
            # Basic email validation - RFC 5322 simplified
            import re

            if len(query) > 254:
                return False
            # Check for control characters
            if any(ord(c) < 32 or ord(c) == 127 for c in query):
                return False
            # Basic format: local@domain
            parts = query.split("@")
            if len(parts) != 2:
                return False
            local, domain = parts
            if not local or not domain:
                return False
            if len(local) > 64:
                return False
            # Local part: no spaces, no control chars, reasonable chars
            if not re.fullmatch(
                r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*", local
            ):
                return False
            # Domain validation
            return bool(
                re.fullmatch(
                    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*",
                    domain,
                )
            )
        return False
