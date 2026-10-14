"""Common integration infrastructure for Sísifo.

Provides:
- Versioned capability catalog for all integrations
- Typed execution requests with validation
- Shared lifecycle management (adapts to existing JobManager)
- Normalized results and evidence
- Centralized transport and credential handling
"""

import hashlib
import json
import threading
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sisifo.core.config import delete_service_config, load_service_config, save_service_config
from sisifo.core.session import atomic_write

# ============================================================================
# Integration Identity and Capabilities
# ============================================================================


class IntegrationCategory(str, Enum):
    """Integration category classification."""

    TOOL = "tool"  # Local analysis tool (nmap, nikto, etc.)
    DATA_CONNECTOR = "data_connector"  # External data connector (OSINT, APIs)
    ACTIVE_OPERATION = "active_operation"  # Active operation on a target


class IntegrationStatus(str, Enum):
    """Integration availability status."""

    AVAILABLE = "available"  # Ready to use
    NOT_CONFIGURED = "not_configured"  # Missing configuration/credentials
    NOT_INSTALLED = "not_installed"  # Tool not found on system
    EXPERIMENTAL = "experimental"  # Early stage, may change
    DEPRECATED = "deprecated"  # Being phased out
    UNAVAILABLE = "unavailable"  # Temporarily unavailable


class ExecutionMode(str, Enum):
    """Execution mode for the integration."""

    LOCAL = "local"  # Runs locally on the executor
    DOCKER = "docker"  # Runs in Docker container
    REMOTE = "remote"  # Calls external service/API


class EvidenceClassification(str, Enum):
    """Classification of evidence sensitivity."""

    PUBLIC = "public"  # Public information, no restrictions
    INTERNAL = "internal"  # Internal use only
    SENSITIVE = "sensitive"  # Sensitive, restricted access
    CLASSIFIED = "classified"  # Highly sensitive, need-to-know


class IntegrationCapability(BaseModel):
    """Describes a single capability of an integration."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=100, description="Capability identifier")
    description: str = Field(..., max_length=500, description="Human-readable description")
    input_types: List[str] = Field(default_factory=list, description="Supported input types")
    output_types: List[str] = Field(default_factory=list, description="Produced output types")
    requires_credentials: bool = Field(default=False, description="Requires credentials")
    requires_docker: bool = Field(default=False, description="Requires Docker")
    external_network: bool = Field(default=False, description="Requires external network access")
    rate_limit: Optional[int] = Field(default=None, ge=1, description="Requests per minute")
    timeout_seconds: Optional[int] = Field(
        default=None, ge=1, le=3600, description="Default timeout"
    )
    external: bool = Field(default=False, description="Sends data to external service")
    consumes_credits: bool = Field(default=False, description="May consume paid credits")


class IntegrationMeta(BaseModel):
    """Metadata for an integration in the catalog."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, max_length=100, pattern=r"^[a-z0-9_-]+$")
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., max_length=1000)
    version: str = Field(..., pattern=r"^\d+\.\d+\.\d+$")
    category: IntegrationCategory
    capabilities: List["IntegrationCapability"] = Field(default_factory=list)
    entry_point: str = Field(..., description="Module:function or CLI command")
    execution_mode: ExecutionMode = ExecutionMode.LOCAL
    dependencies: List[str] = Field(default_factory=list, description="System dependencies")
    supported_environments: List[str] = Field(default_factory=lambda: ["native", "docker"])
    status: IntegrationStatus = IntegrationStatus.NOT_CONFIGURED
    documentation_url: Optional[str] = None
    execution_limits: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


# ============================================================================
# Execution Contracts
# ============================================================================


class ExecutionScope(str, Enum):
    """Execution scope classification."""

    PASSIVE = "passive"  # Read-only, no target modification
    ACTIVE = "active"  # May modify target state
    INTRUSIVE = "intrusive"  # May disrupt target


class CredentialReference(BaseModel):
    """Reference to a stored credential (no secret in the request)."""

    model_config = ConfigDict(extra="forbid")

    service: str = Field(..., description="Service identifier")
    field: str = Field(..., description="Credential field name")
    required: bool = True


class ExecutionLimits(BaseModel):
    """Execution limits for a request."""

    model_config = ConfigDict(extra="forbid")

    max_duration_seconds: int = Field(default=3600, ge=1, le=86400)
    max_concurrency: int = Field(default=1, ge=1, le=1)
    max_output_size_mib: int = Field(default=100, ge=1, le=10240)
    max_retries: int = Field(default=0, ge=0, le=0)
    rate_limit: Optional[int] = Field(default=None, ge=1, le=6000)
    memory_limit_mib: Optional[int] = Field(default=None, ge=64, le=8192)


class ExecutionRequest(BaseModel):
    """Typed execution request for an integration capability."""

    model_config = ConfigDict(extra="forbid")

    integration_id: str = Field(..., min_length=1)
    capability: str = Field(..., min_length=1)
    inputs: Dict[str, Any] = Field(default_factory=dict)
    options: Dict[str, Any] = Field(default_factory=dict)
    scope: ExecutionScope = ExecutionScope.PASSIVE
    credentials: List[CredentialReference] = Field(default_factory=list)
    limits: ExecutionLimits = Field(default_factory=ExecutionLimits)
    idempotency_key: Optional[str] = Field(default=None, max_length=128)
    approval_ref: Optional[str] = Field(default=None, max_length=256)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("idempotency_key", mode="before")
    @classmethod
    def validate_idempotency_key(cls, v):
        if v is not None and len(v) > 128:
            raise ValueError("Idempotency key too long (max 128 chars)")
        return v

    def canonical_key(self) -> str:
        """Return canonical representation for idempotency."""
        canonical = {
            "integration_id": self.integration_id,
            "capability": self.capability,
            "inputs": self.inputs,
            "options": self.options,
            "scope": self.scope,
            "credentials": [c.model_dump() for c in self.credentials],
            "approval_ref": self.approval_ref,
            "limits": self.limits.model_dump(),
        }
        return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()


class ExecutionResult(BaseModel):
    """Normalized execution result."""

    model_config = ConfigDict(extra="forbid")

    execution_id: str = Field(default_factory=lambda: uuid4().hex)
    integration_id: str
    capability: str
    status: Literal["completed", "partial", "failed", "cancelled", "interrupted"]
    reason: Optional[str] = None
    started_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    finished_at: Optional[str] = None
    duration_seconds: float = 0.0
    tool_version: Optional[str] = None
    inputs_sanitized: Dict[str, Any] = Field(default_factory=dict)
    outputs: Dict[str, Any] = Field(default_factory=dict)
    evidence_refs: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    coverage: Literal["complete", "partial", "inconclusive"] = "complete"
    metrics: Dict[str, Any] = Field(default_factory=dict)
    error_code: Optional[str] = None
    error_details: Optional[Dict[str, Any]] = None

    @field_validator("finished_at", mode="before")
    @classmethod
    def set_finished_at(cls, v):
        if v is None:
            return datetime.now(UTC).isoformat()
        return v


class ExecutionState(str, Enum):
    """Job execution state."""

    PENDING = "pending"
    RUNNING = "running"
    CANCELLING = "cancelling"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


# ============================================================================
# Evidence and Artifact Management
# ============================================================================


class EvidenceType(str, Enum):
    """Type of evidence artifact."""

    RAW_OUTPUT = "raw_output"
    PARSED_DATA = "parsed_data"
    REPORT = "report"
    LOG = "log"
    CAPTURE = "capture"
    SCREENSHOT = "screenshot"
    CONFIG = "config"
    OTHER = "other"


class EvidenceRef(BaseModel):
    """Reference to an evidence artifact."""

    model_config = ConfigDict(extra="forbid")

    execution_id: str
    type: EvidenceType
    path: str = Field(..., description="Relative path in evidence store")
    sha256: str
    size: int
    classification: EvidenceClassification = EvidenceClassification.INTERNAL
    description: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


# ============================================================================
# Credential Management
# ============================================================================


class CredentialManager:
    """Manages credential storage with separation from jobs/plans.

    Reuses existing config system (load_service_config/save_service_config).
    """

    def __init__(self):
        self._lock = threading.RLock()

    def _service_key(self, service: str) -> str:
        return f"osint_{service}"

    def save(self, service: str, fields: Dict[str, str]) -> None:
        """Save credentials for a service."""
        with self._lock:
            key = self._service_key(service)
            existing = load_service_config(key)
            existing.update(fields)
            save_service_config(key, existing)

    def load(self, service: str) -> Dict[str, str]:
        """Load credentials for a service."""
        key = self._service_key(service)
        return load_service_config(key)

    def delete(self, service: str) -> bool:
        """Delete credentials for a service."""
        return delete_service_config(self._service_key(service))

    def status(self, service: str) -> Dict[str, Any]:
        """Get credential status without exposing secrets."""
        key = self._service_key(service)
        data = load_service_config(key)
        return {
            "configured": bool(data),
            "fields": list(data.keys()) if data else [],
        }

    def list_services(self) -> List[str]:
        raise NotImplementedError("Use the registered catalog to enumerate services")


# ============================================================================
# Capability Catalog
# ============================================================================


class CapabilityCatalog:
    """Versioned capability catalog for all integrations."""

    def __init__(self, catalog_path: Optional[str] = None):
        self.catalog_path = Path(catalog_path) if catalog_path else None
        self._catalog: Dict[str, IntegrationMeta] = {}
        self._handlers: Dict[str, Dict[str, Callable]] = {}
        self._schemas: Dict[str, Dict[str, Any]] = {}
        self._policies: Dict[str, Dict[str, Any]] = {}
        self._availability = {}
        self._lock = threading.RLock()
        if catalog_path:
            self._load()

    def _load(self) -> None:
        if self.catalog_path and Path(self.catalog_path).exists():
            with open(self.catalog_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for item in data.get("integrations", []):
                meta = IntegrationMeta(**item)
                self._catalog[meta.id] = meta

    def save(self) -> None:
        if self.catalog_path:
            data = {
                "version": "1.0",
                "updated_at": datetime.now(UTC).isoformat(),
                "integrations": [m.model_dump() for m in self._catalog.values()],
            }
            atomic_write(self.catalog_path, json.dumps(data, ensure_ascii=False, indent=2))

    def register(self, meta: IntegrationMeta) -> None:
        with self._lock:
            meta.updated_at = datetime.now(UTC).isoformat()
            if meta.id in self._catalog:
                meta.created_at = self._catalog[meta.id].created_at
            self._catalog[meta.id] = meta
            self.save()

    def unregister(self, integration_id: str) -> bool:
        with self._lock:
            if integration_id in self._catalog:
                del self._catalog[integration_id]
                self._handlers.pop(integration_id, None)
                self._schemas.pop(integration_id, None)
                self._policies.pop(integration_id, None)
                self.save()
                return True
            return False

    def register_handler(
        self,
        integration_id: str,
        capability: str,
        handler: Callable,
        input_schema: type[BaseModel],
        policy: Optional[Dict[str, Any]] = None,
        options_schema: Optional[type[BaseModel]] = None,
    ) -> None:
        if not isinstance(input_schema, type) or not issubclass(input_schema, BaseModel):
            raise TypeError("Input schema must be a Pydantic model")
        with self._lock:
            if integration_id not in self._catalog:
                raise ValueError(f"Integration {integration_id} not registered")
            if integration_id not in self._handlers:
                self._handlers[integration_id] = {}
                self._schemas[integration_id] = {}
                self._policies[integration_id] = {}
            if capability not in {c.name for c in self._catalog[integration_id].capabilities}:
                raise ValueError(f"Capability {capability} not declared for {integration_id}")
            self._handlers[integration_id][capability] = handler
            self._schemas[integration_id][capability] = (
                input_schema,
                options_schema or EmptyInputs,
            )
            self._policies[integration_id][capability] = policy or {}

    def get_handler(self, integration_id: str, capability: str) -> Optional[Callable]:
        with self._lock:
            return self._handlers.get(integration_id, {}).get(capability)

    def get_schema(self, integration_id: str, capability: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._schemas.get(integration_id, {}).get(capability)

    def get_policy(self, integration_id: str, capability: str) -> Dict[str, Any]:
        with self._lock:
            return self._policies.get(integration_id, {}).get(capability, {})

    def register_availability(self, integration_id, resolver):
        with self._lock:
            self._availability[integration_id] = resolver

    def _refresh(self, integration_id):
        if integration_id in self._availability:
            self._catalog[integration_id].status = self._availability[integration_id]()

    def get(self, integration_id: str) -> Optional[IntegrationMeta]:
        with self._lock:
            self._refresh(integration_id)
            return self._catalog.get(integration_id)

    def list(
        self,
        status: Optional[IntegrationStatus] = None,
        category: Optional[IntegrationCategory] = None,
    ) -> List[IntegrationMeta]:
        with self._lock:
            for integration_id in self._availability:
                self._refresh(integration_id)
            result = list(self._catalog.values())
            if status:
                result = [m for m in result if m.status == status]
            if category:
                result = [m for m in result if m.category == category]
            return sorted(result, key=lambda m: m.name)

    def get_capabilities(self, integration_id: str) -> List[IntegrationCapability]:
        with self._lock:
            meta = self._catalog.get(integration_id)
            return meta.capabilities if meta else []

    def get_status(self, integration_id: str) -> Optional[IntegrationStatus]:
        with self._lock:
            self._refresh(integration_id)
            meta = self._catalog.get(integration_id)
            return meta.status if meta else None


class EmptyInputs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class IntegrationExecutionService:
    """Adapter to the application-owned queue; sensitive operations fail closed."""

    def __init__(self, catalog, job_manager, evidence_root):
        self.catalog = catalog
        self.job_manager = job_manager
        self.evidence_root = Path(evidence_root)
        self._gates = {
            m.id: threading.BoundedSemaphore(
                max(1, min(8, int(m.execution_limits.get("max_concurrency", 1))))
            )
            for m in catalog.list()
        }

    def _validate_scope_and_approval(self, request):
        policy = self.catalog.get_policy(request.integration_id, request.capability)
        order = list(ExecutionScope)
        required = ExecutionScope(policy.get("min_scope", "passive"))
        if order.index(request.scope) < order.index(required):
            raise ValueError("Escopo insuficiente para esta capacidade.")
        # No approval authority exists yet. A client-supplied string is not authorization.
        if required != ExecutionScope.PASSIVE or policy.get("approval_required"):
            raise ValueError(
                "Capacidade bloqueada: requer aprovação; use o fluxo de proposta e confirmação específico do serviço."
            )

    def submit(self, request):
        request = request.model_copy(deep=True)
        meta = self.catalog.get(request.integration_id)
        if not meta:
            raise ValueError("Integração desconhecida.")
        capability = next((c for c in meta.capabilities if c.name == request.capability), None)
        handler = self.catalog.get_handler(request.integration_id, request.capability)
        if not capability or not handler:
            raise ValueError("Capacidade desconhecida ou sem handler.")
        if meta.status not in {IntegrationStatus.AVAILABLE, IntegrationStatus.EXPERIMENTAL}:
            raise ValueError("Integração indisponível ou não configurada.")
        schemas = self.catalog.get_schema(request.integration_id, request.capability)
        if not schemas:
            raise ValueError("Capacidade sem schema.")
        from pydantic import ValidationError

        try:
            request.inputs = schemas[0].model_validate(request.inputs).model_dump(mode="json")
            request.options = schemas[1].model_validate(request.options).model_dump(mode="json")
        except ValidationError:
            raise ValueError("Entradas ou opções inválidas para esta capacidade.") from None
        if request.credentials:
            raise ValueError(
                "Referências de credenciais são definidas pelo registro, não pelo cliente."
            )
        if request.limits.rate_limit is not None or request.limits.memory_limit_mib is not None:
            raise ValueError("Limites de taxa/memória por requisição ainda não suportados.")
        self._validate_scope_and_approval(request)
        policy = self.catalog.get_policy(request.integration_id, request.capability)
        seconds = min(
            request.limits.max_duration_seconds,
            capability.timeout_seconds or 300,
            int(meta.execution_limits.get("max_duration_seconds", 300)),
        )
        output_bytes = (
            min(
                request.limits.max_output_size_mib,
                int(meta.execution_limits.get("max_output_size_mib", 10)),
                100,
            )
            * 1024
            * 1024
        )

        def execute_handler(control):
            import time

            from sisifo.core.redaction import redact

            control.check()
            self._validate_scope_and_approval(request)
            if self.catalog.get(request.integration_id).status not in {
                IntegrationStatus.AVAILABLE,
                IntegrationStatus.EXPERIMENTAL,
            }:
                raise ValueError("Integração indisponível ou não configurada.")
            credentials = {}
            for service in policy.get("credential_services", []):
                credentials[service] = load_service_config(service)
            secrets = [
                v
                for fields in credentials.values()
                for v in fields.values()
                if isinstance(v, str) and v
            ]

            def sanitize(value):
                value = redact(value)[0]
                if isinstance(value, dict):
                    return {k: sanitize(v) for k, v in value.items()}
                if isinstance(value, list):
                    return [sanitize(v) for v in value]
                if isinstance(value, str):
                    for secret in secrets:
                        value = value.replace(secret, "[REDACTED]")
                return value

            def bounded(value):
                if len(json.dumps(value, ensure_ascii=False).encode()) > output_bytes:
                    raise ValueError("Resultado excede limite de saída.")
                value = sanitize(value)
                if len(json.dumps(value, ensure_ascii=False).encode()) > output_bytes:
                    raise ValueError("Resultado excede limite de saída.")
                return value

            # Handlers get the real cancellation/deadline object with bounded progress.
            original_progress = control.progress_callback
            control.progress_callback = lambda message, result=None: original_progress(
                bounded(message), bounded(result)
            )
            start = time.monotonic()
            result = handler(
                inputs=request.inputs,
                options=request.options,
                context={"credentials": credentials},
                control=control,
            )
            control.check()
            if isinstance(result, ExecutionResult):
                result = result.model_copy(deep=True)
            elif isinstance(result, dict):
                result = ExecutionResult(
                    integration_id=request.integration_id,
                    capability=request.capability,
                    status="completed",
                    outputs=result,
                )
            else:
                raise ValueError("Handler retornou um resultado inválido.")
            result.duration_seconds = time.monotonic() - start
            result.finished_at = datetime.now(UTC).isoformat()
            return bounded(result.model_dump(mode="json"))

        def execute(control):
            gate = self._gates[request.integration_id]
            while not gate.acquire(timeout=0.05):
                control.check()
            try:
                control.check()
                return execute_handler(control)
            finally:
                gate.release()

        # The queue atomically owns idempotency, including its persisted hash.
        return self.job_manager.submit(
            kind=f"integration_{request.integration_id}_{request.capability}",
            payload={"canonical": request.canonical_key()},
            function=execute,
            key=request.idempotency_key,
            seconds=seconds,
        )

    def list_jobs(self, limit=100):
        return [
            job for job in self.job_manager.list() if job.get("type", "").startswith("integration_")
        ][:limit]

    def get_job(self, job_id):
        job = self.job_manager.get(job_id)
        if not job.get("type", "").startswith("integration_"):
            raise ValueError("Job de integração não encontrado.")
        return job

    def cancel(self, job_id):
        self.get_job(job_id)
        self.job_manager.cancel(job_id)
        return self.get_job(job_id)
