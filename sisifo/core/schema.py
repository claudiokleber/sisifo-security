from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

Identifier = Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]


def utcnow():
    return datetime.now(UTC)


class Finding(BaseModel):
    id: Identifier = Field(default_factory=lambda: uuid4().hex)
    tool: str
    target: str
    timestamp: datetime = Field(default_factory=utcnow)
    observed_at: datetime | None = None
    observation_source: str = "unknown"
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    finding: str
    category: Literal["observation", "potential_issue"] = "observation"
    evidence: str
    fingerprint: str
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | None = None
    service: str | None = None
    raw: str | None = None
    identity: str | None = None
    details: dict = Field(default_factory=dict)


class RunResult(BaseModel):
    id: Identifier = Field(default_factory=lambda: uuid4().hex)
    tool: str
    image: str
    image_id: str | None = None
    command: list[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    status: Literal["running", "completed", "failed", "timeout", "cancelled", "interrupted"] = (
        "running"
    )
    container_id: str | None = None
    coverage: dict | None = None
    imported_at: datetime | None = None
    source_started_at: datetime | None = None
    source_finished_at: datetime | None = None
    exit_code: int | None = None
    error: str | None = None
    stdout: str = ""
    stderr: str = ""
    artifact: str = ""
    artifact_sha256: str | None = None
    findings_count: int = Field(default=0, ge=0)


class Session(BaseModel):
    schema_version: Literal[2] = 2
    id: Identifier = Field(default_factory=lambda: uuid4().hex)
    project: str = "default"
    target: str
    scope: list[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    tools_run: list[str] = Field(default_factory=list)
    runs: list[RunResult] = Field(default_factory=list)
    status: Literal["running", "completed", "partial", "failed", "cancelled", "interrupted"] = (
        "running"
    )
    findings_sha256: str | None = None


class Recommendation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evidence_ids: list[Identifier] = Field(min_length=1)
    assessment: str = Field(min_length=1, max_length=8000)
    measures: list[str] = Field(min_length=1, max_length=20)
    verification: str = Field(min_length=1, max_length=8000)
    confidence: Literal["low", "medium", "high"]
    claim_type: Literal["observation", "hypothesis"] = "hypothesis"
    observation: str = Field(default="", max_length=8000)
    missing_evidence: list[str] = Field(default_factory=list, max_length=20)
    evidence_quotes: dict[str, str] = Field(default_factory=dict)


class AIResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(min_length=1, max_length=12000, description="Resumo em português brasileiro (pt-BR).")
    reviewed_evidence_ids: list[Identifier]
    recommendations: list[Recommendation] = Field(max_length=100)
    limitations: list[str] = Field(max_length=50)
