"""Assisted, auditable agent. Typed plans, no shell and no implicit external actions."""

import hashlib
import json
import re
import time
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from . import session as store
from .ai_analyzer import analyze_session
from .execution import BudgetExceeded, Cancelled, Control, file_lock
from .redaction import redact
from .report import build_report

TOOLS = {
    "verify_session": "Verificar integridade das evidências locais",
    "build_report": "Gerar relatório determinístico local",
    "analyze_session": "Analisar evidências; pode enviar dados ao provedor escolhido",
    "scan": "Executar ferramentas no alvo explicitamente autorizado",
    "osint": "Consultar conector registrado; pode acessar serviço externo",
}


class Step(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: Literal["verify_session", "build_report", "analyze_session", "scan", "osint"]
    session_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    target: str | None = Field(default=None, max_length=253)
    modules: str = "nmap"
    provider: Literal["export", "ollama", "nvidia"] = "export"
    model: str | None = Field(default=None, max_length=200)
    connector: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    query_type: Literal["domain", "ip", "url", "hash"] = "domain"
    timeout: int = Field(default=300, ge=1, le=3600)

    @model_validator(mode="after")
    def arguments(self):
        if self.tool in {"verify_session", "build_report", "analyze_session"} and not self.session_id:
            raise ValueError("A etapa requer ID de sessão explícito.")
        if self.tool in {"scan", "osint"} and not self.target:
            raise ValueError("A etapa requer alvo explícito.")
        if self.tool == "osint" and not self.connector:
            raise ValueError("Conector obrigatório.")
        return self

    @property
    def external(self):
        return self.tool in {"scan", "osint"} or (
            self.tool == "analyze_session" and self.provider != "export")


class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal[1] = 1
    objective: str = Field(min_length=1, max_length=1000)
    steps: list[Step] = Field(min_length=1, max_length=10)
    allowed_sessions: list[str] = Field(default_factory=list, max_length=10)
    allowed_targets: list[str] = Field(default_factory=list, max_length=10)
    max_seconds: int = Field(default=1800, ge=1, le=7200)
    token_budget: int = Field(default=250000, ge=1024, le=1000000)

    @model_validator(mode="after")
    def scope(self):
        for step in self.steps:
            if step.session_id and step.session_id not in self.allowed_sessions:
                raise ValueError("Sessão fora do escopo autorizado.")
            if step.target and step.target not in self.allowed_targets:
                raise ValueError("Alvo fora do escopo autorizado.")
        return self


def plan_directory(plan_id):
    if not re.fullmatch(r"[a-f0-9]{32}", plan_id):
        raise ValueError("ID de plano inválido.")
    root = (store.data_root() / "agent").resolve()
    path = (root / plan_id).resolve()
    if not path.is_relative_to(root):
        raise ValueError("Plano fora da pasta permitida.")
    return path


def digest(plan):
    return hashlib.sha256(plan.model_dump_json().encode()).hexdigest()


def save_plan(plan):
    plan = Plan.model_validate(plan)
    # No provider is called while creating a plan. Credentials are never plan arguments.
    for step in plan.steps:
        validate_step(step)
    plan_id = uuid4().hex
    directory = plan_directory(plan_id)
    directory.mkdir(parents=True)
    store.atomic_write(directory / "plan.json", plan.model_dump_json(indent=2))
    store.atomic_write(directory / "state.json", json.dumps({
        "id": plan_id, "digest": digest(plan), "status": "planned", "steps": [],
        "review_status": "pending_human_review", "token_units_reserved": 0,
    }, indent=2))
    return plan_id


def review_plan(session_id, provider="export", model=None):
    store.verified_findings(store.load_session(session_id))
    return save_plan(Plan(
        objective="Revisar evidências, gerar relatório e análise assistida",
        allowed_sessions=[session_id],
        steps=[Step(tool="verify_session", session_id=session_id),
               Step(tool="build_report", session_id=session_id),
               Step(tool="analyze_session", session_id=session_id, provider=provider, model=model)],
    ))


def load_plan(plan_id):
    return Plan.model_validate_json((plan_directory(plan_id) / "plan.json").read_text(encoding="utf-8"))


def validate_step(step):
    if step.session_id:
        store.verified_findings(store.load_session(step.session_id))
    if step.tool == "scan":
        from .modules import select_modules, target_for
        for module in select_modules(step.modules):
            module.command(target_for(module, step.target))
    elif step.tool == "osint":
        from sisifo.osint.contract import QueryType
        from sisifo.osint.registry import get_connector
        connector = get_connector(step.connector)
        qt = QueryType(step.query_type)
        if qt not in connector.meta.query_types or not connector.validate_query(step.target, qt):
            raise ValueError("Consulta OSINT inválida.")


def execute_step(step, control, token_budget):
    validate_step(step)
    if step.tool == "verify_session":
        return {"count": len(store.verified_findings(store.load_session(step.session_id)))}
    if step.tool == "build_report":
        report = build_report(step.session_id)
        return {"session_id": step.session_id, "count": len(report["findings"]),
                "path": str(store.session_dir(step.session_id) / "reports/report.md")}
    if step.tool == "analyze_session":
        return analyze_session(step.session_id, model=step.model, provider=step.provider,
                               token_budget=token_budget, control=control)
    if step.tool == "scan":
        from .orchestrator import scan
        result = scan(step.target, step.modules, "agent", step.timeout, control=control)
        return {"session_id": result.id, "status": result.status}
    from sisifo.osint.contract import QueryType
    from sisifo.osint.executor import load_osint_config, run_query
    from sisifo.osint.registry import get_connector
    return {"results": [r.model_dump() for r in run_query(get_connector(step.connector),
            step.target, QueryType(step.query_type), load_osint_config(step.connector))]}


def run_plan(plan_id, *, approved_digest=None, control=None):
    directory = plan_directory(plan_id)
    with file_lock(directory / ".run.lock"):
        plan = load_plan(plan_id)
        state = json.loads((directory / "state.json").read_text(encoding="utf-8"))
        fingerprint = digest(plan)
        if state["digest"] != fingerprint:
            raise ValueError("Plano alterado: crie e revise um novo plano.")
        if state["status"] == "completed":
            return state
        if any(s.get("status") == "running" for s in state["steps"]):
            state["status"] = "interrupted"
            store.atomic_write(directory / "state.json", json.dumps(state, indent=2))
            raise ValueError("Etapa interrompida: revise resultados e crie novo plano; ação não repetida.")
        if any(step.external for step in plan.steps) and approved_digest != fingerprint:
            raise ValueError("Ações externas exigem aprovação do hash exato do plano.")
        control = control or Control(plan.max_seconds)
        control.deadline = min(control.deadline, time.monotonic() + plan.max_seconds)
        state.update(status="running", approved_digest=approved_digest)

        def save():
            store.atomic_write(directory / "state.json", json.dumps(state, ensure_ascii=False, indent=2))

        try:
            for index, step in enumerate(plan.steps):
                if index < len(state["steps"]):
                    if state["steps"][index]["status"] == "completed":
                        continue
                    raise ValueError("Etapa anterior não concluída: revise e crie um novo plano.")
                control.check()
                control.progress(f"Agente: etapa {index + 1}/{len(plan.steps)} — {step.tool}")
                entry = {"tool": step.tool, "status": "running"}
                state["steps"].append(entry)
                save()  # persist BEFORE any external side effect
                remaining = plan.token_budget - state["token_units_reserved"]
                if remaining < 1024:
                    raise BudgetExceeded("Orçamento esgotado.")
                result = execute_step(step, control, remaining)
                entry["result"] = redact(result)[0]
                entry["status"] = result.get("status", "completed")
                state["token_units_reserved"] += result.get("budget", {}).get("reserved_units", 0)
                save()
                if entry["status"] != "completed":
                    state["status"] = entry["status"]
                    break
            else:
                state["status"] = "completed"
        except (Cancelled, KeyboardInterrupt):
            state["status"] = "cancelled"
        except BudgetExceeded:
            state["status"] = "partial"
        except Exception:
            state["status"] = "failed"
            state["error"] = "Etapa falhou; revise o diário antes de criar novo plano."
        finally:
            save()
        return state
