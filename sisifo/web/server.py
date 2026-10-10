import os
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal, Optional

from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

from sisifo.core import session as store
from sisifo.core.ai_analyzer import analyze_session, prepare_batches
from sisifo.core.config import (
    load_service_config,
    save_service_config,
    set_web_password,
    verify_web_password,
    web_password_configured,
)
from sisifo.core.integration import ExecutionRequest, IntegrationExecutionService
from sisifo.core.integration_registry import create_catalog
from sisifo.core.jobs import JobManager
from sisifo.core.modules import registry
from sisifo.core.report import build_report, compare_sessions
from sisifo.modules.network import NetworkService
from sisifo.modules.network.models import (
    CaptureConfig,
    CaptureFilter,
    CaptureLimits,
    DisplayFilter,
)
from sisifo.osint import get_connector, list_connectors
from sisifo.osint.contract import QueryType
from sisifo.osint.executor import OsintExecutionError, run_query
from sisifo.osint.interaction import Proposals, ai_preview, interpret
from sisifo.web.limits import RequestLimits
from sisifo.web.security import (
    CSRF_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    HostValidationMiddleware,
    require_session,
    session_manager,
    validate_path,
    verify_csrf,
)

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.osint_proposals = Proposals()
    app.state.jobs = JobManager(store.data_root(), workers=int(os.getenv("SISIFO_MAX_JOBS", "2")))
    try:
        catalog = await run_in_threadpool(create_catalog)
        app.state.integrations = IntegrationExecutionService(catalog, app.state.jobs, store.data_root() / "evidence")
        yield
    finally:
        await run_in_threadpool(app.state.jobs.close)


app = FastAPI(title="Sísifo Web", version="0.3.0", lifespan=lifespan)

app.add_middleware(RequestLimits)


@app.exception_handler(RequestValidationError)
async def validation_error(request, error):
    return JSONResponse({"detail": "Entrada inválida; confira os campos e limites."}, status_code=422)


app.add_middleware(HostValidationMiddleware, allowed_hosts=["127.0.0.1", "localhost"])
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


class LoginRequest(BaseModel):
    password: str = Field(..., min_length=1)


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1)
    modules: str = Field(default="nmap")
    project: str = Field(default="default")
    timeout: int = Field(default=600, ge=60, le=7200)


class AnalyzeRequest(BaseModel):
    session_id: str = Field(..., min_length=1)
    model: Optional[str] = None
    endpoint: Optional[str] = None
    provider: Optional[Literal["nvidia", "ollama", "export", "api"]] = None
    max_batches: int = Field(default=50, ge=1, le=100)
    max_seconds: int = Field(default=1800, ge=1, le=7200)
    token_budget: int = Field(default=250000, ge=1024, le=1000000)
    resume_id: Optional[str] = Field(default=None, pattern=r"^[a-f0-9]{32}$")


class CompareRequest(BaseModel):
    before: str = Field(..., min_length=1)
    after: str = Field(..., min_length=1)


class ImportNmapRequest(BaseModel):
    path: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    project: str = Field(default="default")


class OsintQueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    connector_id: str = Field(..., min_length=1)
    query: str = Field(..., min_length=1, max_length=2048)
    query_type: str = Field(..., min_length=1)


def manager(request: Request):
    return request.app.state.jobs


def submit(request, kind, payload, fn, seconds=3600):
    try:
        key = request.headers.get("Idempotency-Key")
        if key and len(key) > 128:
            raise ValueError("Chave de idempotência muito longa.")
        return {"job_id": manager(request).submit(kind, payload, fn, key=key, seconds=seconds)}
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from None


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.3.0", "title": "Sísifo Web"}


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id and session_manager.get_session(session_id):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse(name="login.html", context={"request": request}, request=request)


@app.post("/login")
async def login(response: Response, password: str = Form(...)):
    if not web_password_configured():
        raise HTTPException(status_code=500, detail="Senha web não configurada. Execute 'sisifo setup-web'.")
    if not await run_in_threadpool(verify_web_password, password):
        raise HTTPException(status_code=401, detail="Senha incorreta")
    session_id = session_manager.create_session()
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_id,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=3600,
        path="/",
    )
    csrf_token = session_manager.get_csrf_token(session_id)
    response.set_cookie(
        CSRF_COOKIE_NAME,
        csrf_token,
        httponly=False,
        secure=False,
        samesite="strict",
        max_age=3600,
        path="/",
    )
    return response


@app.post("/logout")
async def logout(response: Response, session_id: str = Depends(require_session), _: None = Depends(verify_csrf)):
    session_manager.delete_session(session_id)
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    response.delete_cookie(CSRF_COOKIE_NAME, path="/")
    return response


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id or not session_manager.get_session(session_id):
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(name="index.html", context={"request": request, "csrf_token": session_manager.get_csrf_token(session_id)}, request=request)


@app.get("/api/sessions")
async def api_sessions(session_id: str = Depends(require_session)):
    root = store.data_root() / "sessions"
    sessions_list = []
    if root.exists():
        for d in sorted(root.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
            if d.is_dir():
                try:
                    s = store.load_session(d.name)
                    sessions_list.append(
                        {
                            "id": s.id,
                            "project": s.project,
                            "target": s.target,
                            "status": s.status,
                            "created_at": s.started_at,
                            "tools": [r.tool for r in s.runs],
                            "has_error": any(r.error for r in s.runs),
                        }
                    )
                except ValueError:
                    pass
    return {"sessions": sessions_list}


@app.get("/api/sessions/{session_id}")
async def api_session_detail(session_id: str, _: str = Depends(require_session)):
    try:
        s = store.load_session(session_id)
        return {
            "id": s.id,
            "project": s.project,
            "target": s.target,
            "status": s.status,
            "created_at": s.started_at,
            "runs": [
                {
                    "tool": r.tool,
                    "status": r.status,
                    "started_at": r.started_at,
                    "finished_at": r.finished_at,
                    "error": r.error,
                    "command": r.command,
                    "image_id": r.image_id,
                }
                for r in s.runs
            ],
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/reports/{session_id}")
async def api_report(session_id: str, format: str = Query("md"), _: str = Depends(require_session)):
    try:
        build_report(session_id)
        report_dir = store.session_dir(session_id) / "reports"
        if format == "json":
            path = report_dir / "report.json"
        else:
            path = report_dir / "report.md"
        if not path.exists():
            raise HTTPException(status_code=404, detail="Relatório não encontrado")
        return FileResponse(path, media_type="application/json" if format == "json" else "text/markdown", filename=path.name)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/sessions/verify/{session_id}")
async def api_verify(session_id: str, _: str = Depends(require_session), __: None = Depends(verify_csrf)):
    try:
        findings = store.verified_findings(store.load_session(session_id))
        return {"verified": True, "count": len(findings)}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/sessions/compare")
async def api_compare(request: CompareRequest, _: str = Depends(require_session), __: None = Depends(verify_csrf)):
    try:
        result = compare_sessions(request.before, request.after)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/scan")
async def api_scan(body: ScanRequest, request: Request, _: str = Depends(require_session), __: None = Depends(verify_csrf)):
    from sisifo.core.modules import select_modules, target_for
    from sisifo.core.orchestrator import scan
    try:
        for module in select_modules(body.modules):
            module.command(target_for(module, body.target))
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from None
    def execute(control):
        result = scan(body.target, body.modules, body.project, body.timeout, control=control)
        build_report(result.id)
        return {"session_id": result.id, "status": result.status}
    return submit(request, "scan", body.model_dump(), execute, seconds=body.timeout * len(body.modules.split(',')) + 120)


@app.post("/api/analyze/preview")
async def api_analyze_preview(body: AnalyzeRequest, _: str = Depends(require_session), __: None = Depends(verify_csrf)):
    try:
        return await run_in_threadpool(prepare_batches, body.session_id)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from None


@app.post("/api/analyze")
async def api_analyze(body: AnalyzeRequest, request: Request, _: str = Depends(require_session), __: None = Depends(verify_csrf)):
    try:
        store.load_session(body.session_id)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from None
    # Browser may only select a server-configured endpoint, not an arbitrary network destination.
    if body.endpoint and body.endpoint != os.getenv("SISIFO_OLLAMA_URL", "http://localhost:11434"):
        raise HTTPException(status_code=400, detail="Configure o endpoint no ambiente do servidor.")
    return submit(request, "analyze", body.model_dump(),
                  lambda control: analyze_session(**body.model_dump(), control=control), seconds=body.max_seconds)


@app.post("/api/import-nmap")
async def api_import_nmap(file: UploadFile = File(...), target: str = Form(...), project: str = Form("default"),
                          _: str = Depends(require_session), __: None = Depends(verify_csrf)):
    from sisifo.core.importer import import_nmap
    try:
        with tempfile.TemporaryDirectory(prefix="sisifo-upload-") as temp:
            path = Path(temp) / "input.xml"
            size = 0
            with path.open("wb") as output:
                while chunk := await file.read(65536):
                    size += len(chunk)
                    if size > 20 * 1024 * 1024:
                        raise HTTPException(status_code=413, detail="XML excede 20 MiB.")
                    output.write(chunk)
            session = await run_in_threadpool(import_nmap, path, target, project)
            await run_in_threadpool(build_report, session.id)
            return {"session_id": session.id, "status": session.status}
    except ValueError:
        raise HTTPException(status_code=400, detail="XML ou parâmetros inválidos.") from None
    finally:
        await file.close()


@app.get("/api/osint/connectors")
async def api_osint_connectors(_: str = Depends(require_session)):
    result = list_connectors()
    for cid, meta in result.items():
        meta["configured"] = bool(get_connector(cid).validate_config(load_service_config(f"osint_{cid}")))
    return {"connectors": result}


class OsintApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proposal_id: str = Field(min_length=1, max_length=100)
    confirmed: Literal[True]


class OsintSelection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    indices: list[int] = Field(min_length=1, max_length=20)


def validate_osint(body):
    connector = get_connector(body.connector_id)
    qt = QueryType(body.query_type)
    cfg = load_service_config(f"osint_{body.connector_id}")
    if not connector.validate_config(cfg) or qt not in connector.meta.query_types or not connector.validate_query(body.query, qt):
        raise ValueError("Conector, configuração ou consulta inválidos.")
    return connector, qt, cfg


@app.post("/api/osint/proposals")
async def osint_proposal(body: OsintQueryRequest, request: Request, owner: str = Depends(require_session), _: None = Depends(verify_csrf)):
    try:
        connector, _, _ = validate_osint(body)
        token = request.app.state.osint_proposals.create(owner, "query", body.model_dump())
        return {"proposal_id": token, **body.model_dump(), "destinations": connector.meta.allowed_destinations,
                "cost": "Consulte o plano do serviço; custo não estimado.", "expires_in": 300}
    except (KeyError, ValueError):
        raise HTTPException(400, "Conector, configuração ou consulta inválidos.") from None


@app.post("/api/osint/query")
async def api_osint_query(body: OsintApproval, request: Request, owner: str = Depends(require_session), _: None = Depends(verify_csrf)):
    def enqueue(payload):
        connector, qt, cfg = validate_osint(OsintQueryRequest(**payload))
        def execute(control):
            try:
                result = run_query(connector, payload['query'], qt, cfg, control)
                return {"results": [r.model_dump(mode="json") for r in result],
                        "outcome": "RESULTS" if result else "NO_RESULTS",
                        "limitations": ["Ausência de resultados não comprova ausência de exposição."]}
            except OsintExecutionError as error:
                return {"status": "failed", "error_code": error.code,
                        "retry_after": error.details.get("retry_after"),
                        "message": "Consulta não concluída. Confira configuração, limites e disponibilidade do serviço."}
        return submit(request, "osint", payload, execute, seconds=60)
    try:
        return request.app.state.osint_proposals.execute(body.proposal_id, owner, "query", enqueue)
    except (KeyError, ValueError) as error:
        raise HTTPException(400, str(error)) from None


@app.post("/api/osint/ai/preview")
async def osint_ai_preview(body: OsintSelection, request: Request, owner: str = Depends(require_session), _: None = Depends(verify_csrf)):
    try:
        job = manager(request).get(body.job_id)
        if job['type'] != 'osint' or job['status'] != 'completed':
            raise ValueError('Selecione uma consulta OSINT concluída.')
        preview = ai_preview(job['result'].get('results', []), body.indices)
        from sisifo.core.ai_connection import public_status
        status = public_status()
        if not status.get('configured'):
            raise ValueError('A IA ainda não está configurada. Abra Configurações → Conexão com a IA. Seus resultados continuam disponíveis.')
        token = request.app.state.osint_proposals.create(owner, 'ai', {'preview': preview, 'connection': status})
        return {'proposal_id': token, 'preview': preview, 'destination': status.get('endpoint', 'IA configurada')}
    except ValueError as error:
        raise HTTPException(400, str(error)) from None


@app.post("/api/osint/ai/interpret")
async def osint_ai_interpret(body: OsintApproval, request: Request, owner: str = Depends(require_session), _: None = Depends(verify_csrf)):
    def enqueue(payload):
        from sisifo.core.ai_connection import public_status
        if public_status() != payload['connection']:
            raise ValueError('Conexão de IA alterada; gere uma nova prévia.')
        def execute(control):
            control.check()
            if public_status() != payload['connection']:
                raise ValueError('Conexão de IA alterada.')
            answer = interpret(payload['preview'], control=control)
            control.check()
            return answer
        return submit(request, 'osint-ai', payload, execute, seconds=120)
    try:
        return request.app.state.osint_proposals.execute(body.proposal_id, owner, 'ai', enqueue)
    except ValueError as error:
        raise HTTPException(400, str(error)) from None


@app.get("/api/jobs")
async def api_jobs(request: Request, _: str = Depends(require_session)):
    return {"jobs": manager(request).list()}


@app.get("/api/jobs/{job_id}")
async def api_job_status(job_id: str, request: Request, _: str = Depends(require_session)):
    try:
        return manager(request).get(job_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Job não encontrado") from None


@app.post("/api/jobs/{job_id}/cancel")
async def api_cancel_job(job_id: str, request: Request, _: str = Depends(require_session), __: None = Depends(verify_csrf)):
    try:
        manager(request).cancel(job_id)
        return manager(request).get(job_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Job não encontrado") from None


class AIConnectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint: str = Field(min_length=1, max_length=2048)
    api_key: Optional[str] = Field(default=None, max_length=4096)


class AIConfigRequest(AIConnectionRequest):
    model: str = Field(min_length=1, max_length=256)


@app.post("/api/ai/models")
async def ai_models(body: AIConnectionRequest, _: str = Depends(require_session), __: None = Depends(verify_csrf)):
    from sisifo.core.ai_connection import discover_models
    try:
        models = await run_in_threadpool(discover_models, body.endpoint, body.api_key)
        return {"models": models, "note": "Catálogo obtido; teste o modelo para verificar acesso de inferência."}
    except ValueError as error:
        raise HTTPException(400, str(error)) from None


class OfflineAIRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["export"]


@app.post("/api/config/ai")
async def api_save_ai(body: AIConfigRequest | OfflineAIRequest, _: str = Depends(require_session), __: None = Depends(verify_csrf)):
    from sisifo.core.ai_connection import connect
    if isinstance(body, OfflineAIRequest):
        from sisifo.core.config import save_config
        save_config("export", "")
        return {"configured": False}
    try:
        return await run_in_threadpool(connect, body.endpoint, body.model, body.api_key)
    except ValueError as error:
        raise HTTPException(400, str(error)) from None


class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=8000)


class ChatRequest(BaseModel):
    messages: list[ChatMessage] = Field(min_length=1, max_length=40)
    session_id: Optional[str] = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    include_evidence: bool = False


@app.post("/api/ai/chat")
async def ai_chat(body: ChatRequest, _: str = Depends(require_session), __: None = Depends(verify_csrf)):
    from sisifo.core.ai_connection import chat
    try:
        return await run_in_threadpool(chat, [m.model_dump() for m in body.messages],
                                      body.session_id, body.include_evidence)
    except ValueError as error:
        raise HTTPException(400, str(error)) from None


class PasswordRequest(BaseModel):
    password: str = Field(min_length=8, max_length=1024)


class NetworkImportRequest(BaseModel):
    display_filter: Optional[str] = Field(default=None, max_length=500)


class NetworkPacketsRequest(BaseModel):
    display_filter: Optional[str] = Field(default=None, max_length=500)
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=1000)


class NetworkStatsRequest(BaseModel):
    display_filter: Optional[str] = Field(default=None, max_length=500)


class NetworkReportRequest(BaseModel):
    display_filter: Optional[str] = Field(default=None, max_length=500)


class NetworkCaptureRequest(BaseModel):
    interface_id: str = Field(..., min_length=1)
    capture_filter: str = Field(default="", max_length=500)
    max_duration_seconds: int = Field(default=60, ge=1, le=86400)
    max_file_size_mib: int = Field(default=100, ge=1, le=10240)
    max_packets: int = Field(default=100000, ge=1, le=10000000)
    ring_buffer: bool = Field(default=False)
    ring_buffer_files: int = Field(default=5, ge=2, le=50)
    output_directory: Optional[str] = Field(default=None, max_length=200)


@app.get("/api/network/diagnostics")
async def api_network_diagnostics(_: str = Depends(require_session)):
    service = NetworkService()
    diag = service.discover_tools()
    return {
        "platform": diag.platform,
        "is_docker": diag.is_docker,
        "dumpcap_path": diag.dumpcap_path,
        "tshark_path": diag.tshark_path,
        "wireshark_path": diag.wireshark_path,
        "npcap_version": diag.npcap_version,
        "libpcap_version": diag.libpcap_version,
        "dumpcap_version": diag.dumpcap_version,
        "tshark_version": diag.tshark_version,
        "interfaces": [
            {
                "id": i.id,
                "name": i.name,
                "description": i.description,
                "loopback": i.loopback,
                "up": i.up,
                "addresses": i.addresses,
            }
            for i in diag.interfaces
        ],
        "capture_permissions": diag.capture_permissions,
        "permission_details": diag.permission_details,
        "storage_path": diag.storage_path,
        "storage_available_mib": diag.storage_available_mib,
        "max_concurrent_captures": diag.max_concurrent_captures,
        "active_captures": diag.active_captures,
        "recent_captures": [
            {
                "id": c.id,
                "source": c.source.value,
                "status": c.status.value,
                "interface_id": c.interface_id,
                "interface_name": c.interface_name,
                "file_path": c.file_path,
                "file_size": c.file_size,
                "packet_count": c.packet_count,
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in diag.recent_captures
        ],
    }


@app.get("/api/network/captures")
async def api_network_list_captures(limit: int = Query(50, ge=1, le=200), _: str = Depends(require_session)):
    service = NetworkService()
    captures = service.list_captures(limit=limit)
    return {
        "captures": [
            {
                "id": c.id,
                "source": c.source.value,
                "status": c.status.value,
                "interface_id": c.interface_id,
                "interface_name": c.interface_name,
                "file_path": c.file_path,
                "file_size": c.file_size,
                "packet_count": c.packet_count,
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in captures
        ]
    }


@app.post("/api/network/import")
async def api_network_import(
    file: UploadFile = File(...),
    display_filter: Optional[str] = Form(None),
    _: str = Depends(require_session),
    __: None = Depends(verify_csrf),
):
    service = NetworkService()
    if not file.filename or not (file.filename.endswith(".pcap") or file.filename.endswith(".pcapng")):
        raise HTTPException(status_code=400, detail="Arquivo deve ser .pcap ou .pcapng")

    import tempfile
    with tempfile.TemporaryDirectory(prefix="sisifo-upload-") as temp:
        temp_path = Path(temp) / file.filename
        size = 0
        with temp_path.open("wb") as output:
            while chunk := await file.read(65536):
                size += len(chunk)
                if size > 500 * 1024 * 1024:
                    raise HTTPException(status_code=413, detail="Arquivo excede 500 MiB")
                output.write(chunk)

        try:
            result = await run_in_threadpool(service.import_pcap, temp_path)
            return {
                "id": result.id,
                "source": result.source.value,
                "status": result.status.value,
                "file_path": result.file_path,
                "file_size": result.file_size,
                "file_sha256": result.file_sha256,
                "packet_count": result.packet_count,
                "dropped_packets": result.dropped_packets,
                "dropped_by_interface": result.dropped_by_interface,
                "tshark_version": result.tshark_version,
                "dumpcap_version": result.dumpcap_version,
            }
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from None
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Erro inesperado: {e}") from None
    await file.close()


@app.get("/api/network/captures/{capture_id}")
async def api_network_get_capture(capture_id: str, _: str = Depends(require_session)):
    service = NetworkService()
    try:
        result = service.get_capture(capture_id)
        return {
            "id": result.id,
            "source": result.source.value,
            "status": result.status.value,
            "interface_id": result.interface_id,
            "interface_name": result.interface_name,
            "capture_filter": result.capture_filter,
            "display_filter": result.display_filter,
            "file_path": result.file_path,
            "file_size": result.file_size,
            "file_sha256": result.file_sha256,
            "packet_count": result.packet_count,
            "dropped_packets": result.dropped_packets,
            "dropped_by_interface": result.dropped_by_interface,
            "tshark_version": result.tshark_version,
            "dumpcap_version": result.dumpcap_version,
            "environment": result.environment,
            "is_docker": result.is_docker,
            "created_at": result.created_at.isoformat() if result.created_at else None,
            "started_at": result.started_at.isoformat() if result.started_at else None,
            "finished_at": result.finished_at.isoformat() if result.finished_at else None,
            "error": result.error,
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from None


@app.post("/api/network/captures/{capture_id}/packets")
async def api_network_packets(
    capture_id: str,
    body: NetworkPacketsRequest,
    _: str = Depends(require_session),
    __: None = Depends(verify_csrf),
):
    service = NetworkService()
    try:
        df = DisplayFilter(expression=body.display_filter) if body.display_filter else None
        packets = await run_in_threadpool(
            service.list_packets, capture_id, display_filter=df, offset=body.offset, limit=body.limit
        )
        return {
            "packets": [
                {
                    "number": p.number,
                    "time": p.time,
                    "time_iso": p.time_iso,
                    "source": p.source,
                    "destination": p.destination,
                    "protocol": p.protocol,
                    "length": p.length,
                    "info": p.info,
                }
                for p in packets
            ]
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None


@app.get("/api/network/captures/{capture_id}/packets/{packet_number}")
async def api_network_packet_detail(capture_id: str, packet_number: int, _: str = Depends(require_session)):
    service = NetworkService()
    try:
        detail = await run_in_threadpool(service.get_packet_detail, capture_id, packet_number)
        return {
            "number": detail.number,
            "time": detail.time,
            "time_iso": detail.time_iso,
            "source": detail.source,
            "destination": detail.destination,
            "protocol": detail.protocol,
            "length": detail.length,
            "info": detail.info,
            "layers": detail.layers,
            "hex_dump": detail.hex_dump,
            "original_length": detail.original_length,
            "captured_length": detail.captured_length,
            "extracted_length": detail.extracted_length,
            "hex_dump_error": detail.hex_dump_error,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None


@app.post("/api/network/captures/{capture_id}/stats")
async def api_network_stats(
    capture_id: str,
    body: NetworkStatsRequest,
    _: str = Depends(require_session),
    __: None = Depends(verify_csrf),
):
    service = NetworkService()
    try:
        df = DisplayFilter(expression=body.display_filter) if body.display_filter else None

        proto_stats = await run_in_threadpool(service.get_protocol_stats, capture_id, df)
        endpoints = await run_in_threadpool(service.get_endpoints, capture_id, df)
        conversations = await run_in_threadpool(service.get_conversations, capture_id, df)
        dns = await run_in_threadpool(service.get_dns_summary, capture_id, df)
        tcp = await run_in_threadpool(service.get_tcp_summary, capture_id, df)

        return {
            "protocol_stats": {
                "total_packets": proto_stats.total_packets,
                "total_bytes": proto_stats.total_bytes,
                "by_protocol": [
                    {
                        "protocol": item.protocol,
                        "packets": item.packets,
                        "bytes": item.bytes,
                        "percentage_packets": item.percentage_packets,
                        "percentage_bytes": item.percentage_bytes,
                    }
                    for item in proto_stats.by_protocol
                ],
            },
            "endpoints": [
                {
                    "address": ep.address,
                    "type": ep.type,
                    "packets_rx": ep.packets_rx,
                    "packets_tx": ep.packets_tx,
                    "bytes_rx": ep.bytes_rx,
                    "bytes_tx": ep.bytes_tx,
                }
                for ep in endpoints[:50]
            ],
            "conversations": [
                {
                    "endpoint_a": conv.endpoint_a,
                    "endpoint_b": conv.endpoint_b,
                    "protocol": conv.protocol,
                    "packets": conv.packets,
                    "bytes": conv.bytes,
                    "packets_a_to_b": conv.packets_a_to_b,
                    "bytes_a_to_b": conv.bytes_a_to_b,
                    "packets_b_to_a": conv.packets_b_to_a,
                    "bytes_b_to_a": conv.bytes_b_to_a,
                    "start_time": conv.start_time,
                    "end_time": conv.end_time,
                    "duration": conv.duration,
                }
                for conv in conversations[:50]
            ],
            "dns": dns,
            "tcp": tcp,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None


@app.post("/api/network/captures/{capture_id}/report")
async def api_network_report(
    capture_id: str,
    body: NetworkReportRequest,
    _: str = Depends(require_session),
    __: None = Depends(verify_csrf),
):
    service = NetworkService()
    try:
        df = DisplayFilter(expression=body.display_filter) if body.display_filter else None
        report = await run_in_threadpool(service.generate_report, capture_id, df)
        return {
            "capture_id": report.capture_id,
            "summary": {
                "id": report.summary.id,
                "source": report.summary.source.value,
                "status": report.summary.status.value,
                "packet_count": report.summary.packet_count,
                "file_size": report.summary.file_size,
            },
            "protocol_stats": {
                "total_packets": report.protocol_stats.total_packets,
                "total_bytes": report.protocol_stats.total_bytes,
                "by_protocol": [
                    {
                        "protocol": item.protocol,
                        "packets": item.packets,
                        "bytes": item.bytes,
                        "percentage_packets": item.percentage_packets,
                        "percentage_bytes": item.percentage_bytes,
                    }
                    for item in report.protocol_stats.by_protocol
                ],
            },
            "endpoints": [
                {
                    "address": ep.address,
                    "type": ep.type,
                    "packets_rx": ep.packets_rx,
                    "packets_tx": ep.packets_tx,
                    "bytes_rx": ep.bytes_rx,
                    "bytes_tx": ep.bytes_tx,
                }
                for ep in report.endpoints
            ],
            "conversations": [
                {
                    "endpoint_a": conv.endpoint_a,
                    "endpoint_b": conv.endpoint_b,
                    "protocol": conv.protocol,
                    "packets": conv.packets,
                    "bytes": conv.bytes,
                    "duration": conv.duration,
                }
                for conv in report.conversations
            ],
            "anomalies": report.anomalies,
            "limitations": report.limitations,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None


@app.post("/api/network/captures/{capture_id}/open-wireshark")
async def api_network_open_wireshark(capture_id: str, _: str = Depends(require_session), __: None = Depends(verify_csrf)):
    service = NetworkService()
    try:
        service.open_in_wireshark(capture_id)
        return {"success": True, "message": "Wireshark iniciado"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None


def _run_network_capture(payload: dict, control):
    service = NetworkService()
    config = CaptureConfig(
        interface_id=payload["interface_id"],
        capture_filter=CaptureFilter(expression=payload.get("capture_filter", "")),
        limits=CaptureLimits(
            max_duration_seconds=payload["max_duration_seconds"],
            max_file_size_mib=payload["max_file_size_mib"],
            max_packets=payload["max_packets"],
        ),
        ring_buffer=payload.get("ring_buffer", False),
        ring_buffer_files=payload.get("ring_buffer_files", 5),
        output_directory=payload.get("output_directory"),
    )
    result = service.start_capture(config, control=control)
    return {
        "id": result.id,
        "status": result.status.value,
        "file_path": result.file_path,
        "file_size": result.file_size,
        "file_sha256": result.file_sha256,
        "packet_count": result.packet_count,
        "dropped_packets": result.dropped_packets,
        "error": result.error,
    }


@app.post("/api/network/capture")
async def api_network_capture(
    body: NetworkCaptureRequest,
    request: Request,
    _: str = Depends(require_session),
    __: None = Depends(verify_csrf),
):
    service = NetworkService()
    diag = service.discover_tools()
    if diag.is_docker:
        raise HTTPException(status_code=400, detail="Captura nativa não disponível no Docker")
    if not diag.capture_permissions:
        raise HTTPException(status_code=403, detail=f"Sem permissão: {diag.permission_details}")

    iface_ids = [i.id for i in diag.interfaces]
    if body.interface_id not in iface_ids:
        raise HTTPException(status_code=400, detail=f"Interface '{body.interface_id}' não encontrada")

    seconds = body.max_duration_seconds + 60
    return submit(request, "network_capture", body.model_dump(), _run_network_capture, seconds=seconds)


@app.post("/api/network/captures/{capture_id}/stop")
async def api_network_stop(capture_id: str, _: str = Depends(require_session), __: None = Depends(verify_csrf)):
    service = NetworkService()
    try:
        result = await run_in_threadpool(service.stop_capture, capture_id)
        return {
            "id": result.id,
            "status": result.status.value,
            "error": result.error,
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from None


@app.post("/api/config/web")
async def api_save_password(body: PasswordRequest, _: str = Depends(require_session), __: None = Depends(verify_csrf)):
    await run_in_threadpool(set_web_password, body.password)
    session_manager._sessions.clear()
    return {"saved": True, "login_required": True}


@app.post("/api/config/osint/{connector_id}")
async def api_save_osint(connector_id: str, body: dict[str, str], _: str = Depends(require_session), __: None = Depends(verify_csrf)):
    try:
        connector = get_connector(connector_id)
        allowed = {f.name for f in connector.meta.config.fields}
        if not set(body) <= allowed or any(len(v) > 4096 for v in body.values()):
            raise ValueError()
        cfg = load_service_config(f"osint_{connector_id}")
        cfg.update({k: v for k, v in body.items() if v})
        if not connector.validate_config(cfg):
            raise ValueError()
        await run_in_threadpool(save_service_config, f"osint_{connector_id}", cfg)
        return {"configured": True}
    except (KeyError, ValueError):
        raise HTTPException(status_code=400, detail="Configuração do conector inválida.") from None


@app.get("/api/modules")
async def api_modules(_: str = Depends(require_session)):
    return {
        "modules": [
            {
                "name": name,
                "image": m.image,
                "experimental": m.experimental,
            }
            for name, m in registry().items()
        ]
    }


@app.get("/api/config/status")
async def api_config_status(_: str = Depends(require_session)):
    osint_configs = {}
    for connector_id in list_connectors().keys():
        osint_configs[connector_id] = bool(get_connector(connector_id).validate_config(load_service_config(f"osint_{connector_id}")))
    from sisifo.core.ai_connection import public_status
    return {
        "ai": public_status(),
        "osint": osint_configs,
        "web_password_configured": web_password_configured(),
    }


@app.post("/api/sessions/{session_id}/export-vault")
async def api_export_vault(session_id: str, vault: str = Query(...), _: str = Depends(require_session), __: None = Depends(verify_csrf)):
    from sisifo.core.vault import export_vault as export

    allowed = os.getenv("SISIFO_VAULT_DIR")
    if not allowed or Path(vault).resolve() != Path(allowed).resolve():
        raise HTTPException(status_code=403, detail="Configure SISIFO_VAULT_DIR no servidor para autorizar exportação.")
    try:
        path = export(session_id, Path(allowed))
        return {"path": str(path)}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/download/{session_id}/{file_type}")
async def api_download(session_id: str, file_type: str, _: str = Depends(require_session)):
    session_dir = store.session_dir(session_id)
    if file_type == "report-md":
        path = validate_path(session_dir, "reports/report.md")
    elif file_type == "report-json":
        path = validate_path(session_dir, "reports/report.json")
    elif file_type == "nmap-xml":
        path = validate_path(session_dir, "raw_output/nmap.xml")
    elif file_type == "nikto-json":
        path = validate_path(session_dir, "raw_output/nikto.json")
    elif file_type == "metasploit-json":
        path = validate_path(session_dir, "raw_output/metasploit.json")
    else:
        raise HTTPException(status_code=400, detail="Tipo de arquivo inválido")
    return FileResponse(path, filename=path.name)


@app.get("/api/integration/catalog")
async def integration_catalog(request: Request, status: Optional[str] = None,
                              category: Optional[str] = None, _: str = Depends(require_session)):
    from sisifo.core.integration import IntegrationCategory, IntegrationStatus
    try:
        items = request.app.state.integrations.catalog.list(
            IntegrationStatus(status) if status else None,
            IntegrationCategory(category) if category else None)
    except ValueError:
        raise HTTPException(400, "Filtro inválido") from None
    return {"integrations": [item.model_dump(mode="json") for item in items]}


@app.get("/api/integration/catalog/{integration_id}")
async def integration_detail(integration_id: str, request: Request, _: str = Depends(require_session)):
    meta = request.app.state.integrations.catalog.get(integration_id)
    if not meta:
        raise HTTPException(404, "Integração não encontrada")
    return meta.model_dump(mode="json")


@app.get("/api/integration/catalog/{integration_id}/capabilities")
async def integration_capabilities(integration_id: str, request: Request, _: str = Depends(require_session)):
    meta = request.app.state.integrations.catalog.get(integration_id)
    if not meta:
        raise HTTPException(404, "Integração não encontrada")
    return {"capabilities": [c.model_dump(mode="json") for c in meta.capabilities]}


@app.post("/api/integration/execute", status_code=202)
async def integration_execute(body: ExecutionRequest, request: Request,
                              _: str = Depends(require_session), __: None = Depends(verify_csrf)):
    service = request.app.state.integrations
    try:
        job_id = await run_in_threadpool(service.submit, body)
        return {"job_id": job_id}
    except ValueError as error:
        # Executor validation errors are controlled messages, never raw input or secrets.
        message = str(error)
        code = 409 if "idempotência" in message else 400
        raise HTTPException(code, message) from None


@app.get("/api/integration/jobs")
async def integration_jobs(request: Request, limit: int = Query(100, ge=1, le=100),
                           _: str = Depends(require_session)):
    return {"jobs": request.app.state.integrations.list_jobs(limit)}


@app.get("/api/integration/jobs/{job_id}")
async def integration_job(job_id: str, request: Request, _: str = Depends(require_session)):
    try:
        return request.app.state.integrations.get_job(job_id)
    except ValueError:
        raise HTTPException(404, "Job de integração não encontrado") from None


@app.post("/api/integration/jobs/{job_id}/cancel")
async def integration_cancel(job_id: str, request: Request, _: str = Depends(require_session),
                             __: None = Depends(verify_csrf)):
    try:
        return request.app.state.integrations.cancel(job_id)
    except ValueError:
        raise HTTPException(404, "Job de integração não encontrado") from None
