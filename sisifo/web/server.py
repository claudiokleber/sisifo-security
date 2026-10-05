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
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

from sisifo.core import session as store
from sisifo.core.ai_analyzer import analyze_session, prepare_batches
from sisifo.core.config import (
    load_config,
    load_service_config,
    nvidia_key,
    save_config,
    save_service_config,
    set_web_password,
    verify_web_password,
    web_password_configured,
)
from sisifo.core.jobs import JobManager
from sisifo.core.modules import registry
from sisifo.core.report import build_report, compare_sessions
from sisifo.osint import get_connector, list_connectors
from sisifo.osint.contract import QueryType
from sisifo.osint.executor import run_query
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
    app.state.jobs = JobManager(store.data_root(), workers=int(os.getenv("SISIFO_MAX_JOBS", "2")))
    try:
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
    provider: Optional[Literal["nvidia", "ollama", "export"]] = None
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
    connector_id: str = Field(..., min_length=1)
    query: str = Field(..., min_length=1)
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


@app.post("/api/osint/query")
async def api_osint_query(body: OsintQueryRequest, request: Request, _: str = Depends(require_session), __: None = Depends(verify_csrf)):
    try:
        connector = get_connector(body.connector_id)
        qt = QueryType(body.query_type)
        cfg = load_service_config(f"osint_{body.connector_id}")
        if not connector.validate_config(cfg) or qt not in connector.meta.query_types or not connector.validate_query(body.query, qt):
            raise ValueError()
    except (KeyError, ValueError):
        raise HTTPException(status_code=400, detail="Conector, configuração ou consulta inválidos.") from None
    def execute(control):
        control.check()
        result = run_query(connector, body.query, qt, cfg)
        control.check()
        return {"results": [r.model_dump() for r in result]}
    return submit(request, "osint", body.model_dump(), execute)


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


class AIConfigRequest(BaseModel):
    provider: Literal["nvidia", "ollama", "export"]
    model: str = Field(default="", max_length=200)
    nvidia_key: Optional[str] = Field(default=None, max_length=512)


@app.post("/api/config/ai")
async def api_save_ai(body: AIConfigRequest, _: str = Depends(require_session), __: None = Depends(verify_csrf)):
    try:
        await run_in_threadpool(save_config, body.provider, body.model, body.nvidia_key or None)
        return {"saved": True}
    except ValueError:
        raise HTTPException(status_code=400, detail="Configuração inválida.") from None


class PasswordRequest(BaseModel):
    password: str = Field(min_length=8, max_length=1024)


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
    config = load_config()
    osint_configs = {}
    for connector_id in list_connectors().keys():
        osint_configs[connector_id] = bool(get_connector(connector_id).validate_config(load_service_config(f"osint_{connector_id}")))
    configured = bool(config.get("model")) and config.get("provider") == "ollama"
    if config.get("provider") == "nvidia":
        try:
            nvidia_key()
            configured = bool(config.get("model"))
        except ValueError:
            pass
    return {
        "ai": {
            "provider": config.get("provider"),
            "model": config.get("model"),
            "configured": configured,
        },
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
