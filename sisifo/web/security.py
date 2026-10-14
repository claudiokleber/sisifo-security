import hashlib
import hmac
import secrets
import time
from pathlib import Path
from typing import Optional

from fastapi import Depends, HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from sisifo.core.config import config_dir, private_directory

SESSION_SECRET_FILE = config_dir() / "web_session.secret"

CSRF_SECRET_FILE = config_dir() / "web_csrf.secret"

SESSION_COOKIE_NAME = "sisifo_session"

CSRF_COOKIE_NAME = "sisifo_csrf"

SESSION_TIMEOUT = 3600


def _get_or_create_secret(file_path: Path) -> bytes:

    private_directory(file_path.parent)

    if file_path.exists():
        return file_path.read_bytes()

    secret = secrets.token_bytes(32)

    try:
        with file_path.open("xb") as handle:
            handle.write(secret)
    except FileExistsError:
        return file_path.read_bytes()

    file_path.chmod(0o600)

    return secret


def create_session_token() -> str:

    return secrets.token_urlsafe(32)


def create_csrf_token(session_id: str) -> str:

    timestamp = str(int(time.time()))

    message = f"{session_id}:{timestamp}".encode()

    signature = hmac.new(
        _get_or_create_secret(config_dir() / "web_csrf.secret"), message, hashlib.sha256
    ).hexdigest()

    return f"{timestamp}:{signature}"


def verify_csrf_token(session_id: str, token: str) -> bool:

    try:
        timestamp_str, signature = token.split(":", 1)

        timestamp = int(timestamp_str)

        if not 0 <= time.time() - timestamp <= SESSION_TIMEOUT:
            return False

        message = f"{session_id}:{timestamp_str}".encode()

        expected = hmac.new(
            _get_or_create_secret(config_dir() / "web_csrf.secret"), message, hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(signature, expected)

    except Exception:
        return False


class SessionManager:
    def __init__(self):

        self._sessions: dict[str, dict] = {}

    def create_session(self) -> str:

        session_id = create_session_token()

        self._sessions[session_id] = {
            "created_at": time.time(),
            "csrf_token": create_csrf_token(session_id),
        }

        return session_id

    def get_session(self, session_id: str) -> Optional[dict]:

        session = self._sessions.get(session_id)

        if session and time.time() - session["created_at"] < SESSION_TIMEOUT:
            return session

        elif session:
            del self._sessions[session_id]

        return None

    def delete_session(self, session_id: str) -> None:

        self._sessions.pop(session_id, None)

    def get_csrf_token(self, session_id: str) -> Optional[str]:

        session = self.get_session(session_id)

        return session["csrf_token"] if session else None


session_manager = SessionManager()


async def get_session_id(request: Request) -> Optional[str]:

    return request.cookies.get(SESSION_COOKIE_NAME)


async def require_session(session_id: Optional[str] = Depends(get_session_id)) -> str:

    if not session_id or not session_manager.get_session(session_id):
        raise HTTPException(status_code=401, detail="Sessão inválida ou expirada")

    return session_id


async def verify_csrf(
    request: Request,
    session_id: str = Depends(require_session),
) -> None:

    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        csrf_token = request.headers.get("X-CSRF-Token") or (await request.form()).get("csrf_token")

        if not csrf_token or not verify_csrf_token(session_id, csrf_token):
            raise HTTPException(status_code=403, detail="Token CSRF inválido")


class HostValidationMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, allowed_hosts: Optional[list[str]] = None):

        super().__init__(app)

        self.allowed_hosts = allowed_hosts or ["127.0.0.1", "localhost"]

    async def dispatch(self, request: Request, call_next):

        from urllib.parse import urlsplit

        host = request.url.hostname

        if host not in self.allowed_hosts:
            return JSONResponse({"detail": "Host não permitido"}, status_code=403)

        origin = request.headers.get("origin")

        if origin:
            try:
                parsed = urlsplit(origin)

                expected = urlsplit(str(request.base_url))

                if (parsed.scheme, parsed.hostname, parsed.port) != (
                    expected.scheme,
                    expected.hostname,
                    expected.port,
                ):
                    return JSONResponse({"detail": "Origin não permitido"}, status_code=403)

            except ValueError:
                return JSONResponse({"detail": "Origin inválido"}, status_code=403)

        return await call_next(request)


def validate_path(base_dir: Path, requested_path: str) -> Path:

    base = base_dir.resolve()

    target = (base / requested_path).resolve()

    if not target.is_relative_to(base):
        raise HTTPException(status_code=403, detail="Caminho não permitido")

    if not target.exists():
        raise HTTPException(status_code=404, detail="Arquivo não encontrado")

    return target
