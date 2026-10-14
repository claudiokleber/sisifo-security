"""Local credentials: never part of a session, image, prompt or report."""

import csv
import hashlib
import json
import os
import re
import secrets
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

import bcrypt

from .session import atomic_write

NVIDIA_ENDPOINT = "https://integrate.api.nvidia.com/v1"
NVIDIA_MODEL = "nvidia/nemotron-3-super-120b-a12b"

CONFIG_VERSION = 2


def config_dir() -> Path:
    override = os.getenv("SISIFO_CONFIG_DIR")
    if override:
        return Path(override).resolve()
    project = Path(__file__).resolve().parents[2]
    if (project / "pyproject.toml").exists() and (project / ".sisifo-config").is_dir():
        return project / ".sisifo-config"
    base = Path(os.getenv("APPDATA", str(Path.home() / ".config")))
    return (base / "sisifo" / ".sisifo-config" if os.name == "nt" else base / "sisifo").resolve()


def load_config() -> Dict[str, Any]:
    path = config_dir() / "config.json"
    if not path.exists():
        return {"version": CONFIG_VERSION}
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(result, dict):
            raise ValueError
        if result.get("provider") not in {"nvidia", "ollama", "export", "api"}:
            raise ValueError
        if result["provider"] != "export" and not isinstance(result.get("model"), str):
            raise ValueError
        # Migration from v1
        if result.get("version", 1) < CONFIG_VERSION:
            result = migrate_config_v1_to_v2(result)
        return result
    except (ValueError, OSError):
        raise ValueError("Configuração inválida; execute sisifo setup novamente.") from None


def migrate_config_v1_to_v2(old: Dict[str, Any]) -> Dict[str, Any]:
    """Migrate v1 config to v2 format."""
    new = {
        "version": CONFIG_VERSION,
        "provider": old.get("provider", "export"),
        "model": old.get("model"),
        "services": {},
    }
    # NVIDIA key is stored separately in nvidia.key
    return new


def private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "nt":
        identity = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True
        ).stdout
        sid = next(csv.reader([identity.strip()]))[1]
        result = subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F"],
            capture_output=True,
        )
        if result.returncode:
            raise ValueError("Não foi possível proteger a pasta de credenciais.")
    else:
        path.chmod(0o700)


def save_config(provider: str, model: str, api_key: Optional[str] = None) -> None:
    if provider not in {"nvidia", "ollama", "export", "api"}:
        raise ValueError("Provedor inválido.")
    if provider != "export" and (not isinstance(model, str) or not model.strip()):
        raise ValueError("Modelo não pode estar vazio.")
    if api_key is not None and (
        not api_key.startswith("nvapi-") or any(c.isspace() for c in api_key)
    ):
        raise ValueError("Formato de chave NVIDIA inválido.")
    directory = config_dir()
    private_directory(directory)
    if api_key:
        atomic_write(directory / "nvidia.key", api_key)
        if os.name != "nt":
            (directory / "nvidia.key").chmod(0o600)
    config = {
        "version": CONFIG_VERSION,
        "provider": provider,
        "model": model,
        "services": load_config().get("services", {}),
    }
    atomic_write(directory / "config.json", json.dumps(config, ensure_ascii=False, indent=2))


def service_path(service_id):
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", service_id):
        raise ValueError("Identificador de serviço inválido.")
    root = config_dir().resolve()
    path = (root / f"{service_id}.json").resolve()
    if not path.is_relative_to(root):
        raise ValueError("Configuração fora da pasta permitida.")
    return path


def load_service_config(service_id: str) -> Dict[str, Any]:
    """Load configuration for a specific service (OSINT connectors, etc.)."""
    path = service_path(service_id)
    if not path.exists():
        return {}
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
        return result if isinstance(result, dict) else {}
    except (ValueError, OSError):
        return {}


def save_service_config(service_id: str, config: Dict[str, Any]) -> None:
    """Save configuration for a specific service."""
    directory = config_dir()
    private_directory(directory)
    path = service_path(service_id)
    atomic_write(path, json.dumps(config, ensure_ascii=False, indent=2))
    if os.name != "nt":
        path.chmod(0o600)


def delete_service_config(service_id: str) -> bool:
    """Delete configuration for a specific service. Returns True if deleted."""
    path = service_path(service_id)
    if path.exists():
        path.unlink()
        return True
    return False


def list_service_configs() -> List[str]:
    """List all configured service IDs."""
    directory = config_dir()
    if not directory.exists():
        return []
    configs = []
    for f in directory.glob("*.json"):
        if f.name not in ("config.json", "web.json"):
            configs.append(f.stem)
    return configs


def get_service_config_status(service_id: str) -> Dict[str, Any]:
    """Get configuration status without revealing secrets."""
    config = load_service_config(service_id)
    if not config:
        return {"configured": False}
    # Return only field names that are configured, not values
    configured_fields = [k for k, v in config.items() if v]
    return {"configured": bool(configured_fields), "fields": configured_fields}


def nvidia_key() -> str:
    value = os.getenv("NVIDIA_API_KEY")
    if not value:
        try:
            value = (config_dir() / "nvidia.key").read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            raise ValueError("Chave NVIDIA ausente; execute sisifo setup.") from None
    if not value.startswith("nvapi-") or any(c.isspace() for c in value):
        raise ValueError("Formato de chave NVIDIA inválido.")
    return value


def web_password_configured() -> bool:
    cfg = load_service_config("web")
    return bool(os.getenv("SISIFO_WEB_PASSWORD") or cfg.get("password_hash") or cfg.get("password"))


def _password_bytes(password):
    if not isinstance(password, str) or not 8 <= len(password) <= 1024:
        raise ValueError("Senha deve ter entre 8 e 1024 caracteres.")
    # Bcrypt input is bounded to 64 ASCII bytes, avoiding silent 72-byte truncation.
    return hashlib.sha256(password.encode()).hexdigest().encode()


def verify_web_password(password: str) -> bool:
    if not isinstance(password, str) or len(password) > 1024:
        return False
    env_password = os.getenv("SISIFO_WEB_PASSWORD")
    if env_password:
        return secrets.compare_digest(password.encode(), env_password.encode())
    cfg = load_service_config("web")
    hashed = cfg.get("password_hash")
    if hashed:
        try:
            if cfg.get("password_scheme") == "bcrypt-sha256-v1":
                value = _password_bytes(password)
            else:
                value = password.encode()
                if len(value) > 72:
                    return False
            valid = bcrypt.checkpw(value, hashed.encode())
            if valid and cfg.get("password_scheme") != "bcrypt-sha256-v1":
                set_web_password(password)
            return valid
        except (ValueError, TypeError):
            return False
    legacy = cfg.get("password")
    if isinstance(legacy, str) and secrets.compare_digest(legacy.encode(), password.encode()):
        set_web_password(password)
        return True
    return False


def set_web_password(password: str) -> None:
    value = _password_bytes(password)
    cfg = load_service_config("web")
    cfg.pop("password", None)
    cfg.update(
        password_hash=bcrypt.hashpw(value, bcrypt.gensalt()).decode(),
        password_scheme="bcrypt-sha256-v1",
    )
    save_service_config("web", cfg)
