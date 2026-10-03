"""Local credentials: never part of a session, image, prompt or report."""
import csv
import json
import os
import subprocess
from pathlib import Path

from .session import atomic_write

NVIDIA_ENDPOINT = "https://integrate.api.nvidia.com/v1"
NVIDIA_MODEL = "meta/llama-3.3-70b-instruct"


def config_dir():
    return Path(os.getenv("SISIFO_CONFIG_DIR", str(Path.cwd() / ".sisifo-config"))).resolve()


def load_config():
    path = config_dir() / "config.json"
    if not path.exists():
        return {}
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(result, dict):
            raise ValueError
        return result
    except (ValueError, OSError):
        raise ValueError("Configuração inválida; execute sisifo setup novamente.") from None


def private_directory(path):
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


def save_config(provider, model, api_key=None):
    if provider not in {"nvidia", "ollama", "export"}:
        raise ValueError("Provedor inválido.")
    if api_key is not None and (not api_key.startswith("nvapi-") or any(c.isspace() for c in api_key)):
        raise ValueError("Formato de chave NVIDIA inválido.")
    directory = config_dir()
    private_directory(directory)
    if api_key:
        atomic_write(directory / "nvidia.key", api_key)
        if os.name != "nt":
            (directory / "nvidia.key").chmod(0o600)
    atomic_write(directory / "config.json", json.dumps({"provider": provider, "model": model}))


def nvidia_key():
    value = os.getenv("NVIDIA_API_KEY")
    if not value:
        try:
            value = (config_dir() / "nvidia.key").read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            raise ValueError("Chave NVIDIA ausente; execute sisifo setup.") from None
    if not value.startswith("nvapi-") or any(c.isspace() for c in value):
        raise ValueError("Formato de chave NVIDIA inválido.")
    return value
