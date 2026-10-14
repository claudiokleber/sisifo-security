"""Bounded HTTP transports. Authenticated NVIDIA requests cannot redirect."""

import json
import time
from contextlib import contextmanager
from contextvars import ContextVar
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .config import NVIDIA_ENDPOINT, nvidia_key
from .schema import AIResponse

_runtime = ContextVar("inference_runtime", default=None)


@contextmanager
def inference_runtime(control, output_tokens=8192):
    token = _runtime.set((control, output_tokens))
    try:
        yield
    finally:
        _runtime.reset(token)


def _pause(seconds):
    runtime = _runtime.get()
    if runtime:
        control = runtime[0]
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            control.check()
            control.cancelled.wait(min(0.1, end - time.monotonic()))
    else:
        time.sleep(seconds)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_json(url, body, headers=None, timeout=90):
    req = Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    for attempt in range(3):
        try:
            runtime = _runtime.get()
            effective_timeout = min(timeout, runtime[0].remaining()) if runtime else timeout
            with build_opener(NoRedirect()).open(req, timeout=effective_timeout) as response:
                raw = response.read(2_000_001)
            if runtime:
                runtime[0].check()
            if len(raw) > 2_000_000:
                raise ValueError("Resposta da IA excede 2 MB.")
            return json.loads(raw)
        except HTTPError as error:
            code = error.code
            retry_after = error.headers.get("Retry-After", "") if error.headers else ""
            error.close()
            if code in {429, 502, 503, 504} and attempt < 2:
                _pause(min(30, int(retry_after)) if retry_after.isdigit() else attempt + 1)
                continue
            messages = {
                401: "Chave rejeitada",
                403: "Acesso ao modelo negado",
                429: "Limite da API atingido",
                410: "Modelo retirado do provedor; escolha outro em sisifo setup",
            }
            raise ValueError(
                f"{messages.get(code, 'Falha HTTP do provedor')} (HTTP {code})."
            ) from None
        except (URLError, TimeoutError, OSError):
            raise ValueError("Provedor indisponível ou tempo limite atingido.") from None
        except (json.JSONDecodeError, UnicodeError):
            raise ValueError("Provedor retornou JSON inválido.") from None


def complete(provider, model, system, data, endpoint=None):
    messages = [
        {
            "role": "system",
            "content": system + "\nEsquema JSON: " + json.dumps(AIResponse.model_json_schema()),
        },
        {"role": "user", "content": json.dumps(data, ensure_ascii=False)},
    ]
    if provider == "api":
        from .ai_connection import complete_messages, connection

        profile = connection()
        if endpoint and endpoint.rstrip("/") != profile["endpoint"]:
            raise ValueError("A chave só pode ser enviada à API configurada.")
        profile["model"] = model
        runtime = _runtime.get()
        return complete_messages(
            profile,
            messages,
            runtime[0] if runtime else None,
            runtime[1] if runtime else 8192,
            json_output=True,
        )
    if provider == "nvidia":
        if endpoint and endpoint.rstrip("/") != NVIDIA_ENDPOINT:
            raise ValueError("A chave NVIDIA só pode ser enviada ao endpoint oficial.")
        envelope = request_json(
            NVIDIA_ENDPOINT + "/chat/completions",
            {
                "model": model,
                "messages": messages,
                "temperature": 0,
                "max_tokens": _runtime.get()[1] if _runtime.get() else 8192,
                "stream": False,
                "response_format": {"type": "json_object"},
            },
            {"Authorization": "Bearer " + nvidia_key()},
        )
        choices = envelope.get("choices", [])
        if not choices or choices[0].get("finish_reason") != "stop":
            raise ValueError("Geração incompleta ou recusada pelo provedor.")
        content = choices[0].get("message", {}).get("content")
    elif provider == "ollama":
        import os

        base = (endpoint or os.getenv("SISIFO_OLLAMA_URL", "http://localhost:11434")).rstrip("/")
        parsed = urlsplit(base)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Endpoint Ollama inválido.")
        envelope = request_json(
            base + "/api/chat",
            {
                "model": model,
                "messages": messages,
                "stream": False,
                "format": AIResponse.model_json_schema(),
                "options": {
                    "temperature": 0,
                    "num_predict": _runtime.get()[1] if _runtime.get() else 8192,
                },
            },
        )
        if not envelope.get("done"):
            raise ValueError("Geração incompleta.")
        content = envelope.get("message", {}).get("content")
    else:
        raise ValueError("Provedor inválido.")
    if not isinstance(content, str):
        raise ValueError("Provedor não retornou conteúdo textual.")
    usage = envelope.get("usage") or {
        "prompt_tokens": envelope.get("prompt_eval_count"),
        "completion_tokens": envelope.get("eval_count"),
    }
    return content, {"model": envelope.get("model", model), "usage": usage}
