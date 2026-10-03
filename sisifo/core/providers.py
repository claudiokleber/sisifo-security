"""Bounded HTTP transports. Authenticated NVIDIA requests cannot redirect."""
import json
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .config import NVIDIA_ENDPOINT, nvidia_key
from .schema import AIResponse


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_json(url, body, headers=None, timeout=90):
    req = Request(url, data=json.dumps(body).encode(), headers={
        "Content-Type": "application/json", **(headers or {})
    })
    for attempt in range(3):
        try:
            with build_opener(NoRedirect()).open(req, timeout=timeout) as response:
                raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                raise ValueError("Resposta da IA excede 2 MB.")
            return json.loads(raw)
        except HTTPError as error:
            code = error.code
            error.close()
            if code in {429, 502, 503, 504} and attempt < 2:
                time.sleep(attempt + 1)
                continue
            messages = {401: "Chave rejeitada", 403: "Acesso ao modelo negado", 429: "Limite da API atingido"}
            raise ValueError(f"{messages.get(code, 'Falha HTTP do provedor')} (HTTP {code}).") from None
        except (URLError, TimeoutError, OSError):
            raise ValueError("Provedor indisponível ou tempo limite atingido.") from None
        except (json.JSONDecodeError, UnicodeError):
            raise ValueError("Provedor retornou JSON inválido.") from None


def complete(provider, model, system, data, endpoint=None):
    messages = [
        {"role": "system", "content": system + "\nEsquema JSON: " + json.dumps(AIResponse.model_json_schema())},
        {"role": "user", "content": json.dumps(data, ensure_ascii=False)},
    ]
    if provider == "nvidia":
        if endpoint and endpoint.rstrip("/") != NVIDIA_ENDPOINT:
            raise ValueError("A chave NVIDIA só pode ser enviada ao endpoint oficial.")
        envelope = request_json(NVIDIA_ENDPOINT + "/chat/completions", {
            "model": model, "messages": messages, "temperature": 0,
            "max_tokens": 4096, "stream": False, "response_format": {"type": "json_object"},
        }, {"Authorization": "Bearer " + nvidia_key()})
        choices = envelope.get("choices", [])
        if not choices or choices[0].get("finish_reason") != "stop":
            raise ValueError("Geração incompleta ou recusada pelo provedor.")
        content = choices[0].get("message", {}).get("content")
    elif provider == "ollama":
        import os
        base = (endpoint or os.getenv("SISIFO_OLLAMA_URL", "http://localhost:11434")).rstrip("/")
        parsed = urlsplit(base)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Endpoint Ollama inválido.")
        envelope = request_json(base + "/api/chat", {
            "model": model, "messages": messages, "stream": False,
            "format": AIResponse.model_json_schema(), "options": {"temperature": 0},
        })
        if not envelope.get("done"):
            raise ValueError("Geração incompleta.")
        content = envelope.get("message", {}).get("content")
    else:
        raise ValueError("Provedor inválido.")
    if not isinstance(content, str):
        raise ValueError("Provedor não retornou conteúdo textual.")
    return content, {"model": envelope.get("model", model), "usage": envelope.get("usage")}
