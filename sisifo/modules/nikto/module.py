import hashlib
import json
from urllib.parse import urlsplit

from sisifo.core.schema import Finding
from sisifo.modules.nmap.module import validate_target as validate_host


def validate_target(target: str) -> str:
    try:
        url = urlsplit(target)
        port = url.port
        if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password:
            raise ValueError
        if url.query or url.fragment or (url.path not in {"", "/"}):
            raise ValueError
        validate_host(url.hostname)
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        raise ValueError(
            "Nikto requer URL de origem: http(s)://host[:porta], sem credenciais ou caminho."
        ) from None
    return target


def command(target: str) -> list[str]:
    validate_target(target)
    return [
        "-h",
        target,
        "-Format",
        "json",
        "-output",
        "/tmp/nikto.json",
        "-nointeractive",
        "-maxtime",
        "300s",
    ]


def parse(data: bytes, target: str, evidence: str) -> list[Finding]:
    obj = json.loads(data)
    hosts = obj if isinstance(obj, list) else [obj]
    results = []
    for host in hosts:
        if not isinstance(host, dict) or not isinstance(host.get("vulnerabilities"), list):
            raise ValueError("Formato JSON Nikto não reconhecido; revisar saída original.")  # noqa: TRY004
        for item in host["vulnerabilities"]:
            if not isinstance(item, dict) or not isinstance(item.get("msg"), str):
                raise ValueError("Achado Nikto inválido.")  # noqa: TRY004
            key = f"nikto|{target}|{item.get('id')}|{item.get('url')}|{item['msg']}"
            results.append(
                Finding(
                    tool="nikto",
                    target=target,
                    category="potential_issue",
                    severity="info",
                    finding=item["msg"],
                    evidence=evidence,
                    fingerprint=hashlib.sha256(key.encode()).hexdigest(),
                    raw=json.dumps(item, ensure_ascii=False),
                    identity=hashlib.sha256(
                        f"nikto|{target}|{item.get('id')}|{item.get('url')}|{item.get('method')}".encode()
                    ).hexdigest()
                    if item.get("id")
                    else None,
                    details={k: item[k] for k in ("id", "url", "method") if k in item},
                )
            )
    return results
