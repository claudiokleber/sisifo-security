import hashlib
import json
import ipaddress
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from sisifo.core.schema import Finding
from sisifo.modules.nikto.module import validate_target

PROFILE = "auxiliary/scanner/http/http_version"


class Service(BaseModel):
    host: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535)
    protocol: Literal["http", "https"]
    info: str = Field(min_length=1)


class Result(BaseModel):
    schema_version: Literal[1]
    status: Literal["completed"]
    module: Literal["auxiliary/scanner/http/http_version"]
    framework_version: str = Field(min_length=1)
    target: str
    resolved_hosts: list[str] = Field(min_length=1)
    services: list[Service] = Field(min_length=1)


def command(target: str) -> list[str]:
    validate_target(target)
    # JSON is passed as a single argv entry; no shell or msfconsole interpolation.
    return [json.dumps({"target": target}, ensure_ascii=True)]


def parse(data: bytes, target: str, evidence: str) -> list[Finding]:
    result = Result.model_validate_json(data)
    validate_target(target)
    url = urlsplit(target)
    expected_port = url.port or (443 if url.scheme == "https" else 80)
    if result.target != target:
        raise ValueError("Resultado Metasploit pertence a outro alvo.")
    def normalize(host):
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            return host.rstrip(".").lower()
    allowed = {normalize(h) for h in result.resolved_hosts}
    try:
        requested_ip = str(ipaddress.ip_address(url.hostname))
    except ValueError:
        requested_ip = None
    if requested_ip and allowed != {requested_ip}:
        raise ValueError("Resolução Metasploit diverge do IP solicitado.")
    findings, seen = [], set()
    for service in result.services:
        if normalize(service.host) not in allowed:
            raise ValueError("Host Metasploit não pertence à resolução registrada.")
        if (service.port, service.protocol) != (expected_port, url.scheme):
            raise ValueError("Serviço Metasploit não corresponde à origem solicitada.")
        key = f"metasploit|{PROFILE}|{target}|{service.info}"
        fingerprint = hashlib.sha256(key.encode()).hexdigest()
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        findings.append(Finding(
            tool="metasploit", target=target, port=service.port, protocol="tcp",
            service=service.protocol, severity="info", category="observation",
            finding=f"Metasploit identificou serviço {service.protocol}: {service.info}",
            evidence=evidence, fingerprint=fingerprint,
            identity=hashlib.sha256(f"metasploit|{PROFILE}|{target}".encode()).hexdigest(),
            raw=json.dumps({"module": PROFILE, "framework_version": result.framework_version,
                            "service": service.model_dump()}, ensure_ascii=False),
        ))
    return findings
