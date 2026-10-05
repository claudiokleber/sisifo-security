import hashlib
import ipaddress
import re

from defusedxml import ElementTree

from sisifo.core.schema import Finding


def validate_target(target: str) -> str:
    if not target or len(target) > 253 or target.startswith("-"):
        raise ValueError("Alvo Nmap inválido.")
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        if "/" in target or ":" in target:
            raise ValueError("Use IP, CIDR ou hostname, sem URL.") from None
    labels = target.rstrip(".").split(".")
    if not all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", x) for x in labels):
        raise ValueError("Hostname inválido.")
    return target


def command(target: str) -> list[str]:
    validate_target(target)
    ipv6 = []
    try:
        if ipaddress.ip_network(target, strict=False).version == 6:
            ipv6 = ["-6"]
    except ValueError:
        pass
    return ["-sT", "-Pn", "-oX", "-", *ipv6, "--", target]


def parse(data: bytes, target: str, evidence: str) -> list[Finding]:
    root = ElementTree.fromstring(data)
    if root.tag != "nmaprun":
        raise ValueError("Arquivo não é XML do Nmap.")
    finished = root.find("runstats/finished")
    if finished is None or finished.get("exit") != "success":
        raise ValueError("XML do Nmap não confirma execução completa com sucesso.")
    result = []
    for host in root.findall("host"):
        addr = next(
            (
                a.get("addr")
                for a in host.findall("address")
                if a.get("addrtype") in {"ipv4", "ipv6"}
            ),
            target,
        )
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            number = int(port.attrib["portid"])
            protocol = port.attrib["protocol"]
            service = port.find("service")
            name = service.get("name", "unknown") if service is not None else "unknown"
            version = (
                " ".join(service.get(k, "") for k in ("product", "version", "extrainfo")).strip()
                if service is not None
                else ""
            )
            key = f"nmap|{addr}|{protocol}|{number}|{name}|{version}"
            result.append(
                Finding(
                    tool="nmap",
                    target=addr,
                    port=number,
                    protocol=protocol,
                    service=name,
                    finding=f"Porta {number}/{protocol} aberta; serviço {name} {version}".strip(),
                    evidence=evidence,
                    fingerprint=hashlib.sha256(key.encode()).hexdigest(),
                    identity=hashlib.sha256(
                        f"nmap|{addr}|{protocol}|{number}".encode()
                    ).hexdigest(),
                    details={"product_version": version},
                )
            )
    return result
