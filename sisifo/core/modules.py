import os
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from sisifo.modules.metasploit import module as metasploit
from sisifo.modules.nikto import module as nikto
from sisifo.modules.nmap import module as nmap


@dataclass(frozen=True)
class Module:
    name: str
    image: str
    command: Callable
    parse: Callable
    artifact: str
    container_file: str | None = None
    memory_limit: str = "512m"
    experimental: bool = False


def registry() -> dict[str, Module]:
    return {
        "metasploit": Module(
            "metasploit",
            os.getenv("SISIFO_METASPLOIT_IMAGE", "sisifo/metasploit:0.2.1"),
            metasploit.command,
            metasploit.parse,
            "metasploit.json",
            "/tmp/metasploit.json",
            memory_limit="1536m",
            experimental=True,
        ),
        "nmap": Module(
            "nmap",
            os.getenv("SISIFO_NMAP_IMAGE", "sisifo/nmap:0.2"),
            nmap.command,
            nmap.parse,
            "nmap.xml",
        ),
        "nikto": Module(
            "nikto",
            os.getenv(
                "SISIFO_NIKTO_IMAGE",
                "ghcr.io/sullo/nikto:2.6.1@sha256:f65dd97be358e8260d97a00e784c05c5f37d2ed69b9a9611b14d3889c2b54efa",
            ),
            nikto.command,
            nikto.parse,
            "nikto.json",
            "/tmp/nikto.json",
        ),
    }


def select_modules(names: str):
    selected = [x.strip() for x in names.split(",")]
    modules = registry()
    if (
        not selected
        or len(selected) != len(set(selected))
        or any(x not in modules for x in selected)
    ):
        raise ValueError("Módulos inválidos ou repetidos. Disponíveis: " + ", ".join(modules))
    return [modules[x] for x in selected]


def target_for(module: Module, target: str) -> str:
    """A web origin can share one session: Nmap inspects its host, Nikto its URL."""
    if module.name == "nmap" and target.startswith(("http://", "https://")):
        nikto.validate_target(target)
        return urlsplit(target).hostname
    return target
