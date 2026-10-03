import json
from functools import wraps
from pathlib import Path

import typer
from rich.console import Console

from sisifo.core import session as store
from sisifo.core.ai_analyzer import analyze_session
from sisifo.core.importer import import_nmap as import_xml
from sisifo.core.modules import registry
from sisifo.core.orchestrator import scan as execute_scan
from sisifo.core.report import build_report, compare_sessions

app = typer.Typer(
    help="Sísifo — containers, evidências e relatórios de segurança.", no_args_is_help=True
)
sessions = typer.Typer(help="Consultar sessões.", no_args_is_help=True)
app.add_typer(sessions, name="session")
console = Console(markup=False)


def guarded(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (ValueError, OSError) as e:
            console.print(f"Erro: {e}")
            raise typer.Exit(1) from None

    return wrapper


@app.command()
@guarded
def scan(target: str, modules: str = "nmap", project: str = "default", timeout: int = 600):
    """Executar ferramentas nos alvos do seu ambiente autorizado."""
    s = execute_scan(target, modules, project, timeout)
    build_report(s.id)
    console.print(
        f"Sessão: {s.id}\nEstado: {s.status}\nRelatório: {store.session_dir(s.id) / 'reports/report.md'}"
    )
    for r in s.runs:
        if r.error:
            console.print(f"{r.tool}: {r.error}")
    if s.status != "completed":
        raise typer.Exit(130 if s.status == "cancelled" else 1)


@sessions.command("list")
@guarded
def list_sessions():
    root = store.data_root() / "sessions"
    for d in sorted(root.iterdir()) if root.exists() else []:
        if d.is_dir():
            try:
                s = store.load_session(d.name)
                console.print(f"{s.id} | {s.project} | {s.target} | {s.status}")
            except ValueError as e:
                console.print(f"Ignorada {d.name}: {e}")


@sessions.command("show")
@guarded
def show_session(session_id: str):
    console.print(store.load_session(session_id).model_dump_json(indent=2))


@app.command()
@guarded
def report(session_id: str):
    build_report(session_id)
    console.print(str(store.session_dir(session_id) / "reports/report.md"))


@app.command()
@guarded
def analyze(session_id: str, model: str | None = None, endpoint: str | None = None):
    """Sem --model exporta evidências; com --model consulta Ollama."""
    console.print(
        json.dumps(analyze_session(session_id, model, endpoint), ensure_ascii=False, indent=2)
    )


@app.command("import-nmap")
@guarded
def import_nmap(path: Path, target: str, project: str = "default"):
    """Importar XML existente sem executar ferramentas."""
    s = import_xml(path, target, project)
    build_report(s.id)
    console.print(s.id)


@app.command()
@guarded
def compare(before: str, after: str):
    console.print(json.dumps(compare_sessions(before, after), ensure_ascii=False, indent=2))


@app.command()
def modules():
    for name, m in registry().items():
        console.print(f"{name}: {m.image}")


@app.command("export-vault")
@guarded
def export_vault(session_id: str, vault: Path):
    """Exportar resumo para um vault existente, sem sobrescrever notas editadas."""
    from sisifo.core.vault import export_vault as export

    console.print(str(export(session_id, vault)))


@app.command()
def doctor():
    import docker

    console.print(f"Dados: {store.data_root()}")
    client = None
    try:
        client = docker.from_env(timeout=10)
        client.ping()
        console.print("Docker: disponível")
        missing = False
        for m in registry().values():
            try:
                console.print(f"{m.name}: {client.images.get(m.image).id}")
            except docker.errors.ImageNotFound:
                console.print(f"{m.name}: imagem ausente ({m.image})")
                missing = True
        if missing:
            raise typer.Exit(1)
    except docker.errors.DockerException as e:
        console.print(f"Docker indisponível: {e}")
        raise typer.Exit(1) from None
    finally:
        if client:
            client.close()


if __name__ == "__main__":
    app()
