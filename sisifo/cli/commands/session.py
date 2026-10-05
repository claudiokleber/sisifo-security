
import typer
from rich.console import Console

from sisifo.core import session as store
from sisifo.core.orchestrator import recover_session

console = Console(markup=False)

app = typer.Typer(help="Consultar sessões.", no_args_is_help=True)


@app.command("list")
def list_sessions():
    root = store.data_root() / "sessions"
    for d in sorted(root.iterdir()) if root.exists() else []:
        if d.is_dir():
            try:
                s = store.load_session(d.name)
                console.print(f"{s.id} | {s.project} | {s.target} | {s.status}")
            except ValueError as e:
                console.print(f"Ignorada {d.name}: {e}")


@app.command("show")
def show_session(session_id: str):
    console.print(store.load_session(session_id).model_dump_json(indent=2))


@app.command("verify")
def verify(session_id: str):
    """Conferir integridade de achados, contagens e artefatos."""
    findings = store.verified_findings(store.load_session(session_id))
    console.print(f"Integridade verificada: {len(findings)} evidências.")


@app.command("recover")
def recover(session_id: str):
    """Marcar sessão órfã como interrompida, sem reiniciar ferramentas."""
    import docker
    try:
        result = recover_session(session_id)
    except docker.errors.DockerException:
        raise typer.Exit(code=1) from None
    console.print(f"Sessão: {result.id}; estado: {result.status}. Evidências preservadas.")