import typer
from rich.console import Console

from sisifo import branding as ui
from sisifo.core import session as store
from sisifo.core.orchestrator import scan as execute_scan
from sisifo.core.report import build_report

console = Console(markup=False)

app = typer.Typer(help="Executar ferramentas nos alvos do seu ambiente autorizado.", no_args_is_help=True)


@app.callback(invoke_without_command=True)
def scan(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Alvo (IP, CIDR, hostname ou URL)"),
    modules: str = typer.Option("nmap", "--modules", "-m", help="Módulos separados por vírgula"),
    project: str = typer.Option("default", "--project", "-p", help="Nome do projeto"),
    timeout: int = typer.Option(600, "--timeout", "-t", help="Timeout em segundos"),
):
    if ctx.invoked_subcommand is not None:
        return
    with ui.climb("Coletando evidências"):
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