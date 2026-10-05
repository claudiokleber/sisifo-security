import typer
from rich.console import Console

from sisifo import branding as ui
from sisifo.core import session as store
from sisifo.core.report import build_report

console = Console(markup=False)

app = typer.Typer(help="Gerar e mostrar relatório de uma sessão.", no_args_is_help=True)


@app.callback(invoke_without_command=True)
def report(
    ctx: typer.Context,
    session_id: str = typer.Argument(..., help="ID da sessão"),
):
    if ctx.invoked_subcommand is not None:
        return
    with ui.climb("Gerando relatório"):
        build_report(session_id)
    console.print(str(store.session_dir(session_id) / "reports/report.md"))