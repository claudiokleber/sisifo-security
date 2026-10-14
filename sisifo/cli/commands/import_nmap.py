from pathlib import Path

import typer
from rich.console import Console

from sisifo.core.importer import import_nmap as import_xml
from sisifo.core.report import build_report

console = Console(markup=False)

app = typer.Typer(
    help="Importar XML do Nmap existente sem executar ferramentas.", no_args_is_help=True
)


@app.callback(invoke_without_command=True)
def import_nmap(
    ctx: typer.Context,
    path: Path = typer.Argument(..., help="Caminho do arquivo XML"),
    target: str = typer.Argument(..., help="Alvo original"),
    project: str = typer.Option("default", "--project", "-p", help="Nome do projeto"),
):
    if ctx.invoked_subcommand is not None:
        return
    s = import_xml(path, target, project)
    build_report(s.id)
    console.print(s.id)
