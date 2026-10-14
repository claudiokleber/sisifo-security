from pathlib import Path

import typer
from rich.console import Console

from sisifo.core.vault import export_vault as export

console = Console(markup=False)

app = typer.Typer(
    help="Exportar resumo para um vault existente, sem sobrescrever notas editadas.",
    no_args_is_help=True,
)


@app.callback(invoke_without_command=True)
def export_vault(
    ctx: typer.Context,
    session_id: str = typer.Argument(..., help="ID da sessão"),
    vault: Path = typer.Argument(..., help="Caminho do vault Obsidian"),
):
    if ctx.invoked_subcommand is not None:
        return
    console.print(str(export(session_id, vault)))
