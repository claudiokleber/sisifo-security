import json

import typer
from rich.console import Console

from sisifo.core.report import compare_sessions

console = Console(markup=False)

app = typer.Typer(help="Comparar duas sessões compatíveis.", no_args_is_help=True)


@app.callback(invoke_without_command=True)
def compare(
    ctx: typer.Context,
    before: str = typer.Argument(..., help="ID da sessão anterior"),
    after: str = typer.Argument(..., help="ID da sessão posterior"),
):
    if ctx.invoked_subcommand is not None:
        return
    console.print(json.dumps(compare_sessions(before, after), ensure_ascii=False, indent=2))
