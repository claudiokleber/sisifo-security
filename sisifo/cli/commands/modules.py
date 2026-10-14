import typer
from rich.console import Console

from sisifo.core.modules import registry

console = Console(markup=False)

app = typer.Typer(
    help="Listar módulos disponíveis.", no_args_is_help=False, invoke_without_command=True
)


@app.callback(invoke_without_command=True)
def list(ctx: typer.Context):
    if ctx.invoked_subcommand is not None:
        return
    for name, m in registry().items():
        console.print(
            f"{name}: {m.image}" + (" (experimental, opcional)" if m.experimental else "")
        )
