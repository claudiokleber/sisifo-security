import typer
from rich.console import Console

from sisifo.core.config import set_web_password

console = Console(markup=False)

app = typer.Typer(
    help="Configurar senha da interface web.", no_args_is_help=False, invoke_without_command=True
)


@app.callback(invoke_without_command=True)
def set_password(ctx: typer.Context = None):
    if ctx is not None and ctx.invoked_subcommand is not None:
        return
    pwd = typer.prompt("Nova senha", hide_input=True, confirmation_prompt=True)
    if len(pwd) < 8:
        raise typer.BadParameter("Senha deve ter pelo menos 8 caracteres.")
    set_web_password(pwd)
    console.print("Senha da interface web definida com sucesso.")
