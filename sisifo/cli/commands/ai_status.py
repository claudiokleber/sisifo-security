import typer
from rich.console import Console

from sisifo.core.config import load_config, nvidia_key

console = Console(markup=False)

app = typer.Typer(help="Mostrar configuração de IA sem exibir credenciais.", no_args_is_help=True, invoke_without_command=True)


@app.callback(invoke_without_command=True)
def ai_status(ctx: typer.Context):
    if ctx.invoked_subcommand is not None:
        return
    config = load_config()
    console.print(
        f"Provedor: {config.get('provider', 'export')}; modelo: {config.get('model') or '-'}"
    )
    if config.get("provider") == "nvidia":
        try:
            nvidia_key()
            console.print("Chave NVIDIA: configurada (não exibida).")
        except Exception:
            console.print("Chave NVIDIA: não configurada.")