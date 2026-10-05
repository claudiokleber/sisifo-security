import typer
from rich.console import Console

from sisifo.core.config import (
    NVIDIA_MODEL,
    config_dir,
    load_config,
    nvidia_key,
    save_config,
)

console = Console(markup=False)

app = typer.Typer(help="Configuração de IA e credenciais.", no_args_is_help=True, invoke_without_command=True)


@app.callback(invoke_without_command=True)
def setup(ctx: typer.Context = None):
    """Assistente interativo de configuração (IA e senha web)."""
    if ctx is None or ctx.invoked_subcommand is None:
        # Run interactive configuration similar to old behavior
        previous = load_config()
        provider = typer.prompt(
            "Provedor (nvidia, ollama ou export)", default=previous.get("provider", "nvidia")
        )
        if provider not in {"nvidia", "ollama", "export"}:
            raise typer.BadParameter("Escolha nvidia, ollama ou export.")
        key = None
        model = None
        if provider == "nvidia":
            console.print(
                "NVIDIA: analyze enviará as evidências da sessão à API oficial. O vault não é enviado."
            )
            model = typer.prompt("Modelo", default=previous.get("model") or NVIDIA_MODEL)
            try:
                configured = bool(nvidia_key())
            except ValueError:
                configured = False
            if not configured or typer.confirm("Substituir a chave NVIDIA já configurada?", default=False):
                key = typer.prompt("Chave de API NVIDIA", hide_input=True, confirmation_prompt=True).strip()
        elif provider == "ollama":
            model = typer.prompt("Modelo Ollama instalado")
        save_config(provider, model, key)
        console.print(
            f"Configuração salva em {config_dir()}. Chave não exibida nem incluída nos relatórios."
        )
        # Optionally prompt for web password
        from sisifo.core.config import set_web_password, web_password_configured
        if not web_password_configured():
            if typer.confirm("Deseja definir senha da interface web agora?"):
                pwd = typer.prompt("Nova senha", hide_input=True, confirmation_prompt=True)
                set_web_password(pwd)
                console.print("Senha da interface web definida.")


@app.command()
def configure(
    provider: str = typer.Option(None, help="Provedor (nvidia, ollama, export)"),
    model: str = typer.Option(None, help="Modelo a utilizar"),
    nvidia_key_input: str = typer.Option(None, "--key", help="Chave NVIDIA (nvapi-...), entrada oculta se omitida"),
    skip_setup: bool = typer.Option(False, "--skip", help="Pular perguntas interativas"),
):
    """Configurar provedor de IA interativamente ou via flags."""
    previous = load_config()
    prov = provider or previous.get("provider", "nvidia")
    if prov not in {"nvidia", "ollama", "export"}:
        raise typer.BadParameter("Provedor inválido. Escolha nvidia, ollama ou export.")
    mdl = model
    key = None
    if prov == "nvidia":
        if not skip_setup:
            console.print("NVIDIA: analyze enviará as evidências da sessão à API oficial. O vault não é enviado.")
            mdl = mdl or typer.prompt("Modelo", default=previous.get("model") or NVIDIA_MODEL)
            key = key or typer.prompt("Chave de API NVIDIA", hide_input=True, confirmation_prompt=True).strip()
        else:
            if not mdl:
                mdl = previous.get("model") or NVIDIA_MODEL
            if not nvidia_key_input:
                # tentar carregar chave existente
                try:
                    key = nvidia_key()
                except Exception:
                    raise typer.BadParameter("Chave NVIDIA não configurada. Use --key ou execute sem --skip.")
            else:
                key = nvidia_key_input
    elif prov == "ollama":
        mdl = mdl or typer.prompt("Modelo Ollama instalado", default=previous.get("model"))
    else:
        mdl = mdl or previous.get("model")
    save_config(prov, mdl, key)
    console.print(f"Configuração salva. Provedor: {prov}, Modelo: {mdl or '-'}")


@app.command()
def status():
    """Mostrar configuração atual sem revelar segredos."""
    cfg = load_config()
    console.print(f"Provedor: {cfg.get('provider', 'export')}; modelo: {cfg.get('model') or '-'}")
    if cfg.get("provider") == "nvidia":
        try:
            nvidia_key()
            console.print("Chave NVIDIA: configurada (não exibida).")
        except Exception:
            console.print("Chave NVIDIA: não configurada.")
