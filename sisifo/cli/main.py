import sys
import webbrowser  # noqa: F401

import typer
from rich.console import Console

# Import sub-apps from command modules
from sisifo.cli.commands import (
    agent,
    analyze,
    compare,
    import_nmap,
    osint,
    report,
    scan,
    session,
    setup_web,
    vault,
    web,
)
from sisifo.cli.commands import (
    modules as modules_cmd,
)

# core config functions
from sisifo.core.config import (
    NVIDIA_MODEL,
    config_dir,
    load_config,
    nvidia_key,
    save_config,
    set_web_password,
    web_password_configured,
)

console = Console(markup=False)

app = typer.Typer(
    help="Sísifo — containers, evidências e relatórios de segurança.",
    no_args_is_help=False,
    invoke_without_command=True,
)

# Compose CLI sub-apps
app.add_typer(agent.app, name="agent")
app.add_typer(scan.app, name="scan")
app.add_typer(report.app, name="report")
app.add_typer(analyze.app, name="analyze")
app.add_typer(import_nmap.app, name="import-nmap")
app.add_typer(compare.app, name="compare")
app.add_typer(session.app, name="session")
app.add_typer(modules_cmd.app, name="modules")
app.add_typer(setup_web.app, name="setup-web")
app.add_typer(osint.app, name="osint")
app.add_typer(web.app, name="web")
app.add_typer(vault.app, name="export-vault")


# ----- Top-level commands for backward compatibility -----
@app.command()
def setup():
    """Assistente interativo de configuração (IA e senha web)."""
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
    if not web_password_configured() and sys.stdin.isatty():
        if typer.confirm("Deseja definir senha da interface web agora?"):
            pwd = typer.prompt("Nova senha", hide_input=True, confirmation_prompt=True)
            set_web_password(pwd)
            console.print("Senha da interface web definida.")


@app.command()
def doctor(
    modules: str = typer.Option("nmap,nikto", help="Módulos a verificar (nmap,nikto,metasploit)"),
):
    """Verifica Docker e imagens necessárias."""
    import docker

    from sisifo.core import session as store
    from sisifo.core.modules import select_modules

    console.print(f"Dados: {store.data_root()}")
    client = None
    try:
        client = docker.from_env(timeout=10)
        client.ping()
        console.print("Docker: disponível")
        missing = False
        for m in select_modules(modules):
            try:
                img = client.images.get(m.image)
                console.print(f"{m.name}: {img.id}")
            except docker.errors.ImageNotFound:
                console.print(f"{m.name}: imagem ausente ({m.image})")
                missing = True
        if missing:
            raise typer.Exit(1)
    except docker.errors.DockerException as e:
        console.print(f"Docker indisponível: {e}")
        raise typer.Exit(1)
    finally:
        if client:
            client.close()


@app.command(name="ai-status")
def ai_status_cmd():
    """Mostrar configuração de IA sem exibir credenciais."""
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


@app.command()
def menu():
    """Menu interativo do Sísifo."""
    from sisifo.cli.commands.menu import menu as run_menu
    run_menu()


# expose for tests
existing_web = web.existing_web


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """Se nenhum subcomando for dado e estivermos em terminal interativo, abre o menu."""
    if ctx.invoked_subcommand is None:
        if sys.stdin.isatty():
            menu()
        else:
            console.print(ctx.get_help())
            raise typer.Exit()


if __name__ == "__main__":
    app()
