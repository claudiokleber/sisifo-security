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
    integration,
    network,
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
    set_web_password,
    web_password_configured,
)

console = Console(markup=False)

app = typer.Typer(
    help="Sísifo — evidências, OSINT e análise de segurança. Use sisifo help para exemplos.",
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
app.add_typer(integration.app, name="integration")
app.add_typer(network.app, name="network")


# ----- Top-level commands for backward compatibility -----
@app.command()
def setup():
    """Assistente interativo de configuração (IA e senha web)."""
    from sisifo.cli.commands.ai_console import configure

    configure()
    if not web_password_configured() and sys.stdin.isatty():
        if typer.confirm("Deseja definir senha da interface web agora?"):
            pwd = typer.prompt("Nova senha", hide_input=True, confirmation_prompt=True)
            set_web_password(pwd)
            console.print("Senha da interface web definida.")


@app.command()
def doctor(
    modules: str = typer.Option("nmap,nikto", help="Módulos a verificar (nmap,nikto,metasploit)"),
):
    """Verifica dados e Docker opcional; menu/web funcionam sem Docker."""
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
    except docker.errors.DockerException:
        console.print(
            "Docker indisponível (opcional). Menu, configuração e web local continuam disponíveis."
        )
        console.print("Inicie o Docker somente para executar módulos que usam containers.")
    finally:
        if client:
            client.close()


@app.command()
def repair(
    rollback: bool = typer.Option(False, "--rollback", help="Ativar a versão anterior instalada"),
):
    """Repara launcher/PATH da instalação do usuário; não apaga dados."""
    from sisifo.installation import repair as repair_installation

    try:
        repair_installation(rollback)
    except (ValueError, OSError) as exc:
        console.print(str(exc))
        raise typer.Exit(1) from None


@app.command(name="ai-status")
def ai_status_cmd():
    """Mostrar configuração de IA sem exibir credenciais."""
    from sisifo.core.ai_connection import public_status

    state = public_status()
    console.print(
        f"IA: {'configurada' if state['configured'] else 'desconectada'}; modelo: {state['model'] or '-'}"
    )
    console.print(f"API: {state['endpoint'] or '-'} (status local; sem consulta de conectividade)")


@app.command(name="chat")
def chat_cmd(
    session_id: str = typer.Option(None, "--session", help="Incluir prévia de uma sessão"),
):
    """Conversar com a IA configurada sobre verificações e resultados."""
    from sisifo.cli.commands.ai_console import converse

    converse(session_id)


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


@app.command("help")
def help_cmd():
    """Mostrar comandos e exemplos de uso, incluindo OSINT e IA."""
    console.print("""Sísifo — comandos principais
  sisifo menu                         Abrir menu
  sisifo web                          Abrir interface web local
  sisifo setup                        Configurar conexão de IA
  sisifo chat                         Conversar com a IA
  sisifo osint terminal               Terminal OSINT interativo
  sisifo osint list                   Listar conectores
  sisifo osint config hibp            Configurar chave HIBP (entrada oculta)
  sisifo osint query hibp email usuario@exemplo.com
                                      Consulta direta, sem abrir o assistente
  sisifo osint --help                 Ajuda de OSINT
  sisifo doctor                      Diagnóstico da instalação
  sisifo network --help              Análise de rede
  sisifo --help                      Todos os grupos de comandos
No terminal OSINT: /ajuda, /voltar, /limpar, /sair.
Resultados podem ser selecionados para análise pela IA, com prévia e confirmação separada.
Consultas HIBP dependem da chave e do plano contratado; não há garantia de gratuidade.""")


if __name__ == "__main__":
    app()
