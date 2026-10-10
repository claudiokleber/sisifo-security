
"""
Interactive menu for Sísifo.
Provides a Rich‑based terminal UI with ASCII banner, navigation and submenus.
"""

import os
import subprocess
import sys

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import IntPrompt, Prompt
from rich.table import Table

from sisifo import branding as ui
from sisifo.cli.commands.web import existing_web

# Internal services
from sisifo.core import session as store
from sisifo.core.ai_analyzer import analyze_session
from sisifo.core.config import (
    config_dir,
    load_config,
)
from sisifo.core.modules import registry
from sisifo.core.orchestrator import scan as execute_scan
from sisifo.core.report import build_report, compare_sessions

console = Console()

# ---------------------------------------------------------------------------
# Terminal branding
# ---------------------------------------------------------------------------

def _use_colors() -> bool:
    """Respect NO_COLOR and non‑tty output."""
    if "NO_COLOR" in os.environ:
        return False
    return sys.stdout.isatty()

def _print_banner(version: str) -> None:
    ui.banner(version)

# ---------------------------------------------------------------------------
# Helper – run a sub‑command function and show result
# ---------------------------------------------------------------------------
def _run_and_show(func, *args, **kwargs):
    try:
        labels = {execute_scan: "Coletando evidências", analyze_session: "Analisando evidências",
                  build_report: "Gerando relatório"}
        if func in labels:
            with ui.climb(labels[func]):
                result = func(*args, **kwargs)
        else:
            result = func(*args, **kwargs)
        status = result.get("status") if isinstance(result, dict) else getattr(result, "status", None)
        (ui.warn if status in {"failed", "partial", "cancelled"} else ui.ok)(f"Estado: {status or 'concluído'}")
        if result:
            console.print(result)
        return result
    except typer.Exit as e:
        if e.exit_code != 0:
            ui.error(f"Erro (código {e.exit_code})")
    except Exception as exc:  # pragma: no cover – safety net
        ui.error(f"Erro inesperado: {exc}")

# ---------------------------------------------------------------------------
# Sub‑menu implementations
# ---------------------------------------------------------------------------

def _submenu_executar():
    ui.section("Executar ferramentas")
    mods = registry()
    if not mods:
        console.print("Nenhum módulo registrado.")
        return

    table = Table(box=box.SIMPLE)
    table.add_column("#", style="white")
    table.add_column("Módulo", style="bold")
    table.add_column("Descrição")
    for i, (name, mod) in enumerate(mods.items(), 1):
        table.add_row(str(i), name, getattr(mod, "description", ""))
    console.print(table)

    choice = IntPrompt.ask("Escolha o módulo (0 = voltar)", default=0)
    if choice == 0:
        return
    if not 1 <= choice <= len(mods):
        ui.warn("Seleção inválida.")
        return
    mod_name = list(mods.keys())[choice - 1]

    target = Prompt.ask("Alvo (IP, CIDR, hostname ou URL)")
    project = Prompt.ask("Projeto", default="default")
    timeout = IntPrompt.ask("Timeout (s)", default=600)

    console.print(Panel(f"[bold]Resumo[/bold]\nMódulo: {mod_name}\nAlvo: {target}\nProjeto: {project}\nTimeout: {timeout}s", title="Confirmação"))
    if not typer.confirm("Iniciar execução?"):
        ui.info("Cancelado.")
        return

    result = _run_and_show(execute_scan, target, mod_name, project, timeout)
    if result:
        build_report(result.id)
        console.print(f"Sessão: {result.id}; relatório: {store.session_dir(result.id) / 'reports/report.md'}")

def select_session():
    root = store.data_root() / "sessions"
    project = Prompt.ask("Filtro de projeto (Enter = todos; 0 = voltar)", default="")
    if project == "0":
        return None
    status = Prompt.ask("Filtro de estado (Enter = todos)", default="")
    sessions = []
    for path in sorted(root.iterdir(), reverse=True) if root.exists() else []:
        if path.is_dir():
            try:
                session = store.load_session(path.name)
                if (not project or project == session.project) and (not status or status == session.status):
                    sessions.append(session)
            except ValueError:
                console.print(f"Sessão inválida ignorada: {path.name}", markup=False)
    page = 0
    while True:
        selected = sessions[page * 10:(page + 1) * 10]
        if not selected:
            console.print("Nenhuma sessão encontrada.")
            return None
        table = Table("#", "ID", "Projeto", "Alvo", "Estado", box=box.SIMPLE)
        for i, session in enumerate(selected, 1):
            table.add_row(str(i), session.id, session.project, session.target, session.status)
        console.print(table)
        choice = Prompt.ask("Sessão; n = próxima; p = anterior; 0 = voltar", default="0")
        if choice == "0":
            return None
        if choice == "n":
            if (page + 1) * 10 < len(sessions):
                page += 1
        elif choice == "p":
            page = max(0, page - 1)
        elif choice.isdigit() and 1 <= int(choice) <= len(selected):
            return selected[int(choice) - 1].id
        else:
            console.print("Seleção inválida.")


def _submenu_sessoes():
    session_id = select_session()
    if not session_id:
        return
    while True:
        choice = Prompt.ask("[1] Detalhes [2] Integridade [3] Recuperar [0] Voltar", choices=["0", "1", "2", "3"], default="0")
        if choice == "0":
            return
        session = store.load_session(session_id)
        if choice == "1":
            console.print(f"Sessão: {session.id}\nProjeto: {session.project}\nAlvo: {session.target}\nEstado: {session.status}", markup=False)
        elif choice == "2":
            findings = store.verified_findings(session)
            console.print(f"Integridade verificada: {len(findings)} evidências.")
        else:
            from sisifo.core.orchestrator import recover_session
            _run_and_show(recover_session, session_id)


def _submenu_relatorios():
    ui.section("Relatórios")
    sess_id = select_session()
    if not sess_id:
        return
    try:
        report = _run_and_show(build_report, sess_id)
        if report is None:
            return
        path = store.session_dir(sess_id) / "reports/report.md"
        console.print(f"Arquivo: {path}")
        if typer.confirm("Abrir no visualizador padrão?"):
            os.startfile(path) if os.name == "nt" else subprocess.run(["open" if sys.platform == "darwin" else "xdg-open", str(path)], check=True)
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")

    if typer.confirm("Comparar com outra sessão?"):
        other = Prompt.ask("ID da outra sessão")
        _run_and_show(compare_sessions, sess_id, other)

def _submenu_ia():
    ui.section("Análise com IA")
    from sisifo.core.ai_connection import public_status
    state = public_status()
    console.print(f"Modelo: {state['model'] or 'não configurado'}")
    choice = Prompt.ask("[1] Conversar [2] Analisar sessão [3] Conectar IA [0] Voltar",
                        choices=["0", "1", "2", "3"], default="1")
    if choice == "0":
        return
    if choice == "3":
        from sisifo.cli.commands.ai_console import configure
        configure()
        return
    if choice == "1":
        from sisifo.cli.commands.ai_console import converse
        session = select_session() if typer.confirm("Incluir evidências de uma sessão?", default=False) else None
        converse(session)
        return
    cfg = load_config()

    sess_id = select_session()
    if not sess_id:
        return
    provider = cfg.get("provider", "export")
    model = Prompt.ask("Modelo (opcional)", default=cfg.get("model") or "")
    max_batches = IntPrompt.ask("Máx. lotes", default=50)

    from sisifo.core.ai_analyzer import prepare_batches
    preview = prepare_batches(sess_id)
    console.print(f"Prévia local: {store.session_dir(sess_id) / 'analysis/ai-input.json'}")
    console.print(f"Mascaramentos: {preview['redaction']['count']} (heurístico; revise a prévia)")
    console.print("Exportação local, sem API." if provider == "export" else "Evidências serão enviadas ao provedor. Revise antes de autorizar.")
    if not typer.confirm("Continuar?"):
        return
    action = Prompt.ask("[1] Analisar [2] Criar plano do agente [0] Voltar", choices=["0", "1", "2"], default="0")
    if action == "1":
        _run_and_show(analyze_session, sess_id, model or None, None, provider, max_batches)
    elif action == "2":
        from sisifo.core.agent import review_plan
        plan_id = review_plan(sess_id, provider, model or None)
        console.print(f"Plano salvo. Revise: sisifo agent show {plan_id}; execute: sisifo agent run {plan_id}")

def _submenu_osint():
    from sisifo.cli.commands.osint import terminal_cmd
    terminal_cmd()


def _submenu_web():
    ui.section("Interface web")
    if existing_web(8000):
        console.print("Sísifo web já está em execução em http://127.0.0.1:8000")
        open_browser = Prompt.ask("Abrir no navegador?", choices=["s","n"], default="n")
        if open_browser == "s":
            import webbrowser
            webbrowser.open("http://127.0.0.1:8000")
        return
    port = IntPrompt.ask("Porta (0 = voltar)", default=0)
    if port == 0:
        return
    try:
        from sisifo.cli.commands.web import start_web
        start_web(port=port, no_browser=False)
    except typer.Exit as e:
        if e.exit_code != 0:
            console.print(f"[red]Erro ao iniciar web (código {e.exit_code})[/red]")

def _submenu_config():
    while True:
        ui.section("Configurações")
        console.print("[1] IA e modelo")
        console.print("[2] Senha da interface web")
        console.print("[3] Credenciais OSINT")
        console.print("[4] Diretórios efetivos")
        console.print("[0] Voltar")
        opt = Prompt.ask("Opção", choices=["1","2","3","4","0"], default="0")
        if opt == "0":
            return
        if opt == "1":
            from sisifo.cli.commands.setup import setup as setup_cmd
            _run_and_show(setup_cmd)
        elif opt == "2":
            from sisifo.cli.commands.setup_web import set_password as set_web_cmd
            _run_and_show(set_web_cmd)
        elif opt == "3":
            from sisifo.cli.commands.osint import config_cmd
            conn = Prompt.ask("ID do conector")
            _run_and_show(config_cmd, connector=conn, delete=False)
        elif opt == "4":
            console.print(f"Dados: {store.data_root()}")
            console.print(f"Config: {config_dir()}")

def _submenu_diagnostico():
    ui.section("Diagnóstico")
    # Docker
    try:
        import docker
        client = docker.from_env(timeout=5)
        client.ping()
        ui.ok("Docker OK")
        for name, mod in registry().items():
            try:
                img = client.images.get(mod.image)
                console.print(f"  {name}: {img.id}")
            except docker.errors.ImageNotFound:
                console.print(f"  {name}: imagem ausente ({mod.image})")
    except Exception as exc:
        ui.error(f"Docker indisponível: {exc}", "Inicie o Docker Desktop e execute sisifo doctor.")
    # Porta web
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 8000))
        console.print("Porta 8000 livre")
    except OSError:
        console.print("Porta 8000 ocupada")

# ---------------------------------------------------------------------------
# Main menu loop
# ---------------------------------------------------------------------------

def menu() -> None:
    """Entry point used by `sisifo menu` and by the no‑args callback."""
    ver = ui.package_version()

    # navigation map: key -> (title, callable)
    NAV = {
        "1": ("Executar ferramentas", _submenu_executar),
        "2": ("Sessões e evidências", _submenu_sessoes),
        "3": ("Relatórios", _submenu_relatorios),
        "4": ("Análise com IA", _submenu_ia),
        "5": ("OSINT", _submenu_osint),
        "6": ("Interface web", _submenu_web),
        "7": ("Configurações", _submenu_config),
        "8": ("Diagnóstico", _submenu_diagnostico),
        "9": ("Ajuda e comandos", _submenu_ajuda),
        "0": ("Sair", None),
    }

    console.no_color = not _use_colors()
    while True:
        _print_banner(ver)

        cfg = load_config()
        ai_status = "conectada" if cfg.get("provider", "export") != "export" else "offline"
        web_status = "em execução" if existing_web(8000) else "não identificada na porta 8000"
        data_dir = str(store.data_root())
        mode = "Docker" if os.getenv("SISIFO_DATA_DIR") == "/data" else "Nativo"

        ui.panel([
            ("Versão", ver),
            ("IA", f"{ai_status} ({cfg.get('model') or '-'})"),
            ("Web", web_status),
            ("Dados", data_dir),
            ("Modo", mode),
        ])
        ui.menu([(key, title) for key, (title, _) in NAV.items()])

        try:
            choice = ui.prompt(list(NAV.keys()), default="0")
        except (KeyboardInterrupt, EOFError, typer.Abort):
            return
        if choice == "0":
            ui.info("Até logo!")
            break
        action = NAV[choice][1]
        if action is None:
            continue
        try:
            action()
        except KeyboardInterrupt:
            ui.info("Cancelado")
        except (EOFError, typer.Abort):
            ui.info("Encerrado")
            break
        except (ValueError, OSError) as error:
            ui.error(str(error))
        if choice == "6":
            break
        console.print()

def _submenu_ajuda():
    ui.section("Ajuda e comandos")
    help_text = """
Comandos principais (disponíveis após instalação no PATH):

  sisifo agent plan <SESSION_ID>  Cria revisão assistida local
  sisifo agent show <PLAN_ID>    Exibe plano antes da execução
  sisifo agent run <PLAN_ID>     Executa plano revisado
  sisifo --help                Mostra esta ajuda
  sisifo menu                  Abre este menu interativo
  sisifo doctor                Verifica Docker e imagens
  sisifo session list          Lista sessões
  sisifo modules               Lista módulos registrados
  sisifo setup                 Conecta API e seleciona modelo
  sisifo setup-web             Define senha da interface web
  sisifo web                   Inicia a UI web local
  sisifo osint terminal        Terminal OSINT com interpretação opcional pela IA
  sisifo osint list            Lista conectores OSINT
  sisifo osint config hibp     Configura a chave HIBP
  sisifo help                  Exemplos e ajuda geral

Exemplos de uso:

  sisifo scan <ALVO_AUTORIZADO> --modules nmap --project lab
  sisifo report <SESSION_ID>
  sisifo chat --session <SESSION_ID>
  sisifo osint query dummy domain example.com

Para mais detalhes use:  sisifo <comando> --help
"""
    console.print(Panel(help_text.strip(), title="Comandos", expand=False))
    Prompt.ask("Pressione Enter para voltar", default="")