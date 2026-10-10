import json
from typing import Optional

import typer
from rich.console import Console
from rich.prompt import Confirm as RichConfirm
from rich.prompt import InvalidResponse, Prompt
from rich.table import Table

from sisifo.core.config import (
    delete_service_config,
    get_service_config_status,
    load_service_config,
    save_service_config,
)
from sisifo.osint import get_connector, list_connectors
from sisifo.osint.contract import QueryType
from sisifo.osint.executor import OsintExecutionError, run_query
from sisifo.osint.interaction import ai_preview, interpret


class Confirm(RichConfirm):
    choices = ["s", "n"]

    def process_response(self, value):
        value = value.strip().lower()
        if value in ("s", "sim", "y", "yes"):
            return True
        if value in ("n", "não", "nao", "no"):
            return False
        raise InvalidResponse("Responda s para sim ou n para não.")


console = Console(markup=False)

app = typer.Typer(help="OSINT: use sisifo osint terminal para consultas guiadas e interpretação com IA.", no_args_is_help=False)


def _list_connectors_detailed():
    """Show detailed connector list for interactive selection."""
    conns = list_connectors()
    table = Table(title="Escolha um serviço para consultar")
    table.add_column("Opção", style="cyan")
    table.add_column("Nome", style="green")
    table.add_column("Status", style="yellow")
    table.add_column("Tipos de Consulta", style="blue")

    for number, (cid, meta) in enumerate(conns.items(), 1):
        configured = get_connector(cid).validate_config(load_service_config(f"osint_{cid}"))
        status_display = "Pronto" if configured else "Configurar"
        query_types = ", ".join(meta.get("query_types", []))
        table.add_row(f"{number} ({cid})", meta["name"], status_display, query_types)

    console.print(table)
    return conns


def _select_connector(conns: dict) -> Optional[str]:
    """Prompt user to select a connector."""
    if not conns:
        console.print("Nenhum conector disponível.")
        return None

    console.print("\nDigite o número do serviço (ou seu ID). Digite 0 para voltar.")
    while True:
        choice = Prompt.ask("Sua escolha").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(conns):
            return list(conns)[int(choice) - 1]
        if choice.lower() in ("sair", "exit", "quit", "/sair", "0"):
            return None
        if choice.lower() in ("/ajuda", "/limpar", "/voltar"):
            console.print("Escolha o ID do conector. /sair encerra; /voltar retorna; /limpar descarta a seleção. Após a consulta, selecione resultados para a IA.")
            continue
        if choice in conns:
            return choice
        console.print(f"Seleção inválida: conector '{choice}' não encontrado. Tente novamente.")


def _select_query_type(conn) -> Optional[QueryType]:
    """Prompt user to select a query type supported by the connector."""
    supported = conn.meta.query_types
    if not supported:
        console.print("Este conector não suporta nenhum tipo de consulta.")
        return None

    if len(supported) == 1:
        console.print(f"Tipo de consulta: {supported[0].value} (único suportado)")
        return supported[0]

    console.print("\nTipos de consulta suportados:")
    for i, qt in enumerate(supported, 1):
        console.print(f"  {i}. {qt.value}")

    while True:
        choice = Prompt.ask("Selecione o tipo (número ou nome)", default="1").strip()
        if choice.lower() in ("sair", "exit", "quit", "/sair"):
            return None
        # Try as number
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(supported):
                return supported[idx]
        except ValueError:
            pass
        # Try as name
        for qt in supported:
            if qt.value == choice:
                return qt
        console.print("Opção inválida. Tente novamente.")


def _get_query_value(query_type: QueryType) -> Optional[str]:
    """Prompt user for the query value with validation hint."""
    hints = {
        QueryType.EMAIL: "ex.: usuario@dominio.com",
        QueryType.DOMAIN: "ex.: exemplo.com",
        QueryType.IP: "ex.: 192.168.1.1 ou 2001:db8::1",
        QueryType.URL: "ex.: https://exemplo.com/path",
        QueryType.HASH: "ex.: hash MD5/SHA1/SHA256 (32/40/64 chars hex)",
    }
    hint = hints.get(query_type, "")
    console.print(f"\nDigite o valor para consulta ({query_type.value}) {hint}:")
    console.print("Digite 'sair' para cancelar, 'voltar' para escolher outro conector.")

    while True:
        value = Prompt.ask("Valor").strip()
        if value.lower() in ("sair", "exit", "quit", "/sair"):
            return "/sair"
        if value.lower() in ("voltar", "back", "/voltar"):
            return "/voltar"
        if value.lower() in ("/ajuda", "/limpar"):
            console.print("Informe a consulta; /voltar muda o conector; /sair encerra. Nenhuma consulta é enviada antes da confirmação.")
            continue
        if value:
            return value
        console.print("Valor não pode ser vazio.")


def _confirm_query(connector_name: str, query_type: str, query_value: str, connector) -> bool:
    """Show confirmation prompt with details about what will be sent."""
    console.print("\n" + "=" * 60)
    console.print("Resumo da Consulta")
    console.print(f"  Serviço: {connector_name}")
    console.print(f"  Tipo: {query_type}")
    console.print(f"  Valor: {query_value}")
    console.print(f"  Destino: {', '.join(connector.meta.allowed_destinations) if connector.meta.allowed_destinations else 'N/A'}")
    console.print(f"  Credencial: {'Configurada' if connector.validate_config(load_service_config(f'osint_{connector.meta.id}')) else 'Não configurada'}")
    console.print("=" * 60)

    return Confirm.ask("\nConfirmar execução desta consulta?")


def _display_results(results: list, query_value: str):
    """Display query results in a user-friendly format."""
    if not results:
        console.print(f"\nConsulta concluída. O conector não retornou ocorrências para {query_value}.")
        console.print("Isso não garante ausência de exposição; a fonte consultada pode ter cobertura limitada.")
        return

    console.print(f"\nConsulta concluída. Foram encontradas {len(results)} ocorrência(s) para {query_value}.")
    console.print("Isso não confirma que sua senha atual esteja comprometida.\n")

    for i, r in enumerate(results, 1):
        ev = r.evidence
        if r.source != 'hibp':
            console.print(f"{i}. Fonte: {r.source}")
            console.print(json.dumps(ev, ensure_ascii=False, indent=2))
            for warning in r.warnings + r.limitations:
                console.print(warning)
            continue
        console.print(f"{i}. {ev.get('hibp_breach_name', 'Desconhecido')} ({ev.get('hibp_title', 'N/A')})")
        console.print(f"   Domínio: {ev.get('hibp_domain', 'N/A')}")
        console.print(f"   Data da violação: {ev.get('hibp_breach_date', 'N/A')}")
        console.print(f"   Adicionado ao HIBP: {ev.get('hibp_added_date', 'N/A')}")
        console.print(f"   Contas afetadas: {ev.get('hibp_pwn_count', 'N/A'):,}" if ev.get('hibp_pwn_count') else "   Contas afetadas: N/A")
        classes = ev.get('hibp_data_classes', [])
        if classes:
            console.print(f"   Classes de dados: {', '.join(classes)}")
        if ev.get('hibp_is_sensitive'):
            console.print("   [AVISO] Violação sensível - detalhes limitados")
        if ev.get('hibp_is_fabricated'):
            console.print("   [AVISO] Violação fabricada - pode não ser genuína")
        if ev.get('hibp_is_retired'):
            console.print("   [AVISO] Violação aposentada - dados removidos do HIBP")
        if ev.get('hibp_is_malware') or ev.get('hibp_is_stealer_log'):
            console.print("   [ALERTA] Violação de malware/stealer - credenciais roubadas")
        console.print(f"   Referência: {r.reference_url}")
        console.print()


def _interactive_loop():
    """Main interactive loop for OSINT queries."""
    console.print("\nSísifo — Verificação guiada de informações")
    console.print("Passo 1: escolha um serviço. Passo 2: informe a consulta. Passo 3: revise antes de enviar.")
    console.print("A IA é opcional; você pode consultar e ler os resultados sem ela.")
    console.print("Digite /ajuda para comandos, /sair para sair.\n")

    while True:
        try:
            # Show available connectors
            conns = _list_connectors_detailed()

            # Select connector
            connector_id = _select_connector(conns)
            if not connector_id:
                console.print("Saindo...")
                break

            conn = get_connector(connector_id)

            # Check if configured
            cfg = load_service_config(f"osint_{connector_id}")
            if not conn.validate_config(cfg):
                console.print(f"\nConector '{connector_id}' não está configurado.")
                if Confirm.ask("Deseja configurar agora?"):
                    # Reuse config command logic
                    for field in conn.meta.config.fields:
                        prompt_text = f"{field.name}"
                        if field.secret:
                            value = Prompt.ask(prompt_text, password=True)
                        else:
                            value = Prompt.ask(prompt_text)
                        if value:
                            cfg[field.name] = value
                    if conn.validate_config(cfg):
                        save_service_config(f"osint_{connector_id}", cfg)
                        console.print("Configuração salva.")
                    else:
                        console.print("Configuração inválida; nenhum dado salvo.")
                        continue
                else:
                    continue

            # Select query type
            query_type = _select_query_type(conn)
            if not query_type:
                continue

            # Get query value
            while True:
                query_value = _get_query_value(query_type)
                if query_value == "/sair":
                    return
                if query_value == "/voltar":
                    break  # Go back to connector selection

                # Validate query format
                if not conn.validate_query(query_value, query_type):
                    console.print(f"Formato inválido para {query_type.value}. Tente novamente.")
                    continue

                # Confirm and execute
                if _confirm_query(conn.meta.name, query_type.value, query_value, conn):
                    console.print("\nExecutando consulta...")
                    try:
                        results = run_query(conn, query_value, query_type, cfg)
                        _display_results(results, query_value)
                        _offer_interpretation(results)
                    except Exception as e:
                        console.print(f"\nErro na consulta: {e}")
                break  # After execution, go back to connector selection

        except KeyboardInterrupt:
            console.print("\nCancelado pelo usuário (Ctrl+C).")
            if not Confirm.ask("Deseja sair completamente?"):
                continue
            break
        except EOFError:
            break


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """Se nenhum subcomando for dado, abre o modo interativo."""
    if ctx.invoked_subcommand is None:
        _interactive_loop()


@app.command("list")
def list_cmd():
    """Listar conectores disponíveis e status."""
    conns = list_connectors()
    for cid, meta in conns.items():
        status = meta.get("status", "unknown")
        console.print(f"{cid}: {meta['name']} [{status}]")


@app.command("query")
def query_cmd(
    connector: str = typer.Argument(..., help="ID do conector"),
    qtype: str = typer.Argument(..., help="Tipo de consulta: domain, ip, url, hash, email"),
    query: str = typer.Argument(..., help="Valor da consulta"),
):
    """Executar uma consulta OSINT (usa configuração salva)."""
    try:
        qt = QueryType(qtype)
    except ValueError:
        raise typer.BadParameter("Tipo inválido. Use domain, ip, url, hash ou email.")
    try:
        conn = get_connector(connector)
    except KeyError:
        raise typer.BadParameter(f"Conector {connector} não encontrado.")
    cfg = load_service_config(f"osint_{connector}")
    if not conn.validate_config(cfg):
        raise typer.BadParameter("Conector não configurado corretamente.")
    # Validate query type is supported by this connector
    if qt not in conn.meta.query_types:
        raise typer.BadParameter(f"Conector {connector} não suporta tipo de consulta {qtype}. Suportados: {[t.value for t in conn.meta.query_types]}")
    try:
        results = run_query(conn, query, qt, cfg)
    except OsintExecutionError as error:
        console.print(f"Consulta falhou: {error.code}. Confira configuração, limites e disponibilidade.")
        raise typer.Exit(1) from None
    if not results:
        console.print("Nenhum resultado encontrado. Isso não comprova ausência de exposição.")
    for r in results:
        console.print(json.dumps(r.model_dump(), ensure_ascii=False, indent=2))


@app.command("config")
def config_cmd(
    connector: str = typer.Argument(..., help="ID do conector"),
    delete: bool = typer.Option(False, "--delete", help="Remover configuração"),
):
    """Configurar credenciais de um conector OSINT interativamente (entrada oculta para segredos)."""
    try:
        conn = get_connector(connector)
    except KeyError:
        raise typer.BadParameter(f"Conector {connector} não encontrado.")
    if delete:
        deleted = delete_service_config(f"osint_{connector}")
        if deleted:
            console.print(f"Configuração de {connector} removida.")
        else:
            console.print("Nada a remover.")
        return

    # Show current status (fields only)
    status = get_service_config_status(f"osint_{connector}")
    if status["configured"]:
        console.print(f"Campos já configurados: {', '.join(status['fields'])}")
        overwrite = typer.confirm("Deseja sobrescrever?")
        if not overwrite:
            console.print("Operação cancelada.")
            return

    cfg = {}
    for field in conn.meta.config.fields:
        prompt_text = f"{field.name}"
        if field.secret:
            value = typer.prompt(prompt_text, hide_input=True)
        else:
            value = typer.prompt(prompt_text)
        if value:
            cfg[field.name] = value
    if not cfg:
        console.print("Nenhum campo informado.")
        return
    if not conn.validate_config(cfg):
        raise typer.BadParameter("Configuração inválida; nenhum dado foi salvo.")
    save_service_config(f"osint_{connector}", cfg)
    console.print(f"Configuração de {connector} salva com sucesso.")

@app.command("terminal")
def terminal_cmd():
    """Abrir terminal OSINT: consulta guiada, resultados e interpretação opcional pela IA."""
    _interactive_loop()


def _offer_interpretation(results):
    if not results:
        return
    from sisifo.core.ai_connection import public_status
    status = public_status()
    if not status.get('configured'):
        console.print("Consulta disponível sem IA. Use sisifo setup para habilitar interpretação opcional.")
        return
    selection = Prompt.ask("Resultados para interpretar na IA (números separados por vírgula; Enter para voltar)", default="").strip()
    if not selection or selection in ('/voltar', '/sair'):
        return
    try:
        indices = [int(x.strip()) - 1 for x in selection.split(',')]
        preview = ai_preview(results, indices)
        console.print("Prévia exata dos dados selecionados (e-mail da consulta omitido):")
        console.print(preview)
        console.print(f"Destino: {status.get('endpoint', 'IA configurada')} | Modelo: {status.get('model', '')}")
        if Confirm.ask("Autorizar o envio desta prévia à IA?", default=False):
            console.print(interpret(preview)['content'])
    except ValueError as error:
        console.print(str(error))
