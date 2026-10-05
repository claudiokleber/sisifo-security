import json

import typer
from rich.console import Console

from sisifo.core.config import (
    delete_service_config,
    get_service_config_status,
    load_service_config,
    save_service_config,
)
from sisifo.osint import get_connector, list_connectors
from sisifo.osint.contract import QueryType
from sisifo.osint.executor import run_query

console = Console(markup=False)

app = typer.Typer(help="Gerenciar conectores OSINT.", no_args_is_help=True)


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
    qtype: str = typer.Argument(..., help="Tipo de consulta: domain, ip, url, hash"),
    query: str = typer.Argument(..., help="Valor da consulta"),
):
    """Executar uma consulta OSINT (usa configuração salva)."""
    try:
        qt = QueryType(qtype)
    except ValueError:
        raise typer.BadParameter("Tipo inválido. Use domain, ip, url ou hash.")
    try:
        conn = get_connector(connector)
    except KeyError:
        raise typer.BadParameter(f"Conector {connector} não encontrado.")
    cfg = load_service_config(f"osint_{connector}")
    if not conn.validate_config(cfg):
        raise typer.BadParameter("Conector não configurado corretamente.")
    results = run_query(conn, query, qt, cfg)
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
    save_service_config(f"osint_{connector}", cfg)
    console.print(f"Configuração de {connector} salva com sucesso.")