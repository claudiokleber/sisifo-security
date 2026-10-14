"""CLI commands for the integration catalog."""

import json

import typer
from rich.console import Console
from rich.table import Table

from sisifo.core.integration import (
    IntegrationCategory,
    IntegrationStatus,
)
from sisifo.core.integration_registry import create_catalog

console = Console(markup=False)

app = typer.Typer(help="Gerenciar catálogo de integrações.", no_args_is_help=True)


@app.command("list")
def list_cmd(
    status: str = typer.Option(None, "--status", help="Filtrar por status"),
    category: str = typer.Option(None, "--category", help="Filtrar por categoria"),
    json_output: bool = typer.Option(False, "--json", help="Saída em JSON"),
):
    """Listar integrações do catálogo."""
    catalog = create_catalog()
    try:
        status_filter = IntegrationStatus(status) if status else None
    except ValueError:
        raise typer.BadParameter(f"Status inválido: {status}")
    try:
        category_filter = IntegrationCategory(category) if category else None
    except ValueError:
        raise typer.BadParameter(f"Categoria inválida: {category}")

    integrations = catalog.list(status=status_filter, category=category_filter)

    if json_output:
        console.print(
            json.dumps([i.model_dump() for i in integrations], ensure_ascii=False, indent=2)
        )
        return

    if not integrations:
        console.print("Nenhuma integração encontrada.")
        return

    table = Table(title="Catálogo de Integrações")
    table.add_column("ID", style="cyan")
    table.add_column("Nome", style="green")
    table.add_column("Categoria", style="yellow")
    table.add_column("Modo", style="blue")
    table.add_column("Status", style="magenta")
    table.add_column("Versão", style="dim")
    table.add_column("Descrição", style="white", max_width=60)

    for meta in integrations:
        table.add_row(
            meta.id,
            meta.name,
            meta.category.value,
            meta.execution_mode.value,
            meta.status.value,
            meta.version,
            meta.description[:60] + "..." if len(meta.description) > 60 else meta.description,
        )
    console.print(table)


@app.command("show")
def show_cmd(
    integration_id: str = typer.Argument(..., help="ID da integração"),
    json_output: bool = typer.Option(False, "--json", help="Saída em JSON"),
):
    """Mostrar detalhes de uma integração."""
    catalog = create_catalog()
    meta = catalog.get(integration_id)
    if not meta:
        raise typer.BadParameter(f"Integração {integration_id} não encontrada.")

    if json_output:
        console.print(json.dumps(meta.model_dump(), ensure_ascii=False, indent=2))
        return

    console.print(f"[cyan]ID:[/cyan] {meta.id}")
    console.print(f"[cyan]Nome:[/cyan] {meta.name}")
    console.print(f"[cyan]Categoria:[/cyan] {meta.category.value}")
    console.print(f"[cyan]Modo de execução:[/cyan] {meta.execution_mode.value}")
    console.print(f"[cyan]Status:[/cyan] {meta.status.value}")
    console.print(f"[cyan]Versão:[/cyan] {meta.version}")
    console.print(f"[cyan]Descrição:[/cyan] {meta.description}")
    console.print(f"[cyan]Ponto de entrada:[/cyan] {meta.entry_point}")
    console.print(
        f"[cyan]Dependências:[/cyan] {', '.join(meta.dependencies) if meta.dependencies else 'nenhuma'}"
    )
    console.print(f"[cyan]Ambientes suportados:[/cyan] {', '.join(meta.supported_environments)}")
    console.print(
        f"[cyan]Limites de execução:[/cyan] {json.dumps(meta.execution_limits, ensure_ascii=False, indent=2)}"
    )
    console.print(f"[cyan]URL da documentação:[/cyan] {meta.documentation_url or 'não disponível'}")
    console.print(f"[cyan]Criado em:[/cyan] {meta.created_at}")
    console.print(f"[cyan]Atualizado em:[/cyan] {meta.updated_at}")

    if meta.capabilities:
        console.print("\n[bold]Capacidades:[/bold]")
        cap_table = Table()
        cap_table.add_column("Nome", style="cyan")
        cap_table.add_column("Descrição", style="white")
        cap_table.add_column("Tipos de entrada", style="dim")
        cap_table.add_column("Tipos de saída", style="dim")
        cap_table.add_column("Credenciais", style="yellow")
        cap_table.add_column("Docker", style="blue")
        cap_table.add_column("Rede ext.", style="red")
        cap_table.add_column("Rate limit", style="magenta")
        cap_table.add_column("Timeout", style="cyan")
        cap_table.add_column("Externo", style="red")
        cap_table.add_column("Créditos", style="yellow")

        for cap in meta.capabilities:
            cap_table.add_row(
                cap.name,
                cap.description[:60] + "..." if len(cap.description) > 60 else cap.description,
                ", ".join(cap.input_types) if cap.input_types else "-",
                ", ".join(cap.output_types) if cap.output_types else "-",
                "sim" if cap.requires_credentials else "não",
                "sim" if cap.requires_docker else "não",
                "sim" if cap.external_network else "não",
                str(cap.rate_limit) if cap.rate_limit else "-",
                f"{cap.timeout_seconds}s" if cap.timeout_seconds else "-",
                "sim" if cap.external else "não",
                "sim" if cap.consumes_credits else "não",
            )
        console.print(cap_table)


if __name__ == "__main__":
    app()
