import json

import typer
from rich.console import Console

from sisifo import branding as ui
from sisifo.core.ai_analyzer import analyze_session

console = Console(markup=False)

app = typer.Typer(help="Analisar sessão com provedor de IA configurado.", no_args_is_help=True)


@app.callback(invoke_without_command=True)
def analyze(
    ctx: typer.Context,
    session_id: str = typer.Argument(..., help="ID da sessão"),
    model: str = typer.Option(None, "--model", help="Modelo a utilizar"),
    endpoint: str = typer.Option(None, "--endpoint", help="Endpoint do provedor"),
    provider: str = typer.Option(
        None, "--provider", help="Modo: api ou export; omitido usa a conexão configurada"
    ),
    max_batches: int = typer.Option(50, "--max-batches", help="Máximo de lotes"),
    max_seconds: int = typer.Option(1800, min=1, max=86400),
    token_budget: int = typer.Option(250000, min=1024, max=10000000),
    resume_id: str = typer.Option(None, "--resume", help="Retomar análise pelo ID"),
):
    if ctx.invoked_subcommand is not None:
        return
    with ui.climb("Analisando evidências"):
        result = analyze_session(
            session_id,
            model,
            endpoint,
            provider,
            max_batches,
            max_seconds=max_seconds,
            token_budget=token_budget,
            resume_id=resume_id,
        )
    console.print(json.dumps(result, ensure_ascii=False, indent=2))
    if result.get("status") in {"partial", "cancelled", "failed"}:
        raise typer.Exit(1)
