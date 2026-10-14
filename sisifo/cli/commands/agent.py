import json
from pathlib import Path

import typer
from rich.console import Console

from sisifo.core import agent

app = typer.Typer(
    help="Agente assistido: planos tipados e execução auditável.", no_args_is_help=True
)
console = Console(markup=False)


@app.command("plan")
def plan(session_id: str, provider: str = "export", model: str = None):
    """Preparar revisão de uma sessão, sem executar ações externas."""
    plan_id = agent.review_plan(session_id, provider, model)
    console.print(f"Plano: {plan_id}\nRevise com: sisifo agent show {plan_id}")


@app.command("import-plan")
def import_plan(path: Path):
    """Validar plano JSON. Nenhum texto do modelo é executado como shell."""
    if path.stat().st_size > 100_000:
        raise typer.BadParameter("Plano excede 100 KB.")
    console.print(agent.save_plan(agent.Plan.model_validate_json(path.read_text(encoding="utf-8"))))


@app.command("show")
def show(plan_id: str):
    data = agent.load_plan(plan_id)
    console.print(data.model_dump_json(indent=2))
    console.print(f"Hash: {agent.digest(data)}")
    console.print("Ferramentas externas: " + ", ".join(s.tool for s in data.steps if s.external))


@app.command("run")
def run(plan_id: str, approve: str = typer.Option(None, help="Hash exato do plano autorizado")):
    data = agent.load_plan(plan_id)
    if any(s.external for s in data.steps) and approve is None:
        show(plan_id)
        if not typer.confirm("Autorizar as ações externas deste plano?", default=False):
            raise typer.Exit(1)
        approve = agent.digest(data)
    result = agent.run_plan(plan_id, approved_digest=approve)
    console.print(json.dumps(result, ensure_ascii=False, indent=2))
    if result["status"] != "completed":
        raise typer.Exit(1)
