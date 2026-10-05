"""Explicit export of a session summary to an existing Obsidian vault."""

from pathlib import Path

from .report import build_report, plain
from .session import atomic_write, session_dir


def export_vault(session_id: str, vault: Path) -> Path:
    vault = vault.resolve()
    if not (vault / ".obsidian").is_dir():
        raise ValueError("Destino não parece ser um vault Obsidian existente.")
    report = build_report(session_id)
    s = report["session"]
    target = (vault / "30-Projetos/sisifo/relatorios" / f"{session_id}.md").resolve()
    if not target.is_relative_to(vault):
        raise ValueError("Destino fora do vault.")
    lines = [
        "---",
        f"id: sisifo-report-{session_id}",
        f'title: "Sísifo — sessão {session_id}"',
        "area: projetos",
        "type: relatorio",
        "status: ativo",
        "project: sisifo",
        "tags: [sisifo, evidencias]",
        f"created: {s['started_at']}",
        f"updated: {s['finished_at'] or s['started_at']}",
        "---",
        "",
        f"# Sísifo — sessão {session_id}",
        "",
        f"Projeto: {plain(s['project'])}",
        f"Alvo: {plain(s['target'])}",
        f"Estado: {s['status']}",
        f"Dados completos: `{session_dir(session_id)}`",
        "",
        "## Execuções",
        *[
            f"- {plain(r['tool'])}: {r['status']}; {r['findings_count']} observações."
            for r in s["runs"]
        ],
        "",
        "## Evidências",
        *[
            f"- {f['id']}: {plain(f['finding'])} ({f['category']})."
            for f in report["findings"][:50]
        ],
        "",
        f"Resumo com até 50 de {len(report['findings'])} observações; consulte o relatório completo.",
        "As observações e alertas não confirmam vulnerabilidades sem revisão.",
        "",
    ]
    content = "\n".join(lines)
    if target.exists() and target.read_text(encoding="utf-8") != content:
        raise ValueError(
            "Nota já existe com conteúdo diferente; preserve/revise a versão do vault."
        )
    atomic_write(target, content)
    return target
