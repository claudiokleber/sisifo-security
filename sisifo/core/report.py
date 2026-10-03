import json
import html
import re

from .schema import utcnow
from .session import atomic_write, load_session, verified_findings, session_dir


def plain(text):
    # Keep untrusted tool text from injecting Markdown/HTML report structure.
    value = html.escape(" ".join(str(text).split()), quote=True)
    return re.sub(r"([\\`*_{}\[\]()#+\-.!|~=:])", r"\\\1", value)


def build_report(session_id):
    s = load_session(session_id)
    findings = verified_findings(s)
    report = {
        "schema_version": 1,
        "generated_at": utcnow().isoformat(),
        "session": s.model_dump(mode="json"),
        "findings": [f.model_dump(mode="json") for f in findings],
        "limitations": [
            "Porta aberta não confirma vulnerabilidade.",
            "Alertas das ferramentas requerem revisão; ausência de achados não comprova segurança.",
            "Cobertura limitada aos comandos e execuções registrados.",
        ],
    }
    d = session_dir(session_id)
    atomic_write(d / "reports/report.json", json.dumps(report, ensure_ascii=False, indent=2))
    lines = [
        "# Sísifo — relatório de evidências",
        "",
        f"Sessão: {s.id}",
        f"Projeto: {plain(s.project)}",
        f"Alvo: {plain(s.target)}",
        f"Estado: {s.status}",
        "",
        "## Execuções",
        "",
    ]
    for r in s.runs:
        lines.extend(
            [
                f"- {plain(r.tool)}: **{r.status}**; saída: {r.exit_code}; achados: {r.findings_count}.",
                f"  Imagem: {plain(r.image)} ({plain(r.image_id)}).",
                f"  Evidência: {plain(r.artifact)}; SHA256: {plain(r.artifact_sha256 or 'indisponível')}.",
            ]
        )
        if r.error:
            lines.append("  Erro: " + plain(r.error))
    lines.extend(["", "## Observações e possíveis problemas", ""])
    if not findings:
        lines.append("Nenhum achado normalizado. Consulte o estado das execuções e a cobertura.")
    for f in findings:
        lines.extend(
            [
                f"### Evidência {f.id}",
                f"- Ferramenta: {plain(f.tool)}; ativo: {plain(f.target)}.",
                f"- Classificação: {f.category}; severidade da observação: {f.severity}.",
                f"- Observado: {plain(f.finding)}.",
                f"- Origem: {plain(f.evidence)}.",
                f"- Observado em: {plain(f.observed_at or 'desconhecido')}; registrado em: {plain(f.timestamp)}.",
                "- Medida sugerida: confirmar necessidade da exposição e validar a configuração do serviço."
                if f.tool == "nmap"
                else "- Medida sugerida: reproduzir e revisar o alerta antes de decidir a correção.",
                "",
            ]
        )
    lines += ["## Limitações", *["- " + x for x in report["limitations"]]]
    atomic_write(d / "reports/report.md", "\n".join(lines) + "\n")
    return report


def compare_sessions(before_id, after_id):
    before, after = load_session(before_id), load_session(after_id)
    if (before.project, before.target) != (after.project, after.target):
        raise ValueError("Compare sessões do mesmo projeto e alvo.")
    if before.status != "completed" or after.status != "completed":
        raise ValueError("Comparação requer duas sessões concluídas sem falhas.")
    def coverage(s):
        values = []
        for r in s.runs:
            if r.status != "completed":
                raise ValueError("Comparação requer execuções concluídas.")
            if r.image == "imported-xml":
                if not r.coverage or not r.coverage.get("complete"):
                    raise ValueError("Cobertura importada desconhecida; reimporte XML com args e scaninfo.")
                values.append((r.tool, json.dumps(r.coverage, sort_keys=True)))
            else:
                if not r.image_id:
                    raise ValueError("Cobertura desconhecida: ID da imagem ausente.")
                values.append((r.tool, json.dumps([r.command, r.image_id, s.scope])))
        return sorted(values)
    if coverage(before) != coverage(after):
        raise ValueError("Cobertura diferente: ferramenta, comando ou imagem mudou.")
    def index(s):
        result = {}
        for f in verified_findings(s):
            key = f.identity or f.fingerprint
            if key in result:
                raise ValueError("Identidade de evidência ambígua; comparação recusada.")
            result[key] = f.model_dump(mode="json")
        return result
    a, b = index(before), index(after)
    shared = sorted(a.keys() & b.keys())
    result = {
        "before": before_id,
        "after": after_id,
        "new": [b[k] for k in sorted(b.keys() - a.keys())],
        "not_observed_again": [a[k] for k in sorted(a.keys() - b.keys())],
        "changed": [{"before": a[k], "after": b[k]} for k in shared if a[k]["fingerprint"] != b[k]["fingerprint"]],
        "unchanged": sum(a[k]["fingerprint"] == b[k]["fingerprint"] for k in shared),
        "limitation": "Não observado novamente não significa corrigido; valide a cobertura e o serviço.",
    }
    atomic_write(
        session_dir(after_id) / f"reports/comparison-{before_id}.json",
        json.dumps(result, ensure_ascii=False, indent=2),
    )
    return result
