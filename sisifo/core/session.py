import hashlib
import json
import os
import re
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from .schema import Finding, Session, utcnow


def data_root() -> Path:
    override = os.getenv("SISIFO_DATA_DIR")
    if override:
        return Path(override).resolve()
    project = Path(__file__).resolve().parents[2]
    if (project / "pyproject.toml").exists() and (project / "data").is_dir():
        return project / "data"
    return (Path.home() / ".sisifo").resolve()


def session_dir(session_id: str, *, must_exist=True) -> Path:
    if not re.fullmatch(r"[a-f0-9]{32}", session_id):
        raise ValueError("ID de sessão inválido; use o ID retornado por scan/import-nmap.")
    root = (data_root() / "sessions").resolve()
    result = (root / session_id).resolve()
    if not result.is_relative_to(root):
        raise ValueError("Sessão fora da pasta de dados.")
    if must_exist and not (result / "session.json").is_file():
        raise ValueError("Sessão não encontrada.")
    return result


def atomic_write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + "." + uuid4().hex + ".tmp")
    try:
        temp.write_text(content, encoding="utf-8")
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def save_session(session: Session):
    atomic_write(
        session_dir(session.id, must_exist=False) / "session.json",
        session.model_dump_json(indent=2),
    )


def create_session(target: str, scope=None, project="default") -> Session:
    if not project.strip() or len(project) > 100:
        raise ValueError("Projeto deve ter de 1 a 100 caracteres.")
    s = Session(target=target, scope=scope or [target], project=project.strip())
    d = session_dir(s.id, must_exist=False)
    d.mkdir(parents=True, exist_ok=False)
    for child in ["logs", "raw_output", "reports", "analysis"]:
        (d / child).mkdir()
    save_session(s)
    s.findings_sha256 = write_findings(s.id, [])
    save_session(s)
    return s


def load_session(session_id: str) -> Session:
    try:
        session = Session.model_validate_json(
            (session_dir(session_id) / "session.json").read_text(encoding="utf-8")
        )
        if session.id != session_id:
            raise ValueError("ID interno da sessão não corresponde à pasta.")
        return session
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"Não foi possível ler a sessão: {e}") from e


def write_findings(session_id: str, findings: list[Finding]):
    # One writer per session; a scan owns its UUID and runs sequentially.
    ids = [f.id for f in findings]
    if len(ids) != len(set(ids)):
        raise ValueError("IDs de evidência duplicados.")
    content = "".join(f.model_dump_json() + "\n" for f in findings)
    atomic_write(
        session_dir(session_id) / "logs/findings.jsonl",
        content,
    )
    # Hash bytes on disk, including the platform's newline representation.
    return hashlib.sha256(
        (session_dir(session_id) / "logs/findings.jsonl").read_bytes()
    ).hexdigest()


def read_findings(session_id: str) -> list[Finding]:
    p = session_dir(session_id) / "logs/findings.jsonl"
    if not p.exists():
        raise ValueError("Integridade: arquivo de achados ausente.")
    results = []
    with p.open(encoding="utf-8") as f:
        for number, line in enumerate(f, 1):
            if line.strip():
                try:
                    results.append(Finding.model_validate_json(line))
                except ValueError as e:
                    raise ValueError(f"Achado inválido na linha {number} de {p.name}") from e
    return results


def verified_findings(s: Session) -> list[Finding]:
    if s.status == "running":
        raise ValueError("Sessão em execução; aguarde ou use session recover após interrupção.")
    if s.status == "completed" and (not s.runs or any(r.status != "completed" for r in s.runs)):
        raise ValueError("Integridade: estado da sessão diverge das execuções.")
    findings = read_findings(s.id)
    directory = session_dir(s.id)
    digest = hashlib.sha256((directory / "logs/findings.jsonl").read_bytes()).hexdigest()
    if s.findings_sha256 and digest != s.findings_sha256:
        raise ValueError("Integridade: hash dos achados divergente.")
    if len({f.id for f in findings}) != len(findings):
        raise ValueError("Integridade: IDs de evidência duplicados.")
    counts = Counter((f.tool, f.evidence) for f in findings)
    expected = Counter()
    for run in s.runs:
        expected[(run.tool, run.artifact)] += run.findings_count
        if run.status == "completed" and (not run.artifact or not run.artifact_sha256):
            raise ValueError("Integridade: execução concluída sem artefato/hash.")
        if run.artifact_sha256:
            path = (directory / run.artifact).resolve()
            if not path.is_relative_to(directory) or not path.is_file():
                raise ValueError("Integridade: artefato ausente ou fora da sessão.")
            if hashlib.sha256(path.read_bytes()).hexdigest() != run.artifact_sha256:
                raise ValueError("Integridade: hash do artefato divergente.")
    if counts != +expected:
        raise ValueError("Integridade: contagem/referências dos achados divergem das execuções.")
    return findings


@contextmanager
def session_lock(session_id):
    """OS lock released on process death, shared by scan and recovery."""
    path = session_dir(session_id) / ".writer.lock"
    with path.open("a+b") as handle:
        if path.stat().st_size == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ValueError("Sessão possui um escritor ativo; recuperação recusada.") from None
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def finish_session(s: Session):
    statuses = [r.status for r in s.runs]
    s.status = (
        "cancelled"
        if "cancelled" in statuses
        else "completed"
        if statuses and all(x == "completed" for x in statuses)
        else "partial"
        if "completed" in statuses
        else "failed"
    )
    s.finished_at = utcnow()
    save_session(s)
