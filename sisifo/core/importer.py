import hashlib
from pathlib import Path

from sisifo.modules.nmap.module import parse

from .coverage import nmap_metadata
from .schema import RunResult, utcnow
from .session import create_session, finish_session, session_dir, write_findings


def import_nmap(path: Path, target: str, project="default"):
    if path.stat().st_size > 20 * 1024 * 1024:
        raise ValueError("XML excede 20 MiB.")
    raw = path.read_bytes()
    findings = parse(raw, target, "raw_output/nmap.xml")
    coverage, observed_start, observed_end = nmap_metadata(raw)
    for f in findings:
        f.observed_at = observed_end or observed_start
        f.observation_source = "imported-xml" if f.observed_at else "unknown"
    s = create_session(target, project=project)
    (session_dir(s.id) / "raw_output/nmap.xml").write_bytes(raw)
    s.findings_sha256 = write_findings(s.id, findings)
    s.tools_run = ["nmap"]
    s.runs = [
        RunResult(
            tool="nmap",
            image="imported-xml",
            command=["import-nmap"],
            coverage=coverage,
            imported_at=utcnow(),
            source_started_at=observed_start,
            source_finished_at=observed_end,
            status="completed",
            exit_code=0,
            finished_at=utcnow(),
            artifact="raw_output/nmap.xml",
            artifact_sha256=hashlib.sha256(raw).hexdigest(),
            findings_count=len(findings),
        )
    ]
    finish_session(s)
    return s
