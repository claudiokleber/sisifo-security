"""A single Docker executor. Tool containers never receive the Docker socket."""

import hashlib
import io
import os
import tarfile
import time
from contextlib import suppress
from pathlib import Path

import docker
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import ReadTimeout
from urllib3.exceptions import ReadTimeoutError

from .execution import BudgetExceeded, Cancelled
from .logger import log_event
from .modules import select_modules, target_for
from .schema import RunResult, utcnow
from .session import (
    create_session,
    finish_session,
    load_session,
    save_session,
    session_dir,
    session_lock,
    write_findings,
)

MAX_ARTIFACT = 20 * 1024 * 1024


def is_timeout(error):
    """requests may wrap urllib3 read timeouts in ConnectionError."""
    pending, seen = [error], set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, (ReadTimeout, ReadTimeoutError)):
            return True
        if isinstance(current, BaseException):
            pending.extend(current.args)
            pending.extend([current.__cause__, current.__context__])
    return False


def archive_file(container, path):
    stream, _ = container.get_archive(path)
    buf = bytearray()
    for chunk in stream:
        buf.extend(chunk)
        if len(buf) > MAX_ARTIFACT + 1024 * 1024:
            raise ValueError("Artefato excede limite de 20 MiB.")
    with tarfile.open(fileobj=io.BytesIO(buf)) as tar:
        for member in tar.getmembers():
            if member.isfile() and Path(member.name).name == Path(path).name:
                if member.size > MAX_ARTIFACT:
                    raise ValueError("Artefato excede limite de 20 MiB.")
                return tar.extractfile(member).read()
    raise ValueError("Arquivo de resultado ausente no container.")


def new_run(module, target):
    return RunResult(
        tool=module.name,
        image=module.image,
        command=module.command(target),
        stdout=f"raw_output/{module.name}.stdout.txt",
        stderr=f"raw_output/{module.name}.stderr.txt",
        artifact=f"raw_output/{module.artifact}",
        coverage={"source": "docker-run", "network": os.getenv("SISIFO_TOOL_NETWORK", "bridge")},
    )


def execute(module, target, session_id, timeout=600, *, run=None, persist=None, control=None):
    d = session_dir(session_id)
    r = run or new_run(module, target)
    client = container = None
    findings = []
    try:
        client = docker.from_env(timeout=30)
        image = client.images.get(module.image)
        r.image_id = image.id
        if persist:
            persist()
        container = client.containers.run(
            image.id,
            command=r.command,
            detach=True,
            network=os.getenv("SISIFO_TOOL_NETWORK", "bridge"),
            labels={"sisifo.session": session_id, "sisifo.tool": module.name, "sisifo.run": r.id},
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            mem_limit=module.memory_limit,
            pids_limit=128,
            log_config=docker.types.LogConfig(
                type="json-file", config={"max-size": "20m", "max-file": "1"}
            ),
        )
        r.container_id = str(container.id)
        if persist:
            persist()
        try:
            if control is None:
                r.exit_code = container.wait(timeout=timeout)["StatusCode"]
            else:
                deadline = time.monotonic() + timeout
                while True:
                    control.check()
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ReadTimeout("Tool timeout")
                    try:
                        r.exit_code = container.wait(timeout=min(1, remaining))["StatusCode"]
                        break
                    except (ReadTimeout, RequestsConnectionError) as error:
                        if not is_timeout(error):
                            raise
            r.status = "completed" if r.exit_code == 0 else "failed"
            if r.exit_code != 0:
                r.error = f"Ferramenta encerrou com código {r.exit_code}. Consulte stderr."
        except (ReadTimeout, RequestsConnectionError) as error:
            if not is_timeout(error):
                raise
            r.status, r.error = "timeout", f"Tempo limite de {timeout}s atingido."
            container.kill()
        except (KeyboardInterrupt, Cancelled, BudgetExceeded):
            r.status, r.error = "cancelled", "Cancelado pelo usuário."
            container.kill()
        stdout = container.logs(stdout=True, stderr=False)
        stderr = container.logs(stdout=False, stderr=True)
        (d / r.stdout).write_bytes(stdout)
        (d / r.stderr).write_bytes(stderr)
        if len(stdout) > MAX_ARTIFACT or len(stderr) > MAX_ARTIFACT:
            raise ValueError("Saída excede limite de 20 MiB; não interpretada.")
        data = archive_file(container, module.container_file) if module.container_file else stdout
        (d / r.artifact).write_bytes(data)
        r.artifact_sha256 = hashlib.sha256(data).hexdigest()
        if r.status == "completed":
            findings = module.parse(data, target, r.artifact)
            for finding in findings:
                finding.observed_at = utcnow()
                finding.observation_source = "tool-run"
            r.findings_count = len(findings)
    except KeyboardInterrupt:
        r.status, r.error = "cancelled", "Cancelado pelo usuário."
    except Exception as e:  # noqa: BLE001 - persist failure at the plugin boundary
        if r.status not in {"timeout", "cancelled"}:
            r.status = "failed"
        r.error = (r.error + " ") if r.error else ""
        r.error += f"{type(e).__name__}: {e}"
    finally:
        if container is not None:
            with suppress(Exception):
                container.remove(force=True)
        if client is not None:
            with suppress(Exception):
                client.close()
        r.finished_at = utcnow()
    return r, findings


def scan(target, names="nmap", project="default", timeout=600, *, control=None):
    modules = select_modules(names)
    for m in modules:
        m.command(target_for(m, target))  # Validate all inputs before creating a session.
    if timeout < 1 or timeout > 86400:
        raise ValueError("Timeout deve estar entre 1 e 86400 segundos.")
    s = create_session(target, project=project)
    all_findings = []
    with session_lock(s.id):
        for m in modules:
            if control:
                try:
                    control.progress(f"Executando {m.name}", {"session_id": s.id})
                except (Cancelled, BudgetExceeded):
                    s.status = "cancelled"
                    s.finished_at = utcnow()
                    save_session(s)
                    return s
            run = new_run(m, target_for(m, target))
            s.runs.append(run)
            s.tools_run.append(m.name)
            save_session(s)
            log_event(s.id, "module_started", tool=m.name)
            result, findings = execute(
                m, target_for(m, target), s.id, timeout, run=run, persist=lambda: save_session(s),
                **({"control": control} if control else {})
            )
            s.runs[-1] = result
            all_findings.extend(findings)
            s.findings_sha256 = write_findings(s.id, all_findings)
            save_session(s)
            log_event(s.id, "module_finished", tool=m.name, status=result.status)
            if result.status == "cancelled":
                break
        finish_session(s)
    return s


def recover_session(session_id):
    """Reconcile stopped orphan runs. Never kill or restart active containers."""
    with session_lock(session_id):
        s = load_session(session_id)
        if s.status != "running":
            raise ValueError("Somente sessões running podem ser recuperadas.")
        client = docker.from_env(timeout=10)
        try:
            containers = client.containers.list(
                all=True, filters={"label": f"sisifo.session={s.id}"}
            )
            if any(c.status not in {"exited", "dead"} for c in containers):
                raise ValueError("Há container ativo desta sessão; recuperação recusada.")
            for run in s.runs:
                if run.status == "running":
                    run.status = "interrupted"
                    run.finished_at = utcnow()
                    run.error = (
                        "Processo interrompido; resultados desta execução não foram concluídos."
                    )
            s.status = "interrupted"
            s.finished_at = utcnow()
            save_session(s)
            log_event(s.id, "session_recovered", containers_preserved=len(containers))
            return s
        finally:
            client.close()
