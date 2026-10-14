"""Persistent single-owner job queue. Restart never repeats external operations."""

import hashlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

from .execution import BudgetExceeded, Cancelled, Control, file_lock
from .redaction import redact
from .session import atomic_write

ACTIVE = {"pending", "running", "cancelling"}


class JobManager:
    def __init__(self, root, workers=2, max_pending=20):
        if not 1 <= workers <= 8:
            raise ValueError("Concorrência deve estar entre 1 e 8.")
        self.root = root / "jobs"
        self.root.mkdir(parents=True, exist_ok=True)
        self._owner = file_lock(self.root / ".owner.lock")
        self._owner.__enter__()
        self._lock = threading.RLock()
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sisifo-job")
        self._controls = {}
        self._closed = False
        self.max_pending = max_pending
        self._jobs = {}
        for path in self.root.glob("*.json"):
            try:
                job = json.loads(path.read_text(encoding="utf-8"))
                if job["id"] != path.stem:
                    continue
                if job["status"] in ACTIVE:
                    job.update(
                        status="interrupted", error="Executor reiniciado; ação não repetida."
                    )
                    self._save(job)
                self._jobs[job["id"]] = job
            except (ValueError, KeyError, OSError):
                continue

    def _save(self, job):
        job["updated_at"] = time.time()
        atomic_write(self.root / f"{job['id']}.json", json.dumps(job, ensure_ascii=False, indent=2))

    def list(self):
        with self._lock:
            return [
                self.get(j["id"])
                for j in sorted(self._jobs.values(), key=lambda j: j["created_at"], reverse=True)[
                    :100
                ]
            ]

    def get(self, job_id):
        with self._lock:
            if job_id not in self._jobs:
                raise ValueError("Job não encontrado.")
            return json.loads(json.dumps(self._jobs[job_id]))

    def submit(self, kind, payload, function, *, key=None, seconds=3600):
        # Payloads are hashed, not persisted: credentials and input data stay out of the ledger.
        digest = hashlib.sha256(json.dumps([kind, payload], sort_keys=True).encode()).hexdigest()
        key_hash = hashlib.sha256(key.encode()).hexdigest() if key else None
        with self._lock:
            if self._closed:
                raise ValueError("Executor encerrando.")
            for old in self._jobs.values():
                if key_hash and old.get("key") == key_hash:
                    if old["digest"] != digest:
                        raise ValueError("Chave de idempotência reutilizada com dados diferentes.")
                    return old["id"]
                if not key_hash and old["digest"] == digest and old["status"] in ACTIVE:
                    return old["id"]
            if sum(j["status"] in ACTIVE for j in self._jobs.values()) >= self.max_pending:
                raise ValueError("Fila cheia; aguarde a conclusão dos jobs.")
            job_id = uuid4().hex
            job = dict(
                id=job_id,
                type=kind,
                status="pending",
                progress="Na fila",
                result=None,
                error=None,
                created_at=time.time(),
                digest=digest,
                key=key_hash,
            )
            self._jobs[job_id] = job
            self._save(job)

            def progress(message, result=None):
                with self._lock:
                    job["progress"] = redact(message)[0]
                    if result is not None:
                        job["result"] = redact(result)[0]
                    self._save(job)

            control = Control(seconds, progress)
            self._controls[job_id] = control
            self._pool.submit(self._run, job, control, function)
            return job_id

    def _run(self, job, control, function):
        try:
            control.check()
            with self._lock:
                job["status"] = "running"
                self._save(job)
            result = function(control)
            with self._lock:
                control.check()
                job["result"] = redact(result)[0]
                state = (
                    result.get("status", "completed") if isinstance(result, dict) else "completed"
                )
                job["status"] = (
                    state
                    if state in {"partial", "failed", "cancelled", "interrupted"}
                    else "completed"
                )
        except (Cancelled, KeyboardInterrupt):
            job.update(status="cancelled", error="Cancelado; resultados parciais preservados.")
        except BudgetExceeded:
            job.update(
                status="partial" if job["result"] else "failed", error="Limite de tempo atingido."
            )
        except Exception:
            job.update(
                status="partial" if job["result"] else "failed",
                error="A operação falhou. Consulte o resultado parcial e o diagnóstico local.",
            )
        finally:
            with self._lock:
                self._save(job)
                self._controls.pop(job["id"], None)

    def cancel(self, job_id):
        with self._lock:
            self.get(job_id)
            if job_id in self._controls:
                self._controls[job_id].cancelled.set()
                self._jobs[job_id]["status"] = "cancelling"
                self._save(self._jobs[job_id])

    def close(self):
        with self._lock:
            self._closed = True
            for control in self._controls.values():
                control.cancelled.set()
        self._pool.shutdown(wait=True)
        self._owner.__exit__(None, None, None)
