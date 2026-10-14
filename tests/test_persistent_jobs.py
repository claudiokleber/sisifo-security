import json
import threading
import time

import pytest

from sisifo.core.jobs import JobManager


def wait_job(manager, job_id):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        result = manager.get(job_id)
        if result["status"] not in {"pending", "running", "cancelling"}:
            return result
        time.sleep(0.01)
    raise AssertionError("Job did not finish")


def test_persistence_and_idempotency(tmp_path):
    manager = JobManager(tmp_path, workers=1)
    gate = threading.Event()
    try:
        first = manager.submit(
            "test", {"x": 1}, lambda c: gate.wait(2) and {"ok": True}, key="same"
        )
        assert manager.submit("test", {"x": 1}, lambda c: {}, key="same") == first
        with pytest.raises(ValueError, match="diferentes"):
            manager.submit("test", {"x": 2}, lambda c: {}, key="same")
        gate.set()
        assert wait_job(manager, first)["status"] == "completed"
    finally:
        gate.set()
        manager.close()
    reopened = JobManager(tmp_path)
    try:
        assert reopened.get(first)["result"] == {"ok": True}
    finally:
        reopened.close()


def test_recovery_does_not_execute(tmp_path):
    root = tmp_path / "jobs"
    root.mkdir()
    job_id = "a" * 32
    (root / f"{job_id}.json").write_text(
        json.dumps({"id": job_id, "status": "running", "created_at": 1})
    )
    manager = JobManager(tmp_path)
    try:
        assert manager.get(job_id)["status"] == "interrupted"
    finally:
        manager.close()


def test_single_owner(tmp_path):
    manager = JobManager(tmp_path)
    try:
        with pytest.raises(ValueError, match="ativo"):
            JobManager(tmp_path)
    finally:
        manager.close()


def test_cooperative_cancellation_and_partial_progress(tmp_path):
    manager = JobManager(tmp_path)
    started = threading.Event()

    def task(control):
        control.progress("step 1", {"partial": True})
        started.set()
        while True:
            control.check()
            control.cancelled.wait(0.01)

    try:
        job_id = manager.submit("test", {}, task)
        assert started.wait(2)
        manager.cancel(job_id)
        result = wait_job(manager, job_id)
        assert result["status"] == "cancelled"
        assert result["result"] == {"partial": True}
    finally:
        manager.close()


def test_pending_limit(tmp_path):
    manager = JobManager(tmp_path, workers=1, max_pending=1)
    gate = threading.Event()
    try:
        manager.submit("test", {"n": 1}, lambda c: gate.wait(2))
        with pytest.raises(ValueError, match="Fila cheia"):
            manager.submit("test", {"n": 2}, lambda c: {})
    finally:
        gate.set()
        manager.close()
