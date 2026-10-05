"""Cooperative cancellation, deadlines and process-owned file locks."""

import os
import threading
import time
from contextlib import contextmanager


class Cancelled(Exception):
    pass


class BudgetExceeded(Exception):
    pass


class Control:
    def __init__(self, seconds=3600, progress=None):
        self.cancelled = threading.Event()
        self.deadline = time.monotonic() + seconds
        self.progress_callback = progress

    def check(self):
        if self.cancelled.is_set():
            raise Cancelled("Cancelado pelo usuário.")
        if time.monotonic() >= self.deadline:
            raise BudgetExceeded("Limite total de tempo atingido.")

    def remaining(self):
        self.check()
        return max(0.01, self.deadline - time.monotonic())

    def progress(self, message, result=None):
        self.check()
        if self.progress_callback:
            self.progress_callback(message, result)


@contextmanager
def file_lock(path):
    path.parent.mkdir(parents=True, exist_ok=True)
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
            raise ValueError("Operação já possui um executor ativo.") from None
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
