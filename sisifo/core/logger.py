"""Operational events, separate from evidence. Never writes findings."""

import json

from .schema import utcnow
from .session import session_dir


def log_event(session_id: str, event: str, **details):
    with (session_dir(session_id) / "logs/events.jsonl").open("a", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {"time": utcnow().isoformat(), "event": event, **details}, ensure_ascii=False
            )
            + "\n"
        )
