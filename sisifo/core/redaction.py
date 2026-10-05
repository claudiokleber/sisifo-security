"""Best-effort redaction before external inference; never modifies raw evidence."""

import re

_KEY = re.compile(r"password|passwd|secret|token|authorization|cookie|api[_-]?key", re.I)
_PATTERNS = (
    re.compile(r"nvapi-[A-Za-z0-9_-]+"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/-]+=*"),
    re.compile(r"(?i)(?:password|passwd|api[_-]?key|token|secret)\s*[=:]\s*[^\s&;,\"<>]+"),
    re.compile(r"(?i)https?://[^\s/:]+:[^\s/@]+@"),
    re.compile(r"[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}"),
)


def redact(value):
    """Return a sanitized copy and number of redactions (heuristic, not a DLP guarantee)."""
    count = 0

    def visit(item):
        nonlocal count
        if isinstance(item, dict):
            result = {}
            for key, val in item.items():
                if _KEY.search(str(key)) and val:
                    result[key] = "[REDACTED]"
                    count += 1
                else:
                    result[key] = visit(val)
            return result
        if isinstance(item, list):
            return [visit(v) for v in item]
        if isinstance(item, str):
            for pattern in _PATTERNS:
                item, n = pattern.subn("[REDACTED]", item)
                count += n
        return item

    return visit(value), count
