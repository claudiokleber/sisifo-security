"""Conservative comparison of coverage declared by imported Nmap XML."""

import shlex
from datetime import UTC, datetime

from defusedxml import ElementTree


def xml_time(value):
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), UTC)
    except (ValueError, OverflowError, OSError):
        raise ValueError("Horário inválido no XML Nmap.") from None


def nmap_metadata(data):
    root = ElementTree.fromstring(data)
    args = root.get("args", "")
    command = shlex.split(args)
    scans = [dict(sorted(x.attrib.items())) for x in root.findall("scaninfo")]
    complete = bool(command and root.get("version") and scans)
    complete = complete and all(
        all(s.get(k) for k in ("type", "protocol", "numservices", "services")) for s in scans
    )
    # Exact argv is intentionally conservative: unknown/custom profiles never compare silently.
    coverage = {
        "source": "declared-import",
        "complete": complete,
        "args": command,
        "scanner_version": root.get("version"),
        "scaninfo": sorted(scans, key=lambda s: str(sorted(s.items()))),
    }
    finished = root.find("runstats/finished")
    return coverage, xml_time(root.get("start")), xml_time(
        finished.get("time") if finished is not None else None
    )
