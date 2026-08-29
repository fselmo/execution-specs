"""Persist and trend `mutate` reach numbers across runs."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence

if TYPE_CHECKING:
    from .runner import ShapeResult


def summary_data(path: Path) -> Optional[Dict[str, Any]]:
    """Return the parsed `fuzz diff --summary-json` object, or None."""
    if not path.exists():
        return None
    return json.loads(path.read_text())


def reach_record(
    result: ShapeResult,
    *,
    fork: str,
    eels_commit: str,
    timestamp: str,
) -> Dict[str, Any]:
    """Flatten a shape result into one trendable reach record."""
    from .runner import Verdict

    summary = result.summary or {}
    return {
        "timestamp": timestamp,
        "eels_commit": eels_commit,
        "fork": fork,
        "shape": result.shape.name,
        "verdict": result.verdict.value,
        "killed": result.verdict is Verdict.KILLED_DIFFERENTIAL,
        "generator_version": summary.get("generator_version"),
        "seeds": summary.get("seeds"),
        "diverged": summary.get("diverged"),
        "first_kill_seed": summary.get("first_divergent_seed"),
    }


def append_reach_log(records: Sequence[Dict[str, Any]], path: Path) -> None:
    """Append one JSON line per record, creating the file if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


def reach_trend(path: Path) -> str:
    """Render the reach log grouped by shape, oldest run first."""
    by_shape: Dict[str, List[Dict[str, Any]]] = {}
    for line in path.read_text().splitlines():
        record = json.loads(line)
        if "shape" not in record:
            continue  # other kinds (e.g. event-rates) trend elsewhere
        by_shape.setdefault(record["shape"], []).append(record)
    lines = []
    for shape in sorted(by_shape):
        cells = " ".join(
            f"{r['diverged']}/{r['seeds']}" for r in by_shape[shape]
        )
        lines.append(f"{shape}: {cells}")
    return "\n".join(lines)


def eels_commit() -> str:
    """Return the repo HEAD short hash, or 'unknown' on failure."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, OSError):
        return "unknown"
