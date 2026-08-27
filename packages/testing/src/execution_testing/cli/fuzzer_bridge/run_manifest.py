"""
Provenance record for a differential run.

A divergence is only meaningful against a known spec commit, client
version, and generator version; the manifest pins all three plus the seed
range, so a corpus entry can be reproduced and a report can be trusted.
"""

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from execution_testing.forks import Fork
from execution_testing.tools.utility.versioning import (
    get_current_commit_hash_or_tag,
)

from .differential import REFERENCE
from .generator import GENERATOR_VERSION


@dataclass
class RunManifest:
    """What a run compared: spec commit, clients, generator, and seeds."""

    fork: str
    generator_version: int
    eels_commit: str
    clients: Dict[str, str]
    seed_start: int
    count: int
    created: str

    def write(self, path: Path) -> Path:
        """Write the manifest as JSON to ``path``."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2) + "\n")
        return path


def _eels_commit() -> str:
    for directory in Path(__file__).resolve().parents:
        if (directory / ".git").exists():
            return get_current_commit_hash_or_tag(str(directory))
    return "unknown"


def collect_manifest(
    fork: Fork, tools: Dict[str, Any], seeds: range
) -> RunManifest:
    """Record the provenance of a run over ``tools`` and ``seeds``."""
    clients = {
        name: tool.version().splitlines()[0]
        for name, tool in tools.items()
        if name != REFERENCE
    }
    return RunManifest(
        fork=fork.name(),
        generator_version=GENERATOR_VERSION,
        eels_commit=_eels_commit(),
        clients=clients,
        seed_start=seeds.start,
        count=len(seeds),
        created=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
