"""
Provenance record for a differential run.

A divergence is only meaningful against a known spec commit, client
version, and generator version; the manifest pins all three plus the seed
range, so a corpus entry can be reproduced and a report can be trusted.
"""

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

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
    producer: str = ""
    """The transition tool that filled the cases when it was not EELS,
    with its version: a four-month-old evmone would have produced 22%
    "divergences" that were the producer, not the clients."""
    sources: Dict[str, str] = field(default_factory=dict)
    """Where each client binary came from: a path, or `build@<base commit>`
    plus `+series:<hash>` when a patch series was applied on it."""
    binaries: Dict[str, str] = field(default_factory=dict)
    """Per client, a digest of what running its binary executes. A version
    line is what the binary says about itself and a source is how it was
    meant to be built; neither notices a rebuilt cache or a path client
    swapped under the same name, and the digest does."""
    client_env: Dict[str, Dict[str, str]] = field(default_factory=dict)
    """Per client, the environment its toolchain ran under -- a `JAVA_HOME`
    or `DOTNET_ROOT` that would otherwise live only in the shell that
    launched the run."""
    fixture_format: str = "blockchain_test"
    """The one format the run wrote. A verdict is a statement about a
    client's import path or its newPayload path, which are different code,
    so a manifest that did not say which would leave every verdict in it
    ambiguous about what was actually exercised."""

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


def binary_digest(path: Path) -> str:
    """
    A sha256 of what running ``path`` actually executes.

    A plain binary is its own file. A launcher is a symlink into a
    distribution the build lays out beside it as `{out}.<something>` --
    besu's `evmtool` into `evmtool.dist`, nethermind's `nethtest` into
    `nethtest.publish` -- and the launcher script alone would not change
    when a jar or a DLL did, so that whole distribution is hashed.
    """
    if not path.exists():
        return "missing"
    resolved = path.resolve()
    for sibling in sorted(path.parent.glob(path.name + ".*")):
        if sibling.is_dir() and resolved.is_relative_to(sibling.resolve()):
            return "tree:" + _tree_digest(sibling)
    return "file:" + _file_digest(resolved)


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_digest(root: Path) -> str:
    """Every file under ``root`` by relative path, in a stable order."""
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        digest.update(str(path.relative_to(root)).encode())
        digest.update(_file_digest(path).encode())
    return digest.hexdigest()


def collect_manifest(
    fork: Fork,
    tools: Dict[str, Any],
    seeds: range,
    binaries: Optional[Mapping[str, Path]] = None,
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
        binaries={
            name: binary_digest(path)
            for name, path in (binaries or {}).items()
        },
    )
