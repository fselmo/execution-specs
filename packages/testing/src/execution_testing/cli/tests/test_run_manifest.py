"""Tests for the per-run provenance manifest."""

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from ..fuzzer_bridge import run_manifest as manifest_module
from ..fuzzer_bridge.run_manifest import collect_manifest


def test_manifest_records_provenance(tmp_path: Path, monkeypatch: Any) -> None:
    """The manifest pins spec commit, client versions, and the seed range."""
    monkeypatch.setattr(
        manifest_module,
        "get_current_commit_hash_or_tag",
        lambda *_args: "abc123",
    )
    tools = {
        "eels": object(),
        "geth": SimpleNamespace(version=lambda: "evm version 1.17.6\nextra"),
    }
    fork: Any = SimpleNamespace(name=lambda: "Osaka")
    manifest = collect_manifest(fork, tools, range(5, 15))
    path = manifest.write(tmp_path / "manifest.json")
    data = json.loads(path.read_text())
    assert data["fork"] == "Osaka"
    assert data["eels_commit"] == "abc123"
    assert data["clients"] == {"geth": "evm version 1.17.6"}
    assert data["seed_start"] == 5
    assert data["count"] == 10
    assert data["generator_version"] == manifest.generator_version
    assert data["created"].endswith("Z")
