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


def test_a_plain_binary_is_digested_as_its_file(tmp_path: Path) -> None:
    """The digest moves with the binary's bytes."""
    from ..fuzzer_bridge.run_manifest import binary_digest

    binary = tmp_path / "evm"
    binary.write_bytes(b"one")
    first = binary_digest(binary)
    assert first.startswith("file:")
    binary.write_bytes(b"two")
    assert binary_digest(binary) != first


def test_a_launcher_is_digested_with_its_whole_distribution(
    tmp_path: Path,
) -> None:
    """
    Besu's `evmtool` is a symlink to a launcher script inside
    `evmtool.dist`; a changed jar leaves the script alone, so hashing the
    script would report the same binary for a different client.
    """
    from ..fuzzer_bridge.run_manifest import binary_digest

    dist = tmp_path / "evmtool.dist"
    (dist / "bin").mkdir(parents=True)
    (dist / "lib").mkdir()
    (dist / "bin" / "evmtool").write_text("#!/bin/sh\nexec java ...\n")
    (dist / "lib" / "besu.jar").write_bytes(b"v1")
    launcher = tmp_path / "evmtool"
    launcher.symlink_to(dist / "bin" / "evmtool")

    first = binary_digest(launcher)
    assert first.startswith("tree:")
    (dist / "lib" / "besu.jar").write_bytes(b"v2")
    assert binary_digest(launcher) != first


def test_an_absent_binary_is_recorded_as_missing(tmp_path: Path) -> None:
    """Never a guess: a binary that is not there says so."""
    from ..fuzzer_bridge.run_manifest import binary_digest

    assert binary_digest(tmp_path / "nothing") == "missing"
