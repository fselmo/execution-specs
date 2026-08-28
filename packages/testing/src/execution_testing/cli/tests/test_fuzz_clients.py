"""Tests for client source resolution and the build cache."""

import subprocess
from pathlib import Path
from typing import Any

from click.testing import CliRunner

from ..fuzzer_bridge import clients as clients_module
from ..fuzzer_bridge.cli import fuzz
from ..fuzzer_bridge.clients import (
    client_status,
    ensure_built,
    repo_url,
    resolve_client,
)
from ..fuzzer_bridge.config import BuildSource, ClientConfig


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(
        repo,
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@t",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "-m",
        message,
    )


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "upstream"
    repo.mkdir()
    subprocess.run(
        ["git", "init", "-q", "-b", "master", str(repo)], check=True
    )
    (repo / "VERSION").write_text("1")
    _commit(repo, "one")
    return repo


def test_repo_url_expands_github_shorthand() -> None:
    """`owner/name` means GitHub; anything else is passed through."""
    assert (
        repo_url("ethereum/go-ethereum")
        == "https://github.com/ethereum/go-ethereum"
    )
    assert repo_url("https://x/y.git") == "https://x/y.git"
    assert repo_url("git@github.com:a/b.git") == "git@github.com:a/b.git"


def test_build_is_cached_by_commit(tmp_path: Path, monkeypatch: Any) -> None:
    """A ref is built once per commit; update re-fetches and rebuilds."""
    repo = _make_repo(tmp_path)
    monkeypatch.setenv(clients_module.CACHE_ENV, str(tmp_path / "cache"))
    build = BuildSource(
        repo=str(repo), ref="master", command="cp VERSION {out}", binary="v"
    )

    binary, commit = ensure_built("demo", build, update=False)
    assert binary.name == "v"
    assert binary.read_text() == "1"
    assert commit == _git(repo, "rev-parse", "HEAD")

    (repo / "VERSION").write_text("2")
    _commit(repo, "two")
    assert ensure_built("demo", build, update=False)[0].read_text() == "1"

    binary2, commit2 = ensure_built("demo", build, update=True)
    assert binary2.read_text() == "2"
    assert commit2 == _git(repo, "rev-parse", "HEAD")
    assert commit2 != commit
    assert binary.read_text() == "1"


def test_resolve_path_client(tmp_path: Path) -> None:
    """A path source resolves to itself."""
    exe = tmp_path / "evm"
    exe.write_text("")
    resolved = resolve_client(ClientConfig(name="geth", path=exe))
    assert resolved.binary == exe
    assert resolved.source == "path"


def test_resolve_build_client(tmp_path: Path, monkeypatch: Any) -> None:
    """A build source resolves to the cached artifact, tagged by commit."""
    repo = _make_repo(tmp_path)
    monkeypatch.setenv(clients_module.CACHE_ENV, str(tmp_path / "cache"))
    client = ClientConfig(
        name="demo",
        build=BuildSource(
            repo=str(repo), command="cp VERSION {out}", binary="v"
        ),
    )
    resolved = resolve_client(client)
    assert resolved.binary.read_text() == "1"
    assert resolved.source.startswith("build@")


def test_status_reports_version_or_error(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The status line carries the version, or the error in its place."""
    exe = tmp_path / "evm"
    exe.write_text("")
    monkeypatch.setattr(
        clients_module,
        "binary_version",
        lambda _path: "evm version 9",
    )
    line = client_status(ClientConfig(name="geth", path=exe))
    assert "path" in line and "evm version 9" in line and "more" not in line

    missing = client_status(ClientConfig(name="x", path=tmp_path / "nope"))
    assert missing.startswith("error:")


def test_clients_command_lists_each_client(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """`fuzz clients` prints one line per configured client."""
    exe = tmp_path / "evm"
    exe.write_text("")
    (tmp_path / "fuzz.yaml").write_text(
        f"clients:\n  - name: geth\n    path: {exe}\n"
    )
    monkeypatch.setattr(
        clients_module,
        "binary_version",
        lambda _path: "evm version 9",
    )
    result = CliRunner().invoke(
        fuzz, ["clients", "--config", str(tmp_path / "fuzz.yaml")]
    )
    assert result.exit_code == 0, result.output
    assert "geth" in result.output and "evm version 9" in result.output


def test_status_never_builds_but_update_does(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A status query reports an unbuilt source; only --update builds it."""
    repo = _make_repo(tmp_path)
    cache = tmp_path / "cache"
    monkeypatch.setenv(clients_module.CACHE_ENV, str(cache))
    monkeypatch.setattr(
        clients_module,
        "binary_version",
        lambda _path: "v version 1",
    )
    client = ClientConfig(
        name="demo",
        build=BuildSource(
            repo=str(repo), command="cp VERSION {out}", binary="v"
        ),
    )
    assert client_status(client).startswith("not built")
    assert not cache.exists()
    assert "build@" in client_status(client, update=True)
    assert client_status(client).startswith("build@")
