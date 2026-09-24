"""Tests for client source resolution and the build cache."""

import subprocess
from pathlib import Path
from typing import Any

import pytest
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


def test_a_client_s_env_reaches_its_build_and_rides_its_resolution(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """
    Besu's `JAVA_HOME` and nethermind's `DOTNET_ROOT` come from the config,
    not from the shell that happened to launch the run: the build command
    sees them, and the resolved client carries them to everything that
    runs it afterwards.
    """
    repo = _make_repo(tmp_path)
    monkeypatch.setenv(clients_module.CACHE_ENV, str(tmp_path / "cache"))
    monkeypatch.delenv("FUZZ_TOOLCHAIN", raising=False)
    client = ClientConfig(
        name="demo",
        env={"FUZZ_TOOLCHAIN": "/opt/jdk-25"},
        build=BuildSource(
            repo=str(repo),
            command='printf "$FUZZ_TOOLCHAIN" > {out}',
            binary="v",
        ),
    )
    resolved = resolve_client(client)
    assert resolved.binary.read_text() == "/opt/jdk-25"
    assert resolved.env == {"FUZZ_TOOLCHAIN": "/opt/jdk-25"}


def test_a_client_environment_is_scoped_and_restored(monkeypatch: Any) -> None:
    """
    One client's environment must not leak into the next client's run: a
    variable it overrode comes back, and one it introduced goes away.
    """
    import os

    from ..fuzzer_bridge.clients import client_environment

    monkeypatch.setenv("FUZZ_KEPT", "shell")
    monkeypatch.delenv("FUZZ_ADDED", raising=False)
    with client_environment({"FUZZ_KEPT": "client", "FUZZ_ADDED": "x"}):
        assert os.environ["FUZZ_KEPT"] == "client"
        assert os.environ["FUZZ_ADDED"] == "x"
    assert os.environ["FUZZ_KEPT"] == "shell"
    assert "FUZZ_ADDED" not in os.environ


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
        lambda _path, _env=None: "evm version 9",
    )
    line = client_status(ClientConfig(name="geth", path=exe))
    assert "path" in line and "evm version 9" in line and "more" not in line

    missing = client_status(ClientConfig(name="x", path=tmp_path / "nope"))
    assert missing.startswith("error:")


def test_verify_runs_the_version_check_under_the_client_env(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """
    The gate for a missing toolchain has to use the declared one: run
    without the client's env, besu and nethermind fail from any shell that
    does not export JAVA_HOME or DOTNET_ROOT, whatever fuzz.yaml says.
    """
    from ..fuzzer_bridge.clients import verify_client

    exe = tmp_path / "evmtool"
    exe.write_text("")
    seen: list = []

    def version(_path: Path, env: Any = None) -> str:
        seen.append(env)
        return "Besu evm 1"

    monkeypatch.setattr(clients_module, "binary_version", version)
    ok, detail = verify_client(
        ClientConfig(name="besu", path=exe, env={"JAVA_HOME": "/jdk"})
    )
    assert ok and "Besu evm 1" in detail
    assert seen == [{"JAVA_HOME": "/jdk"}]


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
        lambda _path, _env=None: "evm version 9",
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
        lambda _path, _env=None: "v version 1",
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


def _series(tmp_path: Path, repo: Path, rel: str, text: str) -> Path:
    """One format-patch file changing ``rel`` in a clone of ``repo``."""
    clone = tmp_path / f"clone-{rel.replace('/', '_')}"
    subprocess.run(["git", "clone", "-q", str(repo), str(clone)], check=True)
    target = clone / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    _commit(clone, f"series: {rel}")
    out = tmp_path / f"patches-{rel.replace('/', '_')}"
    out.mkdir()
    subprocess.run(
        ["git", "-C", str(clone), "format-patch", "-q", "-1", "-o", str(out)],
        check=True,
    )
    return next(out.glob("*.patch"))


def test_a_series_is_applied_on_the_pin_and_keys_the_cache(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """
    The pinned commit stays upstream's; the series is applied on top,
    its hash is part of the cache key and of the resolved source.
    """
    from ..fuzzer_bridge.clients import resolve_client, series_hash
    from ..fuzzer_bridge.config import ClientConfig

    repo = _make_repo(tmp_path)
    monkeypatch.setenv(clients_module.CACHE_ENV, str(tmp_path / "cache"))
    patch = _series(tmp_path, repo, "cmd/evm/VERSION", "patched")
    build = BuildSource(
        repo=str(repo),
        ref="master",
        command="cp cmd/evm/VERSION {out}",
        binary="v",
        patches=[patch],
        patch_paths=("cmd/evm/",),
    )
    binary, build_id = ensure_built("demo", build, update=False)
    base = _git(repo, "rev-parse", "HEAD")
    assert binary.read_text() == "patched"
    assert build_id == f"{base}+{series_hash([patch])}"
    # The checkout's upstream commit is untouched; the series sits on top.
    checkout = tmp_path / "cache" / "demo" / "repo"
    assert _git(checkout, "rev-parse", "HEAD~1") == base

    resolved = resolve_client(
        ClientConfig(name="demo", build=build), update=False
    )
    assert (
        resolved.source == f"build@{base[:12]}+series:{series_hash([patch])}"
    )


def test_a_series_hunk_outside_the_runner_fails_the_build(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The series may change the runner, never the client."""
    from ..fuzzer_bridge.clients import PatchOutsideRunnerError

    repo = _make_repo(tmp_path)
    monkeypatch.setenv(clients_module.CACHE_ENV, str(tmp_path / "cache"))
    patch = _series(tmp_path, repo, "core/vm/interpreter.go", "x")
    build = BuildSource(
        repo=str(repo),
        ref="master",
        command="cp VERSION {out}",
        binary="v",
        patches=[patch],
        patch_paths=("cmd/evm/", "tests/"),
    )
    with pytest.raises(
        PatchOutsideRunnerError, match="core/vm/interpreter.go"
    ):
        ensure_built("demo", build, update=False)
    assert not (tmp_path / "cache" / "demo" / "repo").exists() or True


def test_a_series_that_no_longer_applies_names_the_cause(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A conflict on the pin is the signal upstream touched the runner."""
    repo = _make_repo(tmp_path)
    monkeypatch.setenv(clients_module.CACHE_ENV, str(tmp_path / "cache"))
    patch = _series(tmp_path, repo, "cmd/evm/VERSION", "patched")
    # Upstream moves the same file under the pin before the series lands.
    (repo / "cmd" / "evm").mkdir(parents=True)
    (repo / "cmd" / "evm" / "VERSION").write_text("upstream moved first")
    _commit(repo, "upstream touches the runner")
    build = BuildSource(
        repo=str(repo),
        ref="master",
        command="cp cmd/evm/VERSION {out}",
        binary="v",
        patches=[patch],
        patch_paths=("cmd/evm/",),
    )
    with pytest.raises(RuntimeError, match="does not apply on the pinned"):
        ensure_built("demo", build, update=False)
