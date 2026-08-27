"""
Client pool: turn `fuzz.yaml` client entries into runnable binaries.

A path source is used as-is. A build source is cloned once, its ref
resolved to a commit, and the artifact built into a commit-keyed cache
directory, so switching a client between branches never rebuilds what is
already there and a run can always say which commit it compared against.
"""

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from .config import BuildSource, ClientConfig
from .differential import build_client_tool

CACHE_ENV = "EELS_FUZZ_CACHE"


def cache_root() -> Path:
    """Directory holding client checkouts and built artifacts."""
    return Path(
        os.environ.get(CACHE_ENV, Path.home() / ".cache" / "eels-fuzz")
    )


def repo_url(repo: str) -> str:
    """Expand `owner/name` to a GitHub URL; pass anything else through."""
    if "://" in repo or repo.startswith("git@") or Path(repo).exists():
        return repo
    return f"https://github.com/{repo}"


class NotBuiltError(Exception):
    """A build source has no cached artifact for its ref yet."""

    def __init__(self, name: str) -> None:
        super().__init__(
            f"client {name!r} is not built yet; run `fuzz clients --update`"
        )


@dataclass
class ResolvedClient:
    """A client ready to run: its binary and where it came from."""

    name: str
    binary: Path
    source: str


def _git(repo_dir: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo_dir), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def ensure_built(
    name: str,
    build: BuildSource,
    *,
    update: bool = False,
    build_missing: bool = True,
) -> Tuple[Path, str]:
    """
    Return the built artifact for ``build`` and the commit it came from.

    The ref is resolved to a commit on first use and again on ``update``;
    each commit is built at most once. With ``build_missing`` false,
    anything not already cached raises ``NotBuiltError`` instead of
    fetching or building -- for status queries that must stay fast.
    """
    assert build.repo and build.command and build.binary
    build_missing = build_missing or update
    root = cache_root() / name
    repo_dir = root / "repo"
    if not repo_dir.exists():
        if not build_missing:
            raise NotBuiltError(name)
        root.mkdir(parents=True, exist_ok=True)
        url = repo_url(build.repo)
        partial = ["--filter=blob:none"] if not Path(url).exists() else []
        subprocess.run(
            ["git", "clone", "--quiet", *partial, url, str(repo_dir)],
            check=True,
        )

    marker = root / f"ref-{build.ref.replace('/', '_')}"
    if update or not marker.exists():
        if not build_missing:
            raise NotBuiltError(name)
        _git(repo_dir, "fetch", "--quiet", "origin", build.ref)
        commit = _git(repo_dir, "rev-parse", "FETCH_HEAD")
        marker.write_text(commit)
    else:
        commit = marker.read_text().strip()

    out = root / commit / build.binary
    if not out.exists():
        if not build_missing:
            raise NotBuiltError(name)
        _git(repo_dir, "checkout", "--quiet", "--detach", commit)
        out.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            build.command.format(out=out),
            shell=True,
            cwd=repo_dir,
            check=True,
        )
    return out, commit


def resolve_client(
    client: ClientConfig, *, update: bool = False, build_missing: bool = True
) -> ResolvedClient:
    """Resolve a configured client to a binary, building it if allowed."""
    if client.path is not None:
        path = client.path.expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"client {client.name!r}: {path}")
        return ResolvedClient(client.name, path, "path")
    assert client.build is not None
    binary, commit = ensure_built(
        client.name, client.build, update=update, build_missing=build_missing
    )
    return ResolvedClient(client.name, binary, f"build@{commit[:12]}")


def client_status(client: ClientConfig, *, update: bool = False) -> str:
    """
    One status line: source, binary, and version -- or what is wrong.

    Status never builds; only ``update`` fetches and builds.
    """
    try:
        resolved = resolve_client(client, update=update, build_missing=update)
        version = build_client_tool(resolved.binary).version().splitlines()
        return f"{resolved.source:<18} {resolved.binary}  {version[0]}"
    except NotBuiltError:
        return "not built: run `fuzz clients --update`"
    except Exception as exc:  # noqa: BLE001 - status must never abort
        return f"error: {exc}"
