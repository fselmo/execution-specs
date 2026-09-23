"""
Client pool: turn `fuzz.yaml` client entries into runnable binaries.

A path source is used as-is. A build source is cloned once, its ref
resolved to a commit, and the artifact built into a commit-keyed cache
directory, so switching a client between branches never rebuilds what is
already there and a run can always say which commit it compared against.
"""

import hashlib
import os
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List, Mapping, Optional, Sequence, Tuple

from execution_testing.client_clis import FixtureConsumerTool, TransitionTool

from .config import BuildSource, ClientConfig

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
    """A client ready to run: its binary, where it came from, its env."""

    name: str
    binary: Path
    source: str
    env: Mapping[str, str] = field(default_factory=dict)


@contextmanager
def client_environment(env: Mapping[str, str]) -> Iterator[None]:
    """
    Layer a client's environment on this process's for the duration.

    For code that launches the client without taking an environment --
    EEST's tool detection runs `--version` itself. Restored on exit, so
    one client's `JAVA_HOME` never leaks into the next client's run.
    """
    saved = {key: os.environ.get(key) for key in env}
    os.environ.update(env)
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class PatchOutsideRunnerError(Exception):
    """A series hunk lands outside the client's runner paths."""


def series_hash(patches: Sequence[Path]) -> str:
    """A short digest of the series' bytes, in order; part of the cache key."""
    digest = hashlib.sha256()
    for patch in patches:
        digest.update(patch.read_bytes())
    return digest.hexdigest()[:12]


def patched_files(patch: Path) -> List[str]:
    """Paths a `git format-patch` file touches, from its diff headers."""
    return [
        line.split(" b/", 1)[0][len("diff --git a/") :]
        for line in patch.read_text().splitlines()
        if line.startswith("diff --git a/")
    ]


def paths_outside(
    patches: Sequence[Path], allowed: Sequence[str]
) -> List[str]:
    """Touched paths no allowed prefix covers, as `patch: path` strings."""
    return [
        f"{patch.name}: {path}"
        for patch in patches
        for path in patched_files(patch)
        if not any(path.startswith(prefix) for prefix in allowed)
    ]


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
    env: Optional[Mapping[str, str]] = None,
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

    build_id = commit
    if build.patches:
        outside = paths_outside(build.patches, build.patch_paths)
        if outside:
            raise PatchOutsideRunnerError(
                f"client {name!r}: the series touches paths outside the "
                f"runner ({', '.join(build.patch_paths) or 'none allowed'}): "
                + "; ".join(outside)
            )
        build_id = f"{commit}+{series_hash(build.patches)}"
    out = root / build_id / build.binary
    if not out.exists():
        if not build_missing:
            raise NotBuiltError(name)
        _git(repo_dir, "checkout", "--quiet", "--detach", commit)
        if build.patches:
            _apply_series(name, repo_dir, build.patches)
        out.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            build.command.format(out=out),
            shell=True,
            cwd=repo_dir,
            check=True,
            env={**os.environ, **(env or {})},
        )
    return out, build_id


def _apply_series(name: str, repo_dir: Path, patches: Sequence[Path]) -> None:
    """
    Apply the series on the pinned commit, in order.

    A patch that no longer applies is the signal that upstream touched
    the runner under the pin: the series is rebased on our schedule, not
    silently skipped.
    """
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repo_dir),
            "-c",
            "user.name=fuzz",
            "-c",
            "user.email=fuzz@eels",
            "-c",
            "commit.gpgsign=false",
            "am",
            "--quiet",
            *[str(p) for p in patches],
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        subprocess.run(
            ["git", "-C", str(repo_dir), "am", "--abort"],
            capture_output=True,
        )
        raise RuntimeError(
            f"client {name!r}: the patch series does not apply on the "
            f"pinned commit -- upstream touched the runner; rebase the "
            f"series. git am said: {result.stderr.strip()[:400]}"
        )


def resolve_client(
    client: ClientConfig, *, update: bool = False, build_missing: bool = True
) -> ResolvedClient:
    """Resolve a configured client to a binary, building it if allowed."""
    if client.path is not None:
        path = client.path.expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"client {client.name!r}: {path}")
        return ResolvedClient(client.name, path, "path", dict(client.env))
    assert client.build is not None
    binary, build_id = ensure_built(
        client.name,
        client.build,
        update=update,
        build_missing=build_missing,
        env=client.env,
    )
    commit, _, series = build_id.partition("+")
    source = f"build@{commit[:12]}" + (f"+series:{series}" if series else "")
    return ResolvedClient(client.name, binary, source, dict(client.env))


def binary_version(
    binary: Path, env: Optional[Mapping[str, str]] = None
) -> str:
    """
    First version line of ``binary``, detected as a fixture runner or a
    t8n -- a client may be either, and `fuzz campaign` only needs the former.
    """
    failure: Exception = RuntimeError("no detection attempted")
    for tool_class in (FixtureConsumerTool, TransitionTool):
        try:
            with client_environment(env or {}):
                tool = tool_class.from_binary_path(binary_path=binary)
                return tool.version().splitlines()[0]
        except Exception as exc:  # noqa: BLE001 - try the other role
            failure = exc
    raise RuntimeError(
        f"not a known fixture runner or t8n: {binary} ({failure})"
    )


def client_status(client: ClientConfig, *, update: bool = False) -> str:
    """
    One status line: source, binary, and version -- or what is wrong.

    Status never builds; only ``update`` fetches and builds.
    """
    try:
        resolved = resolve_client(client, update=update, build_missing=update)
        version = binary_version(resolved.binary, resolved.env)
        return f"{resolved.source:<18} {resolved.binary}  {version}"
    except NotBuiltError:
        return "not built: run `fuzz clients --update`"
    except Exception as exc:  # noqa: BLE001 - status must never abort
        return f"error: {exc}"
