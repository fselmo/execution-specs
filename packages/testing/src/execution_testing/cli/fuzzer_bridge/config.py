"""
`fuzz.yaml`: the clients and campaigns a fuzzing run is driven by.

The file is gitignored and found by walking up from the working directory,
so a checkout carries its own client set without any of it being imposed
on other developers. Clients come from a binary on disk or from a source
build the framework performs and caches; campaigns name a fork, the
clients to compare, and the run size, so a run is `fuzz diff --campaign
NAME` rather than a chain of flags.
"""

from pathlib import Path
from typing import Dict, List, Optional

import yaml
from pydantic import BaseModel, Field, ValidationError, model_validator

CONFIG_NAME = "fuzz.yaml"

DEFAULT_CONFIG_PATH: Optional[Path] = None
"""Explicit default location; when None the nearest `fuzz.yaml` is used."""


class BuildSource(BaseModel):
    """A client built from source at a git ref, cached by commit."""

    recipe: Optional[str] = None
    """Known client whose build recipe fills the fields left out; defaults
    to the client's name."""
    repo: Optional[str] = None
    """Git URL, or `owner/name` for a GitHub repository."""
    ref: str = "master"
    command: Optional[str] = None
    """Shell command run in the checkout; `{out}` is the artifact path."""
    binary: Optional[str] = None
    """
    Artifact file name. EEST detects a client from its `--version` line,
    which echoes the binary's name, so the name must be the canonical one
    (`evm`, `evmtool`, `nethtest`, ...).
    """


KNOWN_BUILDS: Dict[str, BuildSource] = {
    "geth": BuildSource(
        repo="ethereum/go-ethereum",
        command="go build -o {out} ./cmd/evm",
        binary="evm",
    ),
    "erigon": BuildSource(
        repo="erigontech/erigon",
        command=(
            "make BUILD_TAGS=nosqlite,noboltdb,nosilkworm evm "
            "&& cp build/bin/evm {out}"
        ),
        binary="evm",
    ),
    "besu": BuildSource(
        repo="besu-eth/besu",
        command=(
            "./gradlew installDist -x test "
            "&& rm -rf {out}.dist && cp -r build/install/besu {out}.dist "
            "&& ln -sf {out}.dist/bin/evmtool {out}"
        ),
        binary="evmtool",
    ),
    "nethermind": BuildSource(
        repo="NethermindEth/nethermind",
        command=(
            "dotnet publish src/Nethermind/Nethermind.Test.Runner "
            "-c release -o {out}.publish --sc false "
            "&& ln -sf {out}.publish/nethtest {out}"
        ),
        binary="nethtest",
    ),
    "evmone": BuildSource(
        repo="ethereum/evmone",
        command=(
            "cmake -S . -B build -DEVMONE_TESTING=ON "
            "&& cmake --build build --parallel --target evmone-blockchaintest "
            "&& cp build/bin/evmone-blockchaintest {out}"
        ),
        binary="evmone-blockchaintest",
    ),
}
"""
Build recipes for clients the framework knows how to produce: each yields
the client's standalone fixture runner (geth/erigon `evm`, besu `evmtool`,
nethermind `nethtest`, evmone's blockchain-test runner). Builds use the
toolchains in the environment: Go >= 1.24 with cgo for erigon, the JDK
besu's Gradle toolchain asks for (25 on the devnet branches; point
`JAVA_HOME` at it), the .NET SDK band nethermind's `global.json` pins
(10.0.3xx), and CMake + C++20 for evmone.
"""


class ClientConfig(BaseModel):
    """One client under test: a binary path or a source build."""

    name: str
    path: Optional[Path] = None
    build: Optional[BuildSource] = None

    @model_validator(mode="after")
    def _one_source(self) -> "ClientConfig":
        if (self.path is None) == (self.build is None):
            raise ValueError(
                f"client {self.name!r}: declare exactly one of path or build"
            )
        if self.build is not None:
            recipe = self.build.recipe or self.name
            known = KNOWN_BUILDS.get(recipe, BuildSource())
            self.build.repo = self.build.repo or known.repo
            self.build.command = self.build.command or known.command
            self.build.binary = self.build.binary or known.binary
            missing = [
                name
                for name in ("repo", "command", "binary")
                if getattr(self.build, name) is None
            ]
            if missing:
                raise ValueError(
                    f"client {self.name!r}: build needs "
                    f"{', '.join(missing)}; set them or pick a recipe "
                    f"from: {', '.join(KNOWN_BUILDS)}"
                )
        return self


class KnownSignature(BaseModel):
    """A campaign finding understood already: counted, never bundled again."""

    reason: str
    """Substring matched against a signature's normalized reason text."""
    client: Optional[str] = None
    """Restrict the match to one client; any client when omitted."""


class CampaignConfig(BaseModel):
    """A named differential run: fork, clients, and size."""

    fork: str
    clients: List[str]
    seed_start: int = 0
    count: int = 100
    workers: int = 1
    corpus: Optional[Path] = None
    baseline_seeds: int = 20
    known: List[KnownSignature] = Field(default_factory=list)
    """Signatures to suppress from findings (e.g. a bug already filed)."""


class FuzzConfig(BaseModel):
    """The whole `fuzz.yaml`."""

    clients: List[ClientConfig] = Field(default_factory=list)
    campaigns: Dict[str, CampaignConfig] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _campaigns_reference_clients(self) -> "FuzzConfig":
        declared = {client.name for client in self.clients}
        for name, campaign in self.campaigns.items():
            unknown = [c for c in campaign.clients if c not in declared]
            if unknown:
                raise ValueError(
                    f"campaign {name!r} names undeclared clients: "
                    f"{', '.join(unknown)}"
                )
        return self

    def client(self, name: str) -> ClientConfig:
        """Return the client named ``name``."""
        for client in self.clients:
            if client.name == name:
                return client
        known = ", ".join(c.name for c in self.clients) or "none"
        raise KeyError(f"unknown client {name!r}; declared: {known}")


def find_config(start: Optional[Path] = None) -> Optional[Path]:
    """Return the nearest `fuzz.yaml` at or above ``start`` (cwd)."""
    current = (start or Path.cwd()).resolve()
    for directory in (current, *current.parents):
        candidate = directory / CONFIG_NAME
        if candidate.is_file():
            return candidate
    return None


def load_fuzz_config(path: Optional[Path] = None) -> FuzzConfig:
    """
    Load ``path``, or the nearest `fuzz.yaml`; no file means no clients.

    An explicitly given path must exist.
    """
    if path is None:
        path = DEFAULT_CONFIG_PATH or find_config()
        if path is None or not path.is_file():
            return FuzzConfig()
    elif not path.is_file():
        raise FileNotFoundError(path)
    try:
        with path.open() as handle:
            data = yaml.safe_load(handle) or {}
        return FuzzConfig.model_validate(data)
    except yaml.YAMLError as exc:
        raise ValueError(f"{path}: {exc}") from exc
    except ValidationError as exc:
        detail = "; ".join(error["msg"] for error in exc.errors())
        raise ValueError(f"{path}: {detail}") from exc
