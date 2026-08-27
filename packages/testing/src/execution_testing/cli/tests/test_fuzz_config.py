"""Tests for the fuzz.yaml configuration model and loader."""

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ..fuzzer_bridge import config as config_module
from ..fuzzer_bridge.config import FuzzConfig, load_fuzz_config

YAML = """
clients:
  - name: geth
    path: /opt/geth/evm
  - name: nethermind
    build:
      repo: NethermindEth/nethermind
      ref: master
      command: "echo build > {out}"
      binary: nethtest
campaigns:
  amsterdam:
    fork: Amsterdam
    clients: [geth, nethermind]
    count: 50
    workers: 4
"""


def test_loads_clients_and_campaigns(tmp_path: Path) -> None:
    """Clients and campaigns round-trip from YAML with defaults applied."""
    cfg_path = tmp_path / "fuzz.yaml"
    cfg_path.write_text(YAML)
    cfg = load_fuzz_config(cfg_path)
    assert [c.name for c in cfg.clients] == ["geth", "nethermind"]
    assert cfg.client("geth").path == Path("/opt/geth/evm")
    build = cfg.client("nethermind").build
    assert build is not None
    assert build.binary == "nethtest"
    campaign = cfg.campaigns["amsterdam"]
    assert campaign.fork == "Amsterdam"
    assert campaign.count == 50
    assert campaign.workers == 4
    assert campaign.seed_start == 0
    assert campaign.baseline_seeds == 20


def test_missing_default_config_is_empty(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """No fuzz.yaml in the project root means an empty configuration."""
    monkeypatch.setattr(
        config_module, "DEFAULT_CONFIG_PATH", tmp_path / "fuzz.yaml"
    )
    assert load_fuzz_config() == FuzzConfig()


def test_missing_explicit_config_raises(tmp_path: Path) -> None:
    """An explicitly named file that does not exist is an error."""
    with pytest.raises(FileNotFoundError):
        load_fuzz_config(tmp_path / "nope.yaml")


def test_client_needs_exactly_one_source() -> None:
    """A client declares a path or a build, never neither nor both."""
    with pytest.raises(ValidationError):
        FuzzConfig.model_validate({"clients": [{"name": "x"}]})
    with pytest.raises(ValidationError):
        FuzzConfig.model_validate(
            {
                "clients": [
                    {
                        "name": "x",
                        "path": "/a",
                        "build": {
                            "repo": "a/b",
                            "command": "c",
                            "binary": "d",
                        },
                    }
                ]
            }
        )


def test_known_client_build_fills_defaults() -> None:
    """A known client's build needs only the ref; the rest is on file."""
    cfg = FuzzConfig.model_validate(
        {"clients": [{"name": "geth", "build": {"ref": "v1.17.0"}}]}
    )
    build = cfg.client("geth").build
    assert build is not None
    assert build.repo == "ethereum/go-ethereum"
    assert build.ref == "v1.17.0"
    assert build.binary == "evm"
    assert build.command is not None and "{out}" in build.command


def test_recipe_fills_defaults_for_any_client_name() -> None:
    """A freely named client borrows a known client's recipe."""
    cfg = FuzzConfig.model_validate(
        {
            "clients": [
                {"name": "geth-pr", "build": {"recipe": "geth", "ref": "x"}}
            ]
        }
    )
    build = cfg.client("geth-pr").build
    assert build is not None
    assert build.repo == "ethereum/go-ethereum"
    assert build.binary == "evm"


def test_unknown_client_build_needs_every_field() -> None:
    """Without known defaults, an incomplete build is rejected."""
    with pytest.raises(ValidationError, match="command"):
        FuzzConfig.model_validate(
            {"clients": [{"name": "mystery", "build": {"repo": "a/b"}}]}
        )


def test_unknown_client_name_lists_known() -> None:
    """Looking up an undeclared client names the declared ones."""
    cfg = FuzzConfig.model_validate(
        {"clients": [{"name": "geth", "path": "/a"}]}
    )
    with pytest.raises(KeyError, match="geth"):
        cfg.client("besu")


def test_campaign_must_reference_declared_clients() -> None:
    """A campaign naming an undeclared client fails validation."""
    with pytest.raises(ValidationError, match="besu"):
        FuzzConfig.model_validate(
            {
                "clients": [{"name": "geth", "path": "/a"}],
                "campaigns": {"c": {"fork": "Osaka", "clients": ["besu"]}},
            }
        )


def test_malformed_config_names_the_file(tmp_path: Path) -> None:
    """A broken file is reported with its path, not a parser traceback."""
    cfg_path = tmp_path / "fuzz.yaml"
    cfg_path.write_text("clients:\n  - name: x\n path: /a\n")
    with pytest.raises(ValueError, match="fuzz.yaml"):
        load_fuzz_config(cfg_path)
