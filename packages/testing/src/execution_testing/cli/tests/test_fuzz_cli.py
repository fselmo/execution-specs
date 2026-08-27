"""Tests for the `fuzz` command group."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict

from click.testing import CliRunner

from execution_testing.forks import Osaka

from ..fuzzer_bridge import differential_cli
from ..fuzzer_bridge.cli import fuzz


def test_group_lists_subcommands() -> None:
    """The group exposes the fuzzing workflows as subcommands."""
    result = CliRunner().invoke(fuzz, ["--help"])
    assert result.exit_code == 0
    for name in ("run", "diff", "distill"):
        assert name in result.output


def test_diff_reads_a_campaign(tmp_path: Path, monkeypatch: Any) -> None:
    """`fuzz diff --campaign` supplies fork, clients, and counts."""
    exe = tmp_path / "evm"
    exe.write_text("")
    (tmp_path / "fuzz.yaml").write_text(
        f"""
clients:
  - name: geth
    path: {exe}
campaigns:
  osaka:
    fork: Osaka
    clients: [geth]
    count: 7
    seed_start: 3
    workers: 2
"""
    )
    captured: Dict[str, Any] = {}

    def fake_differential_fuzz(fork: Any, seeds: range, **kwargs: Any) -> Any:
        captured.update(fork=fork, seeds=seeds, **kwargs)
        return SimpleNamespace(
            agreed=len(seeds),
            diverged=0,
            seeds=len(seeds),
            outcomes=[],
            manifest=None,
            eels_runs=0,
        )

    monkeypatch.setattr(
        differential_cli, "differential_fuzz", fake_differential_fuzz
    )
    result = CliRunner().invoke(
        fuzz,
        [
            "diff",
            "--campaign",
            "osaka",
            "--config",
            str(tmp_path / "fuzz.yaml"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert captured["fork"] is Osaka
    assert captured["seeds"] == range(3, 10)
    assert captured["clients"] == {"geth": exe}
    assert captured["workers"] == 2


def test_diff_flags_override_the_campaign(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Explicit flags win over campaign values."""
    exe = tmp_path / "evm"
    exe.write_text("")
    (tmp_path / "fuzz.yaml").write_text(
        f"""
clients:
  - name: geth
    path: {exe}
campaigns:
  osaka:
    fork: Osaka
    clients: [geth]
    count: 7
"""
    )
    captured: Dict[str, Any] = {}

    def fake_differential_fuzz(fork: Any, seeds: range, **kwargs: Any) -> Any:
        captured.update(fork=fork, seeds=seeds, **kwargs)
        return SimpleNamespace(
            agreed=len(seeds),
            diverged=0,
            seeds=len(seeds),
            outcomes=[],
            manifest=None,
            eels_runs=0,
        )

    monkeypatch.setattr(
        differential_cli, "differential_fuzz", fake_differential_fuzz
    )
    result = CliRunner().invoke(
        fuzz,
        [
            "diff",
            "--campaign",
            "osaka",
            "--config",
            str(tmp_path / "fuzz.yaml"),
            "--count",
            "2",
        ],
    )
    assert result.exit_code == 0, result.output
    assert captured["seeds"] == range(0, 2)


def test_diff_without_campaign_or_clients_is_a_usage_error(
    tmp_path: Path,
) -> None:
    """Nothing to compare against is reported, not silently run."""
    empty = tmp_path / "fuzz.yaml"
    empty.write_text("")
    result = CliRunner().invoke(
        fuzz, ["diff", "--fork", "Osaka", "--config", str(empty)]
    )
    assert result.exit_code != 0
    assert "client" in result.output


def test_broken_config_is_a_clean_error(tmp_path: Path) -> None:
    """A malformed fuzz.yaml is reported by path without a traceback."""
    broken = tmp_path / "fuzz.yaml"
    broken.write_text("clients:\n  - name: x\n path: /a\n")
    result = CliRunner().invoke(fuzz, ["clients", "--config", str(broken)])
    assert result.exit_code != 0
    assert "fuzz.yaml" in result.output
    assert "Traceback" not in result.output


def _saved_case(tmp_path: Path) -> Path:
    from execution_testing.forks import Osaka as OsakaFork

    from ..fuzzer_bridge.corpus import save_case
    from ..fuzzer_bridge.generator import generate_fuzzer_output

    return save_case(
        generate_fuzzer_output(OsakaFork, 1), tmp_path / "case.json"
    )


def _fake_tools(monkeypatch: Any, behaviour: Dict[str, Any]) -> None:
    from ..fuzzer_bridge import cli as cli_module
    from ..fuzzer_bridge import differential
    from .test_differential import _fake_transition

    monkeypatch.setattr(
        cli_module,
        "build_tools",
        lambda _clients: {name: name for name in behaviour},
    )
    monkeypatch.setattr(
        differential, "_transition", _fake_transition(behaviour)
    )


def test_replay_shows_every_field_and_marks_the_minority(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Replay prints each field per tool and flags the odd one out."""
    from .test_differential import _result

    exe = tmp_path / "evm"
    exe.write_text("")
    _fake_tools(
        monkeypatch,
        {
            "eels": _result(),
            "geth": _result(),
            "besu": _result(gas_used=42),
        },
    )
    result = CliRunner().invoke(
        fuzz, ["replay", str(_saved_case(tmp_path)), "--client", str(exe)]
    )
    assert result.exit_code == 1, result.output
    assert "gas_used" in result.output
    assert "besu" in result.output and "minority" in result.output
    assert "state_root" in result.output


def test_replay_agreement_exits_zero(tmp_path: Path, monkeypatch: Any) -> None:
    """A case every tool agrees on replays cleanly."""
    from .test_differential import _result

    exe = tmp_path / "evm"
    exe.write_text("")
    _fake_tools(monkeypatch, {"eels": _result(), "geth": _result()})
    result = CliRunner().invoke(
        fuzz, ["replay", str(_saved_case(tmp_path)), "--client", str(exe)]
    )
    assert result.exit_code == 0, result.output
    assert "minority" not in result.output
