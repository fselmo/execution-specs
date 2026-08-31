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
    monkeypatch.setattr(differential, "_prepare", lambda case, _fork: case)
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


def test_diff_writes_summary_and_exits_nonzero_on_divergence(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """`--summary-json` records the run; divergence is a nonzero exit."""
    import json

    exe = tmp_path / "evm"
    exe.write_text("")
    divergence = SimpleNamespace(
        field="gas_used", values={"eels": "1", "evm": "2"}, minority=["evm"]
    )
    outcome = SimpleNamespace(
        seed=7,
        divergences=[divergence],
        errors={},
        rejections={},
        asymmetric_failure=False,
        diverged=True,
        eels_ran=True,
        post_state_diff={},
    )

    def fake_differential_fuzz(fork: Any, seeds: range, **_kwargs: Any) -> Any:
        return SimpleNamespace(
            agreed=len(seeds) - 1,
            diverged=1,
            seeds=len(seeds),
            outcomes=[outcome],
            manifest=None,
            eels_runs=len(seeds),
            fork=fork.name(),
            generator_version=4,
            clients=["evm"],
        )

    monkeypatch.setattr(
        differential_cli, "differential_fuzz", fake_differential_fuzz
    )
    summary = tmp_path / "summary.json"
    result = CliRunner().invoke(
        fuzz,
        [
            "diff",
            "--fork",
            "Osaka",
            "--client",
            str(exe),
            "--count",
            "10",
            "--no-baseline",
            "--summary-json",
            str(summary),
        ],
    )
    assert result.exit_code == 1, result.output
    data = json.loads(summary.read_text())
    assert data["seeds"] == 10 and data["diverged"] == 1
    assert data["first_divergent_seed"] == 7
    assert data["fields"] == {"gas_used": 1}


def test_campaign_command_runs_and_reports(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """`fuzz campaign` resolves the campaign and runs the loop."""
    from types import SimpleNamespace

    from ..fuzzer_bridge import cli as cli_module

    exe = tmp_path / "evm"
    exe.write_text("")
    (tmp_path / "fuzz.yaml").write_text(
        f"clients:\n  - name: geth\n    path: {exe}\n"
        "campaigns:\n  osaka:\n    fork: Osaka\n    clients: [geth]\n"
    )
    seen = {}

    def fake_run(options: Any, *, echo: Any) -> Any:  # noqa: ARG001
        seen["options"] = options
        return SimpleNamespace(signatures={}, unique_findings=lambda: 0)

    monkeypatch.setattr(cli_module, "run_campaign", fake_run)
    result = CliRunner().invoke(
        fuzz,
        [
            "campaign",
            "osaka",
            "--count",
            "10",
            "--config",
            str(tmp_path / "fuzz.yaml"),
            "--output",
            str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 0, result.output
    options = seen["options"]
    assert options.count == 10 and options.clients == {"geth": exe}
    assert options.output == tmp_path / "out"


def test_campaign_command_needs_a_budget(tmp_path: Path) -> None:
    """Without --hours or --count the command refuses to run forever."""
    (tmp_path / "fuzz.yaml").write_text("")
    result = CliRunner().invoke(
        fuzz, ["campaign", "x", "--config", str(tmp_path / "fuzz.yaml")]
    )
    assert result.exit_code != 0 and "--hours" in result.output
