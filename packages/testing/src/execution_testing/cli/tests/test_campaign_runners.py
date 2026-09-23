"""Tests for whole-file runner output parsing."""

from pathlib import Path
from typing import Any, List

import pytest

from ..fuzzer_bridge.runners import (
    FixtureRunner,
    StateTestsUnsupportedError,
    Verdict,
    parse_besu_ndjson,
    parse_besu_summary,
    parse_gtest_report,
    parse_json_array,
    strip_nethermind_suffix,
    summarize_gtest_failure,
)


def test_parse_json_array_from_noisy_stdout() -> None:
    """A JSON result list is found even after log lines."""
    out = (
        "INFO something\n"
        '[{"name": "seed_1", "pass": true}, '
        '{"name": "seed_2", "pass": false, "error": "root mismatch"}]\n'
    )
    verdicts = parse_json_array(out)
    assert verdicts["seed_1"].passed and verdicts["seed_1"].error == ""
    assert not verdicts["seed_2"].passed
    assert verdicts["seed_2"].error == "root mismatch"


def test_parse_json_array_without_results_is_empty() -> None:
    """Garbage output yields no verdicts rather than an exception."""
    assert parse_json_array("boom") == {}


def test_parse_gtest_report_maps_failures() -> None:
    """Gtest's report becomes per-test verdicts with the failure text."""
    report = {
        "testsuites": [
            {
                "testsuite": [
                    {"name": "seed_1"},
                    {"name": "seed_2", "failures": [{"failure": "bad root"}]},
                ]
            }
        ]
    }
    verdicts = parse_gtest_report(report)
    assert verdicts["seed_1"].passed
    assert (
        not verdicts["seed_2"].passed
        and "bad root" in verdicts["seed_2"].error
    )


def test_parse_besu_summary_attributes_failures_by_name() -> None:
    """`Running` lines name the tests; the summary names the failed ones."""
    stdout = (
        "Running iteration 0\nRunning seed_1\n"
        "Block 1 (0xab) Imported in 1.0 ms (2.0 MGas/s)\nRunning seed_2\n"
        "\n====\nTEST SUMMARY\n====\nTotal tests:  2\nPassed:       1\n"
        "Failed:       1\n\nFailed tests:\n  - seed_2: bad state root\n====\n"
    )
    verdicts = parse_besu_summary(stdout)
    assert verdicts == {
        "seed_1": Verdict(True),
        "seed_2": Verdict(False, "bad state root"),
    }
    assert "iteration" not in verdicts


def test_strip_nethermind_suffix() -> None:
    """Nethtest reports names with a `_d0g0v0_` suffix."""
    assert strip_nethermind_suffix("seed_7_d0g0v0_") == "seed_7"
    assert strip_nethermind_suffix("seed_7") == "seed_7"


def test_gtest_failure_summary_names_the_mismatched_fields() -> None:
    """The signature line says what differed, not where gtest asserted."""
    text = (
        "/src/blockchaintest.cpp:25\nFailed\nseed_0:\n  Amsterdam/0/0:\n"
        "    state root:\n      actual   0xaa\n      expected 0xbb\n"
        "    gas used:\n      actual   1\n      expected 2\n"
        "    Result state:\n"
    )
    summary = summarize_gtest_failure(text)
    assert summary.startswith("mismatch: state root, gas used\n")
    assert summarize_gtest_failure("plain error") == "plain error"


@pytest.mark.parametrize(
    "kind",
    [
        "GethFixtureConsumer",
        "ErigonFixtureConsumer",
        "EvmOneBlockchainFixtureConsumer",
        "BesuFixtureConsumer",
        "NethtestFixtureConsumer",
    ],
)
def test_runner_flags_precede_the_fixture_path(
    kind: str, monkeypatch: Any, tmp_path: Path
) -> None:
    """
    Every runner takes its flags before the positional file: geth's CLI
    stops parsing flags at the first positional, and the others accept
    either order.
    """
    runner = FixtureRunner(
        "c", Path("/bin/runner"), kind, flags=("--parallelExecution", "true")
    )
    seen: List[List[str]] = []

    def fake_run(args: Any) -> Any:
        seen.append(list(args))
        return type("P", (), {"stdout": "[]", "stderr": "", "returncode": 0})

    monkeypatch.setattr(runner, "_run", fake_run)
    fixture = tmp_path / "batch.json"
    fixture.write_text("{}")
    runner.run_file(fixture, [])
    (args,) = seen
    flag_at = args.index("--parallelExecution")
    assert args[flag_at + 1] == "true"
    assert flag_at < args.index(str(fixture))


def test_with_flags_keeps_the_binary_and_kind() -> None:
    """A contrast runner is the same detected tool under other flags."""
    runner = FixtureRunner("c", Path("/bin/runner"), "GethFixtureConsumer")
    other = runner.with_flags(["--x"])
    assert (other.name, other.binary, other.kind) == (
        runner.name,
        runner.binary,
        runner.kind,
    )
    assert other.flags == ("--x",) and runner.flags == ()


def test_with_env_layers_overrides_on_the_parent_environment() -> None:
    """
    Erigon's contrasts are environment variables, not argv, so a contrast
    that only varies flags cannot reach them. The override has to
    sit on top of the inherited environment, not replace it, or the
    binary loses PATH and HOME.
    """
    import os

    runner = FixtureRunner("erigon", Path("/bin/evm"), "ErigonFixtureConsumer")
    other = runner.with_env({"IGNORE_BAL": "true"})
    assert other.env == {"IGNORE_BAL": "true"} and runner.env == {}
    environ = other._environ()
    assert environ["IGNORE_BAL"] == "true"
    assert set(os.environ) <= set(environ)


def test_detection_runs_under_the_client_env_and_the_runner_keeps_it(
    monkeypatch: Any,
) -> None:
    """
    EEST detects a runner by running it, and a Java or .NET runner cannot
    start without its toolchain, so detection happens under the client's
    env. The runner keeps that env for every run, and a contrast layers
    its own overrides on top rather than replacing it.
    """
    import os

    from ..fuzzer_bridge import runners as runners_module

    seen = {}

    def fake_detect(binary_path: Path) -> Any:
        del binary_path
        seen["home"] = os.environ.get("FUZZ_TOOLCHAIN")
        return type("GethFixtureConsumer", (), {})()

    monkeypatch.delenv("FUZZ_TOOLCHAIN", raising=False)
    monkeypatch.setattr(
        runners_module.FixtureConsumerTool, "from_binary_path", fake_detect
    )
    runner = FixtureRunner.detect(
        "besu", Path("/bin/evmtool"), env={"FUZZ_TOOLCHAIN": "/opt/jdk"}
    )
    assert seen["home"] == "/opt/jdk"
    assert "FUZZ_TOOLCHAIN" not in os.environ
    contrast = runner.with_env({"EXEC3_WORKERS": "1"})
    assert contrast.env == {"FUZZ_TOOLCHAIN": "/opt/jdk", "EXEC3_WORKERS": "1"}


def test_a_contrast_can_vary_flags_and_env_together() -> None:
    """
    The two knobs compose: a contrast can vary a flag and erigon's worker
    count at once.
    """
    runner = FixtureRunner("erigon", Path("/bin/evm"), "ErigonFixtureConsumer")
    other = runner.with_flags(["--x"]).with_env(
        {"IGNORE_BAL": "true", "EXEC3_WORKERS": "4"}
    )
    assert other.flags == ("--x",)
    assert other.env == {"IGNORE_BAL": "true", "EXEC3_WORKERS": "4"}


@pytest.mark.parametrize(
    "kind, subcommand",
    [
        ("GethFixtureConsumer", "statetest"),
        ("ErigonFixtureConsumer", "statetest"),
        ("BesuFixtureConsumer", "state-test"),
        ("NethtestFixtureConsumer", "--input"),
    ],
)
def test_state_tests_use_each_runner_s_state_subcommand(
    kind: str, subcommand: str, monkeypatch: Any, tmp_path: Path
) -> None:
    """The same binary judges state tests through its other entry point."""
    runner = FixtureRunner("c", Path("/bin/runner"), kind, flags=("--f",))
    seen: List[List[str]] = []

    def fake_run(args: Any) -> Any:
        seen.append(list(args))
        return type("P", (), {"stdout": "[]", "stderr": "", "returncode": 0})

    monkeypatch.setattr(runner, "_run", fake_run)
    fixture = tmp_path / "s.json"
    fixture.write_text("{}")
    verdicts = runner.run_state_file(fixture, ["x"])
    (args,) = seen
    assert subcommand in args and "--f" in args
    assert args.index("--f") < args.index(str(fixture))
    assert "--blockTest" not in args and "blocktest" not in args
    assert not verdicts["x"].passed and "no result" in verdicts["x"].error


def test_evmone_blockchaintest_cannot_judge_state_tests(
    tmp_path: Path,
) -> None:
    """Evmone splits the formats across binaries; the campaign has one."""
    runner = FixtureRunner(
        "evmone", Path("/bin/x"), "EvmOneBlockchainFixtureConsumer"
    )
    with pytest.raises(StateTestsUnsupportedError):
        runner.run_state_file(tmp_path / "s.json", ["x"])


def test_parse_besu_ndjson_reads_test_or_name() -> None:
    """One object per line, `test` or `name`, log lines ignored."""
    out = (
        "INFO starting\n"
        '{"test": "a", "pass": true}\n'
        '{"name": "b", "pass": false, "error": "state root mismatch"}\n'
    )
    verdicts = parse_besu_ndjson(out)
    assert verdicts["a"].passed
    assert not verdicts["b"].passed and "state root" in verdicts["b"].error
