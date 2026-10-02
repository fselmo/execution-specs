"""Tests for whole-file runner output parsing."""

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

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


def test_parse_json_array_past_erigon_env_warnings() -> None:
    """Erigon's `[WARN]` lines start with `[` and must not end the search."""
    out = (
        "[WARN] [09-23|23:54:01.399] [env] use ERIGON_ prefix for env "
        "var=IGNORE_BAL\n"
        "[WARN] [09-23|23:54:01.399] [env]      IGNORE_BAL=true\n"
        '[\n  {"name": "seed_1", "pass": true, "error": ""}\n]\n'
    )
    assert parse_json_array(out)["seed_1"].passed


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


def test_an_engine_campaign_judges_nethermind_through_its_engine_path(
    monkeypatch: Any, tmp_path: Path
) -> None:
    """
    `blockchain_test_engine` fixtures go to `nethtest --engineTest`, whose
    result list is the one `--blockTest` prints, so it parses the same.
    """
    runner = FixtureRunner(
        "nethermind",
        Path("/bin/nethtest"),
        "NethtestFixtureConsumer",
        engine=True,
    )
    seen: List[List[str]] = []
    stdout = (
        '[{"name": "seed_0", "pass": true, "fork": "Amsterdam", '
        '"lastPayloadStatus": "VALID"}]'
    )

    def fake_run(args: Any) -> Any:
        seen.append(list(args))
        return type("P", (), {"stdout": stdout, "stderr": "", "returncode": 0})

    monkeypatch.setattr(runner, "_run", fake_run)
    fixture = tmp_path / "batch.json"
    fixture.write_text("{}")
    verdicts = runner.run_file(fixture, ["seed_0"])
    (args,) = seen
    assert args[0] == "--engineTest"
    assert verdicts == {"seed_0": Verdict(True)}


def test_an_engine_campaign_refuses_a_client_with_no_engine_runner(
    monkeypatch: Any,
) -> None:
    """
    The evmone blockchain-test runner has no engine path: an engine-format
    campaign naming it stops before it fills anything, rather than judging
    on import and calling it engine.
    """
    from ..fuzzer_bridge import runners as runners_module
    from ..fuzzer_bridge.runners import EngineRunnerUnsupportedError

    monkeypatch.setattr(
        runners_module.FixtureConsumerTool,
        "from_binary_path",
        lambda **_: type("EvmOneBlockchainFixtureConsumer", (), {})(),
    )
    with pytest.raises(EngineRunnerUnsupportedError, match="evmone"):
        FixtureRunner.detect("evmone", Path("/bin/evmone"), engine=True)
    assert FixtureRunner.detect("evmone", Path("/bin/evmone")).engine is False


def _judge(
    monkeypatch: Any, tmp_path: Path, runner: FixtureRunner, stdout: str
) -> Tuple[List[str], Dict[str, Verdict]]:
    """Run ``runner`` on one batch whose run prints ``stdout``."""
    seen: List[List[str]] = []

    def fake_run(args: Any) -> Any:
        seen.append(list(args))
        return type("P", (), {"stdout": stdout, "stderr": "", "returncode": 1})

    monkeypatch.setattr(runner, "_run", fake_run)
    fixture = tmp_path / "batch.json"
    fixture.write_text("{}")
    verdicts = runner.run_file(fixture, ["seed_0", "seed_1"])
    (args,) = seen
    return args, verdicts


STATE_ROOT = (
    "0x31357f1cc1e97fc69b6921ef869bbd552a60cc0532ebb43affa66fdd0257e392"
)
BLOCK_HASH = (
    "0xd699eb29166ebed62e63b4bea039418fef7f75ac4ccaaa7d689bf36687b7b8ff"
)
GAS_ERROR = "block #1 insertion into chain failed: invalid gas used"

GETH_BLOCKTEST_BEFORE_34650 = json.dumps(
    [
        {
            "name": "seed_0",
            "pass": True,
            "stateRoot": STATE_ROOT,
            "fork": "Amsterdam",
        },
        {
            "name": "seed_1",
            "pass": False,
            "fork": "Amsterdam",
            "error": GAS_ERROR,
        },
    ],
    indent=2,
)
"""`evm blocktest` at 920c0777: `stateRoot` on a pass, `error` omitted."""

GETH_BLOCKTEST_AFTER_34650 = json.dumps(
    [
        {
            "name": "seed_0",
            "pass": True,
            "fork": "Amsterdam",
            "error": "",
            "lastBlockHash": BLOCK_HASH,
        },
        {
            "name": "seed_1",
            "pass": False,
            "fork": "Amsterdam",
            "error": GAS_ERROR,
        },
    ],
    indent=2,
)
"""`evm blocktest` with #34650: `lastBlockHash` in place of `stateRoot`,
and `error` always present, empty on a pass."""


@pytest.mark.parametrize(
    "stdout",
    [
        pytest.param(GETH_BLOCKTEST_BEFORE_34650, id="before-34650"),
        pytest.param(GETH_BLOCKTEST_AFTER_34650, id="after-34650"),
    ],
)
def test_geth_blocktest_parses_before_and_after_34650(
    monkeypatch: Any, tmp_path: Path, stdout: str
) -> None:
    """Both of geth's result schemas give the same verdicts."""
    runner = FixtureRunner("geth", Path("/bin/evm"), "GethFixtureConsumer")
    args, verdicts = _judge(monkeypatch, tmp_path, runner, stdout)
    assert args[0] == "blocktest"
    assert verdicts == {
        "seed_0": Verdict(True),
        "seed_1": Verdict(False, GAS_ERROR),
    }


def test_an_engine_campaign_judges_geth_through_enginetest(
    monkeypatch: Any, tmp_path: Path
) -> None:
    """
    Geth's engine runner is `evm enginetest`. A payload correctly refused
    passes with its validation error in `error`, and stays a pass.
    """
    runner = FixtureRunner(
        "geth", Path("/bin/evm"), "GethFixtureConsumer", engine=True
    )
    stdout = """[
  {"name": "seed_0", "pass": true, "fork": "Amsterdam",
   "error": "invalid block access list", "lastPayloadStatus": "INVALID"},
  {"name": "seed_1", "pass": false, "fork": "Amsterdam",
   "error": "expected INVALID, got VALID", "lastPayloadStatus": "VALID"}
]"""
    args, verdicts = _judge(monkeypatch, tmp_path, runner, stdout)
    assert args[0] == "enginetest"
    assert verdicts["seed_0"].passed
    assert not verdicts["seed_1"].passed


def test_an_engine_campaign_judges_besu_through_engine_test(
    monkeypatch: Any, tmp_path: Path
) -> None:
    """Besu's engine runner is `evmtool engine-test --json-array`."""
    runner = FixtureRunner(
        "besu", Path("/bin/evmtool"), "BesuFixtureConsumer", engine=True
    )
    stdout = """[ {
  "name" : "seed_0", "pass" : true, "fork" : "Amsterdam",
  "lastBlockHash" : "0x01", "lastPayloadStatus" : "INVALID", "error" : ""
}, {
  "name" : "seed_1", "pass" : false, "fork" : "Amsterdam",
  "lastBlockHash" : "0x02", "lastPayloadStatus" : "VALID",
  "error" : "payload 1: expected INVALID, got VALID"
} ]"""
    args, verdicts = _judge(monkeypatch, tmp_path, runner, stdout)
    assert args[:2] == ["engine-test", "--json-array"]
    assert verdicts == {
        "seed_0": Verdict(True),
        "seed_1": Verdict(False, "payload 1: expected INVALID, got VALID"),
    }


def test_nethtest_judges_generated_engine_fixtures() -> None:
    """
    A real `nethtest --engineTest` passes fixtures EELS filled in the
    engine format. `NETHTEST` names the binary; skipped without one.
    """
    import contextlib
    import io
    import json
    import os
    import tempfile
    import warnings

    from ..fuzzer_bridge import campaign as mod
    from ..fuzzer_bridge.generator import generate_fuzzer_output

    binary = os.environ.get("NETHTEST")
    if not binary or not Path(binary).is_file():
        pytest.skip("set NETHTEST to a nethtest binary")
    mod._init_fill_worker("Amsterdam")
    fork, eels = mod._FILL["fork"], mod._FILL["eels"]
    engine = mod.campaign_format("blockchain_test_engine")
    fixtures = {}
    for seed in range(3):
        with contextlib.redirect_stdout(io.StringIO()):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                fixtures[f"seed_{seed}"] = mod.fill_case(
                    generate_fuzzer_output(fork, seed),
                    fork,
                    eels,
                    fixture_format=engine,
                )
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "batch.json"
        path.write_text(json.dumps(fixtures))
        runner = FixtureRunner(
            "nethermind", Path(binary), "NethtestFixtureConsumer", engine=True
        )
        verdicts = runner.run_file(path, list(fixtures))
    assert all(v.passed for v in verdicts.values()), verdicts


ETHREX_BAL_ERROR = (
    "Expected transaction execution to fail in test: seed_1 with error: "
    "Some([Other])"
)
ETHREX_BLOCKTEST = json.dumps(
    [
        {"error": "", "fork": "Amsterdam", "name": "seed_0", "pass": True},
        {
            "error": ETHREX_BAL_ERROR,
            "fork": "Amsterdam",
            "name": "seed_1",
            "pass": False,
        },
    ],
    indent=2,
)
"""`ethrex-blocktest --json` on a block expected rejected for a list
changed by a wei and committed to, which it imports."""

ETHREX_PAYLOAD_ERROR = (
    "wrong_status[0]  expected=VALID  got=INVALID  validationError=Invalid "
    "block hash. Expected 0x4fa3cca22412fb1fe572a88ffee476e2191e982374ed91c8"
    "00b327abdbff246a, got 0x63ebc003ca696a5696088b447039d1572fc09a9edba4f186"
    "acc42711f5d19c31"
)
ETHREX_ENGINETEST = json.dumps(
    [
        {"error": "", "fork": "Amsterdam", "name": "seed_0", "pass": True},
        {
            "error": ETHREX_PAYLOAD_ERROR,
            "fork": "Amsterdam",
            "name": "seed_1",
            "pass": False,
        },
    ],
    indent=2,
)
"""`ethrex-enginetest --json` on a payload whose `gasUsed` was edited
after the fill."""


@pytest.mark.parametrize(
    "engine,stdout,error",
    [
        pytest.param(False, ETHREX_BLOCKTEST, ETHREX_BAL_ERROR, id="block"),
        pytest.param(
            True, ETHREX_ENGINETEST, ETHREX_PAYLOAD_ERROR, id="engine"
        ),
    ],
)
def test_ethrex_runners_take_flags_then_the_path(
    monkeypatch: Any, tmp_path: Path, engine: bool, stdout: str, error: str
) -> None:
    """Each ethrex runner judges one format, so it takes no subcommand."""
    runner = FixtureRunner(
        "ethrex",
        Path("/bin/ethrex"),
        "EthrexFixtureConsumer",
        flags=("--no-bal-parallel-exec",),
        engine=engine,
    )
    args, verdicts = _judge(monkeypatch, tmp_path, runner, stdout)
    assert args == [
        "--no-bal-parallel-exec",
        "--json",
        "--path",
        str(tmp_path / "batch.json"),
    ]
    assert verdicts == {
        "seed_0": Verdict(True),
        "seed_1": Verdict(False, error),
    }


def _fake_ethrex(tmp_path: Path, name: str) -> Path:
    binary = tmp_path / name
    binary.write_text(f'#!/bin/sh\necho "{name} 4.0.0"\n')
    binary.chmod(0o755)
    return binary


@pytest.mark.parametrize(
    "name,engine",
    [
        pytest.param("ethrex-blocktest", False, id="block"),
        pytest.param("ethrex-enginetest", True, id="engine"),
    ],
)
def test_ethrex_runners_are_detected_by_their_version_line(
    tmp_path: Path, name: str, engine: bool
) -> None:
    """EEST cannot detect ethrex's runners; their `--version` names them."""
    runner = FixtureRunner.detect(
        "ethrex", _fake_ethrex(tmp_path, name), engine=engine
    )
    assert runner.kind == "EthrexFixtureConsumer"
    assert runner.engine == engine


@pytest.mark.parametrize(
    "name,engine",
    [
        pytest.param("ethrex-blocktest", True, id="block-in-engine"),
        pytest.param("ethrex-enginetest", False, id="engine-in-block"),
    ],
)
def test_an_ethrex_runner_for_the_other_format_is_refused(
    tmp_path: Path, name: str, engine: bool
) -> None:
    """A runner that cannot read the campaign's format fails at detection."""
    with pytest.raises(ValueError, match="judges the other fixture format"):
        FixtureRunner.detect(
            "ethrex", _fake_ethrex(tmp_path, name), engine=engine
        )


RETH_BALANCE_ERROR = (
    "test failed: Balance does not match\n  left `309698523628523820`,\n "
    "right `309698523628523819`"
)
RETH_BLOCKTEST = json.dumps(
    [
        {"error": "", "fork": "", "name": "seed_0", "pass": True},
        {
            "error": RETH_BALANCE_ERROR,
            "fork": "",
            "name": "seed_1",
            "pass": False,
        },
    ]
)
"""`ef-test-runner blocktest --json-array` with reth's series on a v36 batch,
one fixture's expected post-state balance raised by a wei."""


@pytest.mark.parametrize(
    "engine,command",
    [
        pytest.param(False, "blocktest", id="block"),
        pytest.param(True, "enginetest", id="engine"),
    ],
)
def test_reth_judges_a_batch_with_json_array(
    monkeypatch: Any, tmp_path: Path, engine: bool, command: str
) -> None:
    """The reth runner takes its subcommand, the flags, then the file."""
    runner = FixtureRunner(
        "reth",
        Path("/bin/ef-test-runner"),
        "RethFixtureConsumer",
        engine=engine,
    )
    args, verdicts = _judge(monkeypatch, tmp_path, runner, RETH_BLOCKTEST)
    assert args == [command, "--json-array", str(tmp_path / "batch.json")]
    assert verdicts == {
        "seed_0": Verdict(True),
        "seed_1": Verdict(False, RETH_BALANCE_ERROR),
    }


def test_reth_is_detected_for_both_formats(tmp_path: Path) -> None:
    """The reth runner is named by `--help`; one binary judges both formats."""
    binary = tmp_path / "ef-test-runner"
    binary.write_text(
        "#!/bin/sh\n"
        '[ "$1" = --help ] || exit 2\n'
        'echo "Usage: ef-test-runner [SUITE_PATH]"\n'
    )
    binary.chmod(0o755)
    for engine in (False, True):
        runner = FixtureRunner.detect("reth", binary, engine=engine)
        assert runner.kind == "RethFixtureConsumer"
        assert runner.engine == engine


def test_a_rejection_for_the_wrong_reason_fails(
    monkeypatch: Any, tmp_path: Path
) -> None:
    """
    A runner on the shared interface passes every rejection and reports
    the client's error for each rejected block, so the error at the block
    the fixture expects rejected is mapped through the client's mapper and
    compared with the expected exception. Only the right reason passes; a
    wrong one and an unmapped one each fail, keyed on the expected
    exception. Geth's runner today reports the error in `error`, which is
    checked the same way, and a pass with no error came from a runner that
    checked the reason itself.
    """
    from ..fuzzer_bridge.campaign import per_client_signatures

    expected = "TransactionException.GAS_LIMIT_EXCEEDS_MAXIMUM"
    names = ["right", "wrong", "unmapped", "legacy_wrong", "checked"]
    fixture = tmp_path / "batch.json"
    fixture.write_text(
        json.dumps(
            {
                name: {"blocks": [{}, {"expectException": expected}]}
                for name in names
            }
        )
    )

    def rejected(name: str, error: str) -> Dict[str, Any]:
        return {
            "name": name,
            "pass": True,
            "rejections": [{"index": 1, "error": error}],
        }

    stdout = json.dumps(
        [
            rejected("right", "transaction gas limit too high (cap: 2^24)"),
            rejected("wrong", "max fee per gas less than block base fee"),
            rejected("unmapped", "no such check"),
            {
                "name": "legacy_wrong",
                "pass": True,
                "error": "max fee per gas less than block base fee",
            },
            {"name": "checked", "pass": True, "error": ""},
        ]
    )
    runner = FixtureRunner("geth", Path("/bin/evm"), "GethFixtureConsumer")
    monkeypatch.setattr(
        runner,
        "_run",
        lambda _args: type(
            "P", (), {"stdout": stdout, "stderr": "", "returncode": 0}
        ),
    )
    verdicts = runner.run_file(fixture, names)

    assert verdicts["right"].passed
    assert verdicts["checked"].passed
    signatures = dict(per_client_signatures(verdicts, expected))
    assert set(signatures) == {"wrong", "unmapped", "legacy_wrong"}
    wrong = (
        f"expected {expected}: rejected for the wrong reason: "
        "TransactionException.INSUFFICIENT_MAX_FEE_PER_GAS"
    )
    assert signatures["wrong"] == signatures["legacy_wrong"] == wrong
    assert signatures["unmapped"] == (
        f"expected {expected}: rejected with an error no exception maps: "
        "no such check"
    )
