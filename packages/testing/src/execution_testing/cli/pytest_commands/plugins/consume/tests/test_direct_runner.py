"""Test `consume direct` with a client test runner."""

import json
import shutil
import stat
from pathlib import Path
from typing import Any, Dict, List

import pytest
from pytest import Pytester

import execution_testing

# Fixtures whose blocks (or payloads) 2 and 4 are invalid with
# PRIORITY_GREATER_THAN_MAX_FEE_PER_GAS.
SPEC_FIXTURES = Path(execution_testing.__file__).parent / "specs" / "tests"
BLOCKCHAIN_FIXTURE = (
    SPEC_FIXTURES / "fixtures/blockchain_london_invalid_filled.json"
)
ENGINE_FIXTURE = (
    SPEC_FIXTURES / "fixtures/blockchain_shanghai_invalid_filled_engine.json"
)
FIXTURE_NAME = "000/my_blockchain_test/London"
ENGINE_FIXTURE_NAME = "000/my_blockchain_test/Shanghai"
PRIORITY_FEE_ERROR = "max priority fee per gas higher than max fee per gas"

# A geth `evm` stand-in. `blocktest --help` and `enginetest --help` print
# $HELP, and each command prints its results from $BLOCKTEST or $ENGINETEST.
FAKE_EVM = """#!/bin/sh
if [ "$1" = -v ]; then echo "evm version 1.17.0"; exit 0; fi
if [ "$2" = --help ]; then echo "$HELP"; exit 0; fi
if [ "$1" = enginetest ]; then echo "$ENGINETEST"; else echo "$BLOCKTEST"; fi
exit 0
"""


def runner_result(
    block_4_error: str,
    name: str = FIXTURE_NAME,
    block_2_error: str = PRIORITY_FEE_ERROR,
) -> List[Dict[str, Any]]:
    """Return results that reject blocks 2 and 4 of a fixture."""
    return [
        {
            "name": name,
            "pass": True,
            "rejections": [
                {"index": 2, "error": block_2_error},
                {"index": 4, "error": block_4_error},
            ],
        }
    ]


@pytest.fixture
def consume_direct(pytester: Pytester, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Set up `consume direct` with a fake runner and one fixture file."""
    direct = Path(
        "src/execution_testing/cli/pytest_commands/plugins/consume/direct"
    )
    target = Path(pytester.path) / direct
    target.mkdir(parents=True)
    for name in ("test_via_direct.py", "conftest.py"):
        pytester.copy_example(name=str(direct / name))
        shutil.move(name, target / name)
    pytester.copy_example(
        name="src/execution_testing/cli/pytest_commands/pytest_ini_files/"
        "pytest-consume.ini"
    )
    fixtures = Path(pytester.path) / "fixtures"
    (fixtures / "blockchain_tests").mkdir(parents=True)
    shutil.copyfile(
        BLOCKCHAIN_FIXTURE, fixtures / "blockchain_tests" / "london.json"
    )
    (fixtures / "blockchain_tests_engine").mkdir()
    shutil.copyfile(
        ENGINE_FIXTURE, fixtures / "blockchain_tests_engine" / "shanghai.json"
    )
    evm = Path(pytester.path) / "evm"
    evm.write_text(FAKE_EVM)
    evm.chmod(evm.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("HELP", "--bal-sequential")
    monkeypatch.setenv(
        "ENGINETEST",
        json.dumps(runner_result(PRIORITY_FEE_ERROR, ENGINE_FIXTURE_NAME)),
    )

    def run(
        results: List[Dict[str, Any]],
        *args: str,
        binaries: List[Path] | None = None,
    ) -> Any:
        monkeypatch.setenv("BLOCKTEST", json.dumps(results))
        # `--bin=` keeps pytest's early parse, which runs before the copied
        # conftest adds the option, from taking the path for a test path.
        bin_args = [f"--bin={binary}" for binary in binaries or [evm]]
        return pytester.runpytest(
            "-c",
            "pytest-consume.ini",
            "--input",
            str(fixtures),
            *bin_args,
            str(direct / "test_via_direct.py"),
            *args,
        )

    return run


def test_matching_reasons_pass(consume_direct: Any) -> None:
    """A fixture passes when every rejection maps to its exception."""
    result = consume_direct(runner_result(PRIORITY_FEE_ERROR))
    result.assert_outcomes(passed=2)


def test_a_wrong_reason_fails(consume_direct: Any) -> None:
    """A rejection for the wrong reason fails although the runner passed."""
    result = consume_direct(
        runner_result("nonce too low"), "-m", "blockchain_test"
    )
    result.assert_outcomes(failed=1)
    result.stdout.fnmatch_lines(
        ['*block 4: expected *, client said "nonce too low"*']
    )


@pytest.mark.parametrize(
    "marker", ["blockchain_test", "blockchain_test_engine"]
)
def test_the_format_picks_the_command(
    consume_direct: Any, marker: str
) -> None:
    """
    Each format runs through its own command, and `-m` selects one. Each
    command prints only its own fixture's result, so a fixture sent to the
    wrong command finds none.
    """
    result = consume_direct(runner_result(PRIORITY_FEE_ERROR), "-m", marker)
    result.assert_outcomes(passed=1)


def test_a_runner_without_the_interface_collects_no_engine_tests(
    consume_direct: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without the interface, engine fixtures are not collected at all."""
    monkeypatch.setenv("HELP", "--run value")
    result = consume_direct(
        [{"name": FIXTURE_NAME, "pass": True}], "--collect-only", "-q"
    )
    result.stdout.fnmatch_lines(["*1 test collected*"])


def test_each_bal_mode_is_its_own_test(consume_direct: Any) -> None:
    """
    Every mode is its own test id; `withhold` applies to block tests only,
    so the engine fixture runs in two modes and the block fixture in three.
    """
    result = consume_direct(
        runner_result(PRIORITY_FEE_ERROR),
        "--bal-modes",
        "parallel,sequential,withhold",
        "-v",
    )
    result.assert_outcomes(passed=5, deselected=1)
    result.stdout.fnmatch_lines(
        [
            "*bal_sequential-*Shanghai*PASSED*",
            "*bal_withhold-*London*PASSED*",
        ]
    )
    result.stdout.no_fnmatch_line("*bal_withhold-*Shanghai*")


def test_old_runners_skip_the_other_bal_modes(
    consume_direct: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A runner without the interface runs the parallel mode only."""
    monkeypatch.setenv("HELP", "--run value")
    result = consume_direct(
        [{"name": FIXTURE_NAME, "pass": True}],
        "--bal-modes",
        "parallel,sequential",
    )
    result.assert_outcomes(passed=1, skipped=1)


def test_no_fixture_the_binary_can_run(
    consume_direct: Any, pytester: Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    With only engine fixtures and a binary without the interface, nothing is
    collected and the run reports one skipped empty parameter set.
    """
    shutil.rmtree(Path(pytester.path) / "fixtures" / "blockchain_tests")
    monkeypatch.setenv("HELP", "--run value")
    result = consume_direct([])
    assert result.ret == pytest.ExitCode.OK
    result.assert_outcomes(skipped=1)


def test_each_mode_dumps_its_run_once(
    consume_direct: Any, pytester: Pytester
) -> None:
    """
    With `--dump-dir`, each file's run is dumped once per mode, the
    `parallel` one beside the file's other output and the others under
    their mode, so no mode overwrites another.
    """
    dump_dir = Path(pytester.path) / "dump"
    result = consume_direct(
        runner_result(PRIORITY_FEE_ERROR),
        "-m",
        "blockchain_test",
        "--bal-modes",
        "parallel,sequential",
        f"--dump-dir={dump_dir}",
    )
    result.assert_outcomes(passed=2)
    london = dump_dir / "london"
    assert sorted(path.name for path in london.iterdir()) == [
        "bal_sequential",
        "consume_direct_args.py",
        "consume_direct_returncode.txt",
        "consume_direct_stderr.txt",
        "consume_direct_stdout.txt",
    ]
    assert "--bal-report" in (london / "consume_direct_args.py").read_text()
    assert (
        "--bal-sequential"
        in (london / "bal_sequential" / "consume_direct_args.py").read_text()
    )


def test_unknown_bal_modes_are_rejected(consume_direct: Any) -> None:
    """A mode outside the runner flags is a usage error."""
    result = consume_direct([], "--bal-modes", "serial")
    assert result.ret == pytest.ExitCode.USAGE_ERROR


# One of ethrex's runner binaries, each its own command; $1 of the template
# is the command name, results come from $BLOCKTEST or $ENGINETEST.
FAKE_ETHREX = """#!/bin/sh
if [ "$1" = --version ]; then echo "ethrex-{command} 4.0.0"; exit 0; fi
for arg in "$@"; do
    if [ "$arg" = --help ]; then echo "--bal-sequential"; exit 0; fi
done
echo "${variable}"
"""


def test_binaries_that_run_one_format_each(
    consume_direct: Any, pytester: Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    With ethrex's two binaries, each fixture runs once, on the binary for
    its format, and the other pairs are deselected rather than skipped.
    """
    ethrex_error = "priority fee 2 is greater than max fee 1"
    binaries = []
    for command, variable in (
        ("blocktest", "BLOCKTEST"),
        ("enginetest", "ENGINETEST"),
    ):
        binary = Path(pytester.path) / command
        binary.write_text(
            FAKE_ETHREX.replace("{command}", command).replace(
                "{variable}", variable
            )
        )
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
        binaries.append(binary)
    monkeypatch.setenv(
        "ENGINETEST",
        json.dumps(
            runner_result(ethrex_error, ENGINE_FIXTURE_NAME, ethrex_error)
        ),
    )
    result = consume_direct(
        runner_result(ethrex_error, block_2_error=ethrex_error),
        "-v",
        binaries=binaries,
    )
    result.assert_outcomes(passed=2, deselected=2)
    result.stdout.fnmatch_lines(
        [
            "*EthrexBlocktestConsumer-*London*PASSED*",
            "*EthrexEnginetestConsumer-*Shanghai*PASSED*",
        ]
    )
