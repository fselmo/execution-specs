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
    block_4_error: str, name: str = FIXTURE_NAME
) -> List[Dict[str, Any]]:
    """Return results that reject blocks 2 and 4 of a fixture."""
    return [
        {
            "name": name,
            "pass": True,
            "rejections": [
                {"index": 2, "error": PRIORITY_FEE_ERROR},
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

    def run(results: List[Dict[str, Any]], *args: str) -> Any:
        monkeypatch.setenv("BLOCKTEST", json.dumps(results))
        return pytester.runpytest(
            "-c",
            "pytest-consume.ini",
            "--input",
            str(fixtures),
            "--bin",
            str(evm),
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
