"""Test `consume direct` with a client test runner."""

import json
import shutil
import stat
from pathlib import Path
from typing import Any, Dict, List

import pytest
from pytest import Pytester

import execution_testing

FIXTURE_NAME = "000/my_blockchain_test/London"
BLOCKCHAIN_FIXTURE = (
    Path(execution_testing.__file__).parent
    / "specs"
    / "tests"
    / "fixtures"
    / "blockchain_london_invalid_filled.json"
)
PRIORITY_FEE_ERROR = "max priority fee per gas higher than max fee per gas"

# A geth `evm` stand-in that speaks the runner interface and prints $RESULTS.
FAKE_EVM = """#!/bin/sh
if [ "$1" = -v ]; then echo "evm version 1.17.0"; exit 0; fi
if [ "$2" = --help ]; then echo "--bal-sequential"; exit 0; fi
echo "$RESULTS"
exit 0
"""


def runner_result(block_4_error: str) -> List[Dict[str, Any]]:
    """Return the results of the London fixture: blocks 2 and 4 rejected."""
    return [
        {
            "name": FIXTURE_NAME,
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
    fixtures = Path(pytester.path) / "fixtures" / "blockchain_tests"
    fixtures.mkdir(parents=True)
    shutil.copyfile(BLOCKCHAIN_FIXTURE, fixtures / "london.json")
    evm = Path(pytester.path) / "evm"
    evm.write_text(FAKE_EVM)
    evm.chmod(evm.stat().st_mode | stat.S_IXUSR)

    def run(results: List[Dict[str, Any]], *args: str) -> Any:
        monkeypatch.setenv("RESULTS", json.dumps(results))
        return pytester.runpytest(
            "-c",
            "pytest-consume.ini",
            "--input",
            str(fixtures.parent),
            "--bin",
            str(evm),
            str(direct / "test_via_direct.py"),
            *args,
        )

    return run


def test_matching_reasons_pass(consume_direct: Any) -> None:
    """The fixture passes when every rejection maps to its exception."""
    result = consume_direct(runner_result(PRIORITY_FEE_ERROR))
    result.assert_outcomes(passed=1)


def test_a_wrong_reason_fails(consume_direct: Any) -> None:
    """A rejection for the wrong reason fails although the runner passed."""
    result = consume_direct(runner_result("nonce too low"))
    result.assert_outcomes(failed=1)
    result.stdout.fnmatch_lines(
        ['*block 4: expected *, client said "nonce too low"*']
    )
