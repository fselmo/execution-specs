"""Test consuming fixtures through a client's test runner."""

import json
import shutil
import stat
from pathlib import Path
from typing import Any, Dict, List

import pytest

from execution_testing.client_clis import GethFixtureConsumer
from execution_testing.client_clis.client_runner import (
    parse_run,
    rejection_problems,
)
from execution_testing.client_clis.clis.geth import GethExceptionMapper
from execution_testing.fixtures import BlockchainFixture

# A London fixture whose blocks 2 and 4 are invalid, each with
# PRIORITY_GREATER_THAN_MAX_FEE_PER_GAS.
SPEC_FIXTURES = Path(__file__).parents[2] / "specs" / "tests" / "fixtures"
BLOCKCHAIN_FIXTURE = SPEC_FIXTURES / "blockchain_london_invalid_filled.json"
FIXTURE_NAME = "000/my_blockchain_test/London"

PRIORITY_FEE_ERROR = "max priority fee per gas higher than max fee per gas"


def result(
    name: str = FIXTURE_NAME,
    passed: bool = True,
    rejections: Dict[int, str] | None = None,
) -> Dict[str, Any]:
    """Return one result object as a runner prints it."""
    if rejections is None:
        rejections = {2: PRIORITY_FEE_ERROR, 4: PRIORITY_FEE_ERROR}
    return {
        "name": name,
        "pass": passed,
        "rejections": [
            {"index": index, "error": error}
            for index, error in rejections.items()
        ],
    }


@pytest.mark.parametrize("returncode", [0, 1])
def test_results_are_trusted_after_exit_0_or_1(returncode: int) -> None:
    """Exit 0 and 1 both carry complete results."""
    run = parse_run(["evm"], returncode, json.dumps([result()]), "")
    assert run.error is None
    assert run.results[FIXTURE_NAME].passed


@pytest.mark.parametrize("returncode", [2, -9])
def test_other_exit_codes_are_run_errors(returncode: int) -> None:
    """Any other exit is a run error, even with results on stdout."""
    run = parse_run(["evm"], returncode, json.dumps([result()]), "boom")
    assert run.error == f"runner exited with code {returncode}"
    assert run.results == {}
    assert run.stderr == "boom"


@pytest.mark.parametrize(
    "stdout,error",
    [
        pytest.param("Passed: 1", "do not parse", id="not_json"),
        pytest.param(
            json.dumps([result(), result()]), "twice", id="duplicate_name"
        ),
    ],
)
def test_results_that_cannot_be_trusted(stdout: str, error: str) -> None:
    """Output that is not one result per fixture is a run error."""
    run = parse_run(["evm"], 0, stdout, "")
    assert run.error is not None and error in run.error


@pytest.fixture(scope="module")
def blockchain_fixture() -> BlockchainFixture:
    """The London fixture with two invalid blocks."""
    fixtures = json.loads(BLOCKCHAIN_FIXTURE.read_text())
    return BlockchainFixture.model_validate(fixtures[FIXTURE_NAME])


@pytest.mark.parametrize(
    "rejections,problems",
    [
        pytest.param(
            {2: PRIORITY_FEE_ERROR, 4: PRIORITY_FEE_ERROR}, [], id="match"
        ),
        pytest.param(
            {2: PRIORITY_FEE_ERROR, 4: "nonce too low"},
            [
                "block 4: expected "
                "TransactionException.PRIORITY_GREATER_THAN_MAX_FEE_PER_GAS, "
                'client said "nonce too low" '
                "(maps to TransactionException.NONCE_MISMATCH_TOO_LOW)"
            ],
            id="wrong_reason",
        ),
        pytest.param(
            {2: "kaput", 4: PRIORITY_FEE_ERROR},
            [
                "block 2: expected "
                "TransactionException.PRIORITY_GREATER_THAN_MAX_FEE_PER_GAS, "
                'client said "kaput" (maps to nothing in GethExceptionMapper)'
            ],
            id="unmapped_reason",
        ),
        pytest.param(
            {2: PRIORITY_FEE_ERROR},
            [
                "block 4: expected "
                "TransactionException.PRIORITY_GREATER_THAN_MAX_FEE_PER_GAS, "
                "client accepted it"
            ],
            id="missing_rejection",
        ),
        pytest.param(
            {2: PRIORITY_FEE_ERROR, 3: "bad", 4: PRIORITY_FEE_ERROR},
            ['block 3: expected valid, client said "bad"'],
            id="extra_rejection",
        ),
    ],
)
def test_rejection_reasons(
    blockchain_fixture: BlockchainFixture,
    rejections: Dict[int, str],
    problems: List[str],
) -> None:
    """
    Each rejection's error goes through the client's mapper and must give
    the exception the fixture expects at that index.
    """
    parsed = parse_run(
        ["evm"], 0, json.dumps([result(rejections=rejections)]), ""
    ).results[FIXTURE_NAME]
    assert (
        rejection_problems(blockchain_fixture, parsed, GethExceptionMapper())
        == problems
    )


# A geth `evm` stand-in: `-v` names it, `blocktest --help` lists the flags
# given in $HELP, and `blocktest <file>` logs its arguments, prints $RESULTS
# and exits with $EXIT.
FAKE_EVM = """#!/bin/sh
if [ "$1" = -v ]; then echo "evm version 1.17.0"; exit 0; fi
if [ "$2" = --help ]; then echo "$HELP"; exit 0; fi
echo "$@" >> "$LOG"
echo "$RESULTS"
echo "runner stderr" >&2
exit "$EXIT"
"""


class FakeEvm:
    """A fake geth `evm` and the fixture file it runs."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Write the runner and copy the fixture next to it."""
        self.binary = tmp_path / "evm"
        self.binary.write_text(FAKE_EVM)
        self.binary.chmod(self.binary.stat().st_mode | stat.S_IXUSR)
        self.log = tmp_path / "calls.log"
        self.fixture_path = tmp_path / "fixtures.json"
        shutil.copyfile(BLOCKCHAIN_FIXTURE, self.fixture_path)
        self.monkeypatch = monkeypatch
        monkeypatch.setenv("LOG", str(self.log))
        self.configure(help_text="--bal-sequential", results=[], exit_code=0)

    def configure(
        self, *, help_text: str, results: List[Dict[str, Any]], exit_code: int
    ) -> None:
        """Set what the runner prints and how it exits."""
        self.monkeypatch.setenv("HELP", help_text)
        self.monkeypatch.setenv("RESULTS", json.dumps(results))
        self.monkeypatch.setenv("EXIT", str(exit_code))

    def calls(self) -> List[str]:
        """Return the argument lines of every fixture run."""
        if not self.log.exists():
            return []
        return self.log.read_text().splitlines()

    def consume(self, consumer: GethFixtureConsumer, name: str) -> None:
        """Consume one fixture of the file."""
        consumer.consume_fixture(BlockchainFixture, self.fixture_path, name)


@pytest.fixture
def fake_evm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeEvm:
    """A fake geth `evm` that speaks the runner interface."""
    return FakeEvm(tmp_path, monkeypatch)


def test_interface_detection(fake_evm: FakeEvm) -> None:
    """A runner speaks the interface when its help lists `--bal-sequential`."""
    assert GethFixtureConsumer(binary=fake_evm.binary).speaks_runner_interface(
        BlockchainFixture
    )
    fake_evm.configure(help_text="--run value", results=[], exit_code=0)
    assert not GethFixtureConsumer(
        binary=fake_evm.binary
    ).speaks_runner_interface(BlockchainFixture)


def test_each_file_runs_once_and_results_are_found_by_name(
    fake_evm: FakeEvm,
) -> None:
    """
    The file runs once for all its fixtures, and each fixture reads its own
    result, even when another fixture in the file failed.
    """
    other = "001/other_test/London"
    fake_evm.configure(
        help_text="--bal-sequential",
        results=[result(name=other, passed=False), result()],
        exit_code=1,
    )
    consumer = GethFixtureConsumer(binary=fake_evm.binary)
    fake_evm.consume(consumer, FIXTURE_NAME)
    fake_evm.consume(consumer, FIXTURE_NAME)
    assert fake_evm.calls() == [f"blocktest {fake_evm.fixture_path}"]
    with pytest.raises(AssertionError, match="no result for 'missing'"):
        fake_evm.consume(consumer, "missing")


def test_a_failed_fixture_names_the_reason(fake_evm: FakeEvm) -> None:
    """A failing fixture's message names both sides of a wrong reason."""
    fake_evm.configure(
        help_text="--bal-sequential",
        results=[
            result(
                passed=False,
                rejections={2: PRIORITY_FEE_ERROR, 4: "nonce too low"},
            )
        ],
        exit_code=1,
    )
    consumer = GethFixtureConsumer(binary=fake_evm.binary)
    with pytest.raises(AssertionError, match=r"block 4: expected .*nonce"):
        fake_evm.consume(consumer, FIXTURE_NAME)


def test_a_run_error_carries_stderr(fake_evm: FakeEvm) -> None:
    """After exit 2 no result is trusted, and the error shows stderr."""
    fake_evm.configure(
        help_text="--bal-sequential", results=[result()], exit_code=2
    )
    consumer = GethFixtureConsumer(binary=fake_evm.binary)
    with pytest.raises(Exception, match="(?s)code 2.*runner stderr"):
        fake_evm.consume(consumer, FIXTURE_NAME)


def test_a_runner_without_the_interface_keeps_the_old_path(
    fake_evm: FakeEvm,
) -> None:
    """
    A runner without the interface runs each fixture on its own with
    `--run`, and its output is read the old way.
    """
    fake_evm.configure(
        help_text="--run value",
        results=[{"name": FIXTURE_NAME, "pass": True}],
        exit_code=0,
    )
    consumer = GethFixtureConsumer(binary=fake_evm.binary)
    fake_evm.consume(consumer, FIXTURE_NAME)
    fake_evm.consume(consumer, FIXTURE_NAME)
    run_flag = f"blocktest --run {FIXTURE_NAME} {fake_evm.fixture_path}"
    assert fake_evm.calls() == [run_flag, run_flag]
