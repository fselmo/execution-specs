"""Test consuming fixtures through a client's test runner."""

import json
import shutil
import stat
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import pytest

from execution_testing.base_types import Hash, to_json
from execution_testing.client_clis import (
    EthrexFixtureConsumer,
    FixtureConsumerTool,
    GethFixtureConsumer,
    NethtestFixtureConsumer,
    RethFixtureConsumer,
)
from execution_testing.client_clis.client_runner import (
    BalExecutionWarning,
    BalMode,
    bal_problems,
    parse_bal_report,
    parse_run,
    rejection_problems,
)
from execution_testing.client_clis.clis.geth import GethExceptionMapper
from execution_testing.exceptions import EngineAPIError
from execution_testing.fixtures import (
    BlockchainEngineFixture,
    BlockchainFixture,
    FixtureFormat,
    StateFixture,
)
from execution_testing.fixtures.blockchain import FixtureBlock
from execution_testing.test_types.block_access_list.t8n import (
    BlockAccessList,
)

# Fixtures whose blocks (or payloads) 2 and 4 are invalid, each with
# PRIORITY_GREATER_THAN_MAX_FEE_PER_GAS.
SPEC_FIXTURES = Path(__file__).parents[2] / "specs" / "tests" / "fixtures"
BLOCKCHAIN_FIXTURE = SPEC_FIXTURES / "blockchain_london_invalid_filled.json"
ENGINE_FIXTURE = (
    SPEC_FIXTURES / "blockchain_shanghai_invalid_filled_engine.json"
)
FIXTURE_NAME = "000/my_blockchain_test/London"
ENGINE_FIXTURE_NAME = "000/my_blockchain_test/Shanghai"

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


@pytest.fixture(scope="module")
def engine_fixture() -> BlockchainEngineFixture:
    """The Shanghai engine fixture with two invalid payloads."""
    fixtures = json.loads(ENGINE_FIXTURE.read_text())
    return BlockchainEngineFixture.model_validate(
        fixtures[ENGINE_FIXTURE_NAME]
    )


def test_payload_rejection_reasons(
    engine_fixture: BlockchainEngineFixture,
) -> None:
    """Engine payloads are checked by index and reason, like blocks."""
    parsed = parse_run(
        ["evm"],
        0,
        json.dumps(
            [result(ENGINE_FIXTURE_NAME, rejections={2: PRIORITY_FEE_ERROR})]
        ),
        "",
    ).results[ENGINE_FIXTURE_NAME]
    assert rejection_problems(
        engine_fixture, parsed, GethExceptionMapper()
    ) == [
        "payload 4: expected "
        "TransactionException.PRIORITY_GREATER_THAN_MAX_FEE_PER_GAS, "
        "client accepted it"
    ]


@pytest.mark.parametrize(
    "error,problems",
    [
        pytest.param("-32602: Invalid params", [], id="same_code"),
        pytest.param(
            "-38003: Invalid payload attributes",
            [
                "payload 4: expected error code -32602, "
                'client said "-38003: Invalid payload attributes"'
            ],
            id="other_code",
        ),
    ],
)
def test_payload_error_codes(
    engine_fixture: BlockchainEngineFixture, error: str, problems: List[str]
) -> None:
    """A payload that expects a JSON-RPC error is checked by its code alone."""
    fixture = engine_fixture.model_copy(deep=True)
    fixture.payloads[4].error_code = EngineAPIError.InvalidParams
    parsed = parse_run(
        ["evm"],
        0,
        json.dumps(
            [
                result(
                    ENGINE_FIXTURE_NAME,
                    rejections={2: PRIORITY_FEE_ERROR, 4: error},
                )
            ]
        ),
        "",
    ).results[ENGINE_FIXTURE_NAME]
    assert (
        rejection_problems(fixture, parsed, GethExceptionMapper()) == problems
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
echo "$REPORT" >&2
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
    assert fake_evm.calls() == [
        f"blocktest --bal-report {fake_evm.fixture_path}"
    ]
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


# A runner binary stand-in: `--version` prints $VERSION, any `--help` prints
# $HELP, and a run logs its arguments and prints $RESULTS.
FAKE_RUNNER = """#!/bin/sh
if [ "$1" = --version ]; then echo "$VERSION"; exit 0; fi
for arg in "$@"; do
    if [ "$arg" = --help ]; then echo "$HELP"; exit 0; fi
done
echo "$@" >> "$LOG"
echo "$RESULTS"
"""


@pytest.fixture
def fake_runner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Write a runner binary that speaks the interface."""
    binary = tmp_path / "runner"
    binary.write_text(FAKE_RUNNER)
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("HELP", "--bal-sequential")
    monkeypatch.setenv("LOG", str(tmp_path / "calls.log"))
    return binary


@pytest.mark.parametrize(
    "version,consumer_class,formats",
    [
        pytest.param(
            "ef-test-runner 2.7.0 (47c7ff1)",
            RethFixtureConsumer,
            {BlockchainFixture, BlockchainEngineFixture},
            id="reth",
        ),
        pytest.param(
            "ethrex-blocktest 4.0.0",
            EthrexFixtureConsumer,
            {BlockchainFixture},
            id="ethrex_blocktest",
        ),
        pytest.param(
            "ethrex-enginetest 4.0.0",
            EthrexFixtureConsumer,
            {BlockchainEngineFixture},
            id="ethrex_enginetest",
        ),
        pytest.param(
            "Nethermind nethtest 2.2.0-preview+441af213",
            NethtestFixtureConsumer,
            {StateFixture, BlockchainFixture, BlockchainEngineFixture},
            id="nethermind",
        ),
    ],
)
def test_runner_binaries_are_detected(
    fake_runner: Path,
    monkeypatch: pytest.MonkeyPatch,
    version: str,
    consumer_class: type[FixtureConsumerTool],
    formats: Set[FixtureFormat],
) -> None:
    """Each runner binary is detected from `--version` with its formats."""
    monkeypatch.setenv("VERSION", version)
    consumer = FixtureConsumerTool.from_binary_path(binary_path=fake_runner)
    assert type(consumer) is consumer_class
    assert {
        fixture_format
        for fixture_format in (
            StateFixture,
            BlockchainFixture,
            BlockchainEngineFixture,
        )
        if consumer.can_consume(fixture_format)
    } == formats


def test_ethrex_runs_its_binary_without_a_subcommand(
    fake_runner: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Ethrex's `blocktest` binary is the command, with `--json` results."""
    monkeypatch.setenv("VERSION", "ethrex-blocktest 4.0.0")
    monkeypatch.setenv(
        "RESULTS", json.dumps([result(rejections={2: "x", 4: "y"})])
    )
    consumer = EthrexFixtureConsumer(binary=fake_runner)
    run = consumer.run_fixture_file(BlockchainFixture, BLOCKCHAIN_FIXTURE)
    assert run.error is None
    assert (tmp_path / "calls.log").read_text() == (
        f"--json --bal-report {BLOCKCHAIN_FIXTURE}\n"
    )


def test_a_runner_only_binary_must_speak_the_interface(
    fake_runner: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reth has no older path, so a binary without the interface fails."""
    monkeypatch.setenv("VERSION", "ef-test-runner 1.0.0 (abc)")
    monkeypatch.setenv("HELP", "--threads")
    with pytest.raises(Exception, match="does not speak"):
        FixtureConsumerTool.from_binary_path(binary_path=fake_runner)


def report_line(event: str, block_hash: Hash, **fields: str) -> str:
    """Return one execution report line; lines are matched by hash only."""
    return json.dumps(
        {"event": event, "block": 1, "hash": str(block_hash), **fields}
    )


@pytest.fixture
def amsterdam_like_fixture(
    blockchain_fixture: BlockchainFixture,
) -> BlockchainFixture:
    """The London fixture with an access list on its first block."""
    fixture = blockchain_fixture.model_copy(deep=True)
    first_block = fixture.blocks[0]
    assert isinstance(first_block, FixtureBlock)
    first_block.block_access_list = BlockAccessList()
    return fixture


@pytest.mark.parametrize(
    "lines,problems",
    [
        pytest.param(
            [("balExecution", 0, {"path": "parallel", "reason": ""})],
            [],
            id="parallel",
        ),
        pytest.param(
            [
                (
                    "balExecution",
                    0,
                    {"path": "sequential", "reason": "block-import"},
                )
            ],
            ['block 1 ran sequential (reason "block-import")'],
            id="sequential",
        ),
        pytest.param([], ["block 1 has no balExecution line"], id="missing"),
        pytest.param(
            [
                ("balExecution", 0, {"path": "parallel", "reason": ""}),
                (
                    "balFallback",
                    2,
                    {
                        "parallelError": "boom",
                        "sequentialResult": "invalid",
                        "sequentialError": "nonce",
                    },
                ),
            ],
            [
                'block 3 fell back to sequential ("boom"), which found it '
                "invalid"
            ],
            id="fallback_on_an_invalid_block",
        ),
        pytest.param(
            [("balExecution", 1, {"path": "sequential", "reason": "x"})],
            ["block 1 has no balExecution line"],
            id="only_blocks_with_a_list_must_run_parallel",
        ),
    ],
)
def test_bal_report(
    amsterdam_like_fixture: BlockchainFixture,
    lines: List[Tuple[str, int, Dict[str, str]]],
    problems: List[str],
) -> None:
    """
    A valid block with an access list must run on the parallel executor,
    and no block may fall back; lines are tied to blocks by hash.
    """
    stderr_lines = ["INFO some client log", "{not json"]
    for event, block_index, fields in lines:
        block = amsterdam_like_fixture.blocks[block_index]
        if isinstance(block, FixtureBlock):
            block_hash = block.header.block_hash
        else:
            assert block.rlp_decoded is not None
            block_hash = block.rlp_decoded.header.block_hash
        stderr_lines.append(report_line(event, block_hash, **fields))
    report = parse_bal_report("\n".join(stderr_lines))
    assert bal_problems(amsterdam_like_fixture, report) == problems


@pytest.mark.parametrize(
    "bal_mode,flag",
    [
        pytest.param("parallel", "--bal-report", id="parallel"),
        pytest.param("sequential", "--bal-sequential", id="sequential"),
        pytest.param("withhold", "--bal-withhold", id="withhold"),
    ],
)
def test_each_mode_runs_with_its_flag(
    fake_evm: FakeEvm, bal_mode: BalMode, flag: str
) -> None:
    """Each mode is a run of its own, with the mode's runner flag."""
    fake_evm.configure(
        help_text="--bal-sequential", results=[result()], exit_code=0
    )
    consumer = GethFixtureConsumer(binary=fake_evm.binary)
    consumer.consume_with_runner(
        BlockchainFixture, fake_evm.fixture_path, FIXTURE_NAME, None, bal_mode
    )
    assert fake_evm.calls() == [f"blocktest {flag} {fake_evm.fixture_path}"]


@pytest.mark.parametrize("require_bal_parallel", [False, True])
def test_a_block_off_the_parallel_executor_warns_or_fails(
    fake_evm: FakeEvm,
    amsterdam_like_fixture: BlockchainFixture,
    monkeypatch: pytest.MonkeyPatch,
    require_bal_parallel: bool,
) -> None:
    """
    A valid block with a list that ran sequentially is a warning, or a
    failure when parallel execution is required.
    """
    fake_evm.fixture_path.write_text(
        json.dumps({FIXTURE_NAME: to_json(amsterdam_like_fixture)})
    )
    fake_evm.configure(
        help_text="--bal-sequential", results=[result()], exit_code=0
    )
    block = amsterdam_like_fixture.blocks[0]
    assert isinstance(block, FixtureBlock)
    monkeypatch.setenv(
        "REPORT",
        report_line(
            "balExecution",
            block.header.block_hash,
            path="sequential",
            reason="disabled",
        ),
    )
    consumer = GethFixtureConsumer(binary=fake_evm.binary)
    expectation = (
        pytest.raises(AssertionError, match="ran sequential")
        if require_bal_parallel
        else pytest.warns(BalExecutionWarning, match="ran sequential")
    )
    with expectation:
        consumer.consume_with_runner(
            BlockchainFixture,
            fake_evm.fixture_path,
            FIXTURE_NAME,
            require_bal_parallel=require_bal_parallel,
        )
