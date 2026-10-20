"""
Consume fixtures through a client's test runner (`blocktest`, `enginetest`).

The interface is described in `docs/running_tests/consume/client_runners.md`.
A runner runs a whole fixture file at once, so each file runs once and every
test looks its fixture up in the cached results by full name.
"""

import json
import warnings
from dataclasses import dataclass, field
from functools import cache, lru_cache
from pathlib import Path
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Tuple

from pydantic import TypeAdapter, ValidationError

from execution_testing.base_types import Hash
from execution_testing.exceptions import (
    EngineAPIError,
    ExceptionMapper,
    ExceptionMapperValidator,
    UndefinedException,
)
from execution_testing.fixtures import (
    BaseFixture,
    BlockchainEngineFixture,
    BlockchainFixture,
    FixtureConsumer,
    FixtureFormat,
)
from execution_testing.fixtures.blockchain import (
    FixtureBlock,
    InvalidFixtureBlock,
)
from execution_testing.rpc.rpc_types import ClientValidationError

from .ethereum_cli import EthereumCLI
from .file_utils import dump_files_to_directory
from .runner_interface import (
    BalExecution,
    BalFallback,
    FixtureResult,
    RunnerResults,
)

TRUSTED_EXIT_CODES = (0, 1)
"""
Exit codes after which the results are complete: every fixture passed, or
at least one failed. Nethermind and Erigon exit 0 either way.
"""

INTERFACE_FLAG = "--bal-sequential"
"""A flag only runners that speak the interface take."""

BalMode = Literal["parallel", "sequential", "withhold"]

BAL_MODE_FLAGS: Dict[str, Tuple[str, ...]] = {
    # The runner's default executor, reporting which one ran each block.
    "parallel": ("--bal-report",),
    "sequential": ("--bal-sequential",),
    "withhold": ("--bal-withhold",),
}
"""Runner flags for each way of executing blocks with access lists."""


class BalExecutionWarning(UserWarning):
    """A block with an access list did not run on the parallel executor."""


@dataclass(frozen=True)
class RunnerCommands:
    """
    How a client spells the runner commands: the arguments before the flags
    for each lane, and the switch for JSON results, if any.
    """

    blocktest: Tuple[str, ...]
    enginetest: Tuple[str, ...]
    json_flags: Tuple[str, ...] = ()


RUNNER_COMMANDS: Dict[str, RunnerCommands] = {
    "go-ethereum": RunnerCommands(("blocktest",), ("enginetest",)),
    "besu": RunnerCommands(
        ("block-test",), ("engine-test",), ("--json-array",)
    ),
    "nethermind": RunnerCommands(("blocktest",), ("enginetest",)),
    "erigon": RunnerCommands(("blocktest",), ("enginetest",), ("--jsonout",)),
    "reth": RunnerCommands(("blocktest",), ("enginetest",)),
    # ethrex ships each command as a binary of its own.
    "ethrex": RunnerCommands((), (), ("--json",)),
}
"""The Clients table of the runner interface page."""


@dataclass
class RunnerRun:
    """One run of a runner over one fixture file."""

    command: List[str]
    returncode: int
    stdout: str
    stderr: str
    results: Dict[str, FixtureResult] = field(default_factory=dict)
    error: str | None = None
    bal_report: Dict[Hash, List[BalExecution | BalFallback]] = field(
        default_factory=dict
    )


def parse_run(
    command: List[str], returncode: int, stdout: str, stderr: str
) -> RunnerRun:
    """
    Parse a runner's output, trusting it only after exit 0 or 1; anything
    else is a run error that carries stderr.
    """
    run = RunnerRun(
        command=command, returncode=returncode, stdout=stdout, stderr=stderr
    )
    if returncode not in TRUSTED_EXIT_CODES:
        run.error = f"runner exited with code {returncode}"
        return run
    try:
        results = RunnerResults.model_validate_json(stdout).root
    except ValidationError as e:
        run.error = f"runner printed results that do not parse: {e}"
        return run
    for result in results:
        if result.name in run.results:
            run.error = f"runner reported '{result.name}' twice"
            return run
        run.results[result.name] = result
    run.bal_report = parse_bal_report(stderr)
    return run


BAL_EVENTS: Dict[str, type[BalExecution] | type[BalFallback]] = {
    "balExecution": BalExecution,
    "balFallback": BalFallback,
}


def parse_bal_report(
    stderr: str,
) -> Dict[Hash, List[BalExecution | BalFallback]]:
    """
    Collect the execution report lines on stderr by block hash, which ties
    each line to its block when fixtures interleave. Other lines are logs.
    """
    report: Dict[Hash, List[BalExecution | BalFallback]] = {}
    for line in stderr.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict) or event.get("event") not in BAL_EVENTS:
            continue
        try:
            entry = BAL_EVENTS[event["event"]].model_validate(event)
        except ValidationError:
            # Left out, so its block shows as having no line.
            continue
        report.setdefault(entry.hash, []).append(entry)
    return report


def bal_problems(
    fixture: BaseFixture,
    report: Dict[Hash, List[BalExecution | BalFallback]],
) -> List[str]:
    """
    Return one line per valid block carrying an access list that did not
    run on the parallel executor, and per fallback in the fixture.

    Invalid blocks may legitimately run sequentially, as when the runner
    drops a list that does not match its header, so only their fallbacks
    count.
    """
    # (number, hash, expected to run in parallel) per block
    blocks: List[Tuple[int, Hash, bool]] = []
    if isinstance(fixture, BlockchainFixture):
        for block in fixture.blocks:
            if isinstance(block, FixtureBlock):
                blocks.append(
                    (
                        int(block.header.number),
                        block.header.block_hash,
                        block.block_access_list is not None,
                    )
                )
            elif block.rlp_decoded is not None:
                header = block.rlp_decoded.header
                blocks.append((int(header.number), header.block_hash, False))
    elif isinstance(fixture, BlockchainEngineFixture):
        for payload in fixture.payloads:
            execution_payload = payload.params[0]
            blocks.append(
                (
                    int(execution_payload.number),
                    execution_payload.block_hash,
                    payload.valid()
                    and payload.error_code is None
                    and execution_payload.block_access_list is not None,
                )
            )
    else:
        raise ValueError(f"Unsupported fixture format: {fixture.format_name}")

    problems = []
    for number, block_hash, needs_parallel in blocks:
        entries = report.get(block_hash, [])
        for entry in entries:
            if isinstance(entry, BalFallback):
                problems.append(
                    f"block {number} fell back to sequential "
                    f'("{entry.parallel_error}"), which found it '
                    f"{entry.sequential_result}"
                )
        if not needs_parallel:
            continue
        executions = [e for e in entries if isinstance(e, BalExecution)]
        if not executions:
            problems.append(f"block {number} has no balExecution line")
        for execution in executions:
            if execution.path != "parallel":
                problems.append(
                    f"block {number} ran {execution.path} "
                    f'(reason "{execution.reason}")'
                )
    return problems


CLIENT_ERROR_ADAPTER: TypeAdapter[ClientValidationError] = TypeAdapter(
    Annotated[ClientValidationError, ExceptionMapperValidator]
)


def map_client_error(
    error: str, mapper: ExceptionMapper
) -> ClientValidationError:
    """Map a client's error through its exception mapper, as engine does."""
    return CLIENT_ERROR_ADAPTER.validate_python(
        error, context={"exception_mapper": mapper}
    )


def rejection_problems(
    fixture: BaseFixture, result: FixtureResult, mapper: ExceptionMapper
) -> List[str]:
    """
    Compare the blocks or payloads a runner rejected, and why, with what the
    fixture expects; return one line per mismatch.

    A payload that expects a JSON-RPC error is checked by its code, which
    belongs to the Engine API rather than to the client.
    """
    expected: Dict[int, Any] = {}
    if isinstance(fixture, BlockchainFixture):
        kind = "block"
        for index, block in enumerate(fixture.blocks):
            if isinstance(block, InvalidFixtureBlock):
                expected[index] = block.expect_exception
    elif isinstance(fixture, BlockchainEngineFixture):
        kind = "payload"
        for index, payload in enumerate(fixture.payloads):
            if payload.error_code is not None:
                expected[index] = payload.error_code
            elif payload.validation_error is not None:
                expected[index] = payload.validation_error
    else:
        raise ValueError(f"Unsupported fixture format: {fixture.format_name}")

    problems = []
    rejected = {
        rejection.index: rejection.error for rejection in result.rejections
    }
    for index in sorted(expected.keys() | rejected.keys()):
        want = expected.get(index)
        error = rejected.get(index)
        if error is None:
            problems.append(
                f"{kind} {index}: expected {want}, client accepted it"
            )
            continue
        if want is None:
            problems.append(
                f'{kind} {index}: expected valid, client said "{error}"'
            )
            continue
        if isinstance(want, EngineAPIError):
            if not error.startswith(f"{want.value}:"):
                problems.append(
                    f"{kind} {index}: expected error code {want.value}, "
                    f'client said "{error}"'
                )
            continue
        mapped = map_client_error(error, mapper)
        if isinstance(mapped, UndefinedException):
            problems.append(
                f'{kind} {index}: expected {want}, client said "{error}" '
                f"(maps to nothing in {mapper.mapper_name})"
            )
        elif want not in mapped:
            got = " | ".join(str(e) for e in mapped.exceptions)
            problems.append(
                f'{kind} {index}: expected {want}, client said "{error}" '
                f"(maps to {got})"
            )
    return problems


@lru_cache(maxsize=1)
def read_fixture_file(path: Path) -> Dict[str, Any]:
    """Read a fixture file, keeping only the last one: tests come by file."""
    return json.loads(path.read_text())


class ClientRunner(FixtureConsumer, EthereumCLI):
    """
    A client binary that may speak the runner interface.

    A fixture consumer that inherits this runs a fixture through the runner
    when the binary speaks the interface, and its own older code path
    otherwise.
    """

    runner_commands: ClassVar[RunnerCommands]
    runner_exception_mapper: ExceptionMapper

    def runner_command(
        self, fixture_format: FixtureFormat
    ) -> Tuple[str, ...] | None:
        """Return the runner command for a fixture format, if it has one."""
        if fixture_format == BlockchainFixture:
            return self.runner_commands.blocktest
        if fixture_format == BlockchainEngineFixture:
            return self.runner_commands.enginetest
        return None

    def can_consume(self, fixture_format: FixtureFormat) -> bool:
        """
        Return whether the consumer takes a format, on its old path or
        through the runner interface, which adds Blockchain Engine Tests.
        """
        return super().can_consume(
            fixture_format
        ) or self.speaks_runner_interface(fixture_format)

    def require_runner_interface(self) -> None:
        """Raise unless the binary speaks the interface for some format."""
        if not any(
            self.speaks_runner_interface(fixture_format)
            for fixture_format in (BlockchainFixture, BlockchainEngineFixture)
        ):
            raise Exception(
                f"{self.binary} does not speak the client runner interface: "
                f"its help lists no {INTERFACE_FLAG}"
            )

    def consume_fixture(
        self,
        fixture_format: FixtureFormat,
        fixture_path: Path,
        fixture_name: str | None = None,
        debug_output_path: Path | None = None,
    ) -> None:
        """Consume a fixture through the runner, the only path it has."""
        if not self.speaks_runner_interface(fixture_format):
            raise Exception(
                f"{self.binary} does not run "
                f"{fixture_format.format_name} fixtures"
            )
        self.consume_with_runner(
            fixture_format, fixture_path, fixture_name, debug_output_path
        )

    @cache  # noqa: B019
    def speaks_runner_interface(self, fixture_format: FixtureFormat) -> bool:
        """
        Return whether the binary runs `fixture_format` through the runner
        interface, judged by its help listing a flag only the interface has.
        """
        command = self.runner_command(fixture_format)
        if command is None:
            return False
        try:
            result = self._run_command([*command, "--help"])
        except Exception:
            return False
        return INTERFACE_FLAG in result.stdout + result.stderr

    @cache  # noqa: B019
    def run_fixture_file(
        self,
        fixture_format: FixtureFormat,
        fixture_path: Path,
        bal_mode: BalMode = "parallel",
    ) -> RunnerRun:
        """Run a fixture file once per mode, and cache the run."""
        command = self.runner_command(fixture_format)
        assert command is not None
        args = [
            *command,
            *self.runner_commands.json_flags,
            *BAL_MODE_FLAGS[bal_mode],
            str(fixture_path),
        ]
        result = self._run_command(args, read_only=[fixture_path])
        return parse_run(
            list(result.args), result.returncode, result.stdout, result.stderr
        )

    @cache  # noqa: B019
    def dump_run(
        self,
        fixture_format: FixtureFormat,
        fixture_path: Path,
        bal_mode: BalMode,
        dump_dir: Path,
    ) -> None:
        """Dump a run's command and output, once per directory."""
        run = self.run_fixture_file(fixture_format, fixture_path, bal_mode)
        dump_files_to_directory(
            dump_dir,
            {
                "consume_direct_args.py": run.command,
                "consume_direct_returncode.txt": run.returncode,
                "consume_direct_stdout.txt": run.stdout,
                "consume_direct_stderr.txt": run.stderr,
            },
        )

    def consume_with_runner(
        self,
        fixture_format: FixtureFormat,
        fixture_path: Path,
        fixture_name: str | None = None,
        debug_output_path: Path | None = None,
        bal_mode: BalMode = "parallel",
        require_bal_parallel: bool = False,
    ) -> None:
        """
        Check one fixture, or every fixture in the file when `fixture_name`
        is `None`, against the runner's results.

        A named fixture must pass and give the reasons the fixture expects,
        read through the client's exception mapper. Without a name, as when
        `fill` verifies its output, every fixture in the file must have a
        result, and only `pass` is checked.

        In the parallel mode, a valid block with an access list that did not
        run on the parallel executor, or any fallback, is a warning, or a
        failure with `require_bal_parallel`.

        `debug_output_path` receives the run's command and output once, as
        the run covers the whole file in one mode.
        """
        run = self.run_fixture_file(fixture_format, fixture_path, bal_mode)
        if debug_output_path:
            self.dump_run(
                fixture_format, fixture_path, bal_mode, debug_output_path
            )
        if run.error is not None:
            raise Exception(
                f"{run.error}:\n{' '.join(run.command)}\n\n"
                f"stderr:\n{run.stderr}"
            )
        if fixture_name is None:
            missing = [
                name
                for name in read_fixture_file(fixture_path)
                if name not in run.results
            ]
            failed = [name for name, r in run.results.items() if not r.passed]
            if missing or failed:
                raise AssertionError(
                    "\n".join(
                        [
                            *(f"no result for '{name}'" for name in missing),
                            *(f"'{name}' failed" for name in failed),
                        ]
                    )
                )
            return

        result = run.results.get(fixture_name)
        if result is None:
            raise AssertionError(
                f"Runner reported no result for '{fixture_name}':\n"
                f"{' '.join(run.command)}"
            )
        fixture = fixture_format.model_validate(
            read_fixture_file(fixture_path)[fixture_name]
        )
        problems = rejection_problems(
            fixture, result, self.runner_exception_mapper
        )
        if not result.passed:
            details = (
                [f"client details: {result.model_extra}"]
                if result.model_extra
                else []
            )
            raise AssertionError(
                "\n".join(
                    [
                        "Runner reported the fixture failed.",
                        *problems,
                        *details,
                    ]
                )
            )
        if problems:
            raise AssertionError(
                "\n".join(
                    [
                        "Runner passed the fixture; its rejections differ.",
                        *problems,
                    ]
                )
            )
        if bal_mode != "parallel":
            return
        bal_issues = bal_problems(fixture, run.bal_report)
        if not bal_issues:
            return
        message = "\n".join(
            [f"{fixture_name} did not run in parallel:", *bal_issues]
        )
        if require_bal_parallel:
            raise AssertionError(message)
        warnings.warn(BalExecutionWarning(message), stacklevel=2)
