"""
Consume fixtures through a client's test runner (`blocktest`, `enginetest`).

The interface is described in `docs/running_tests/consume/client_runners.md`.
A runner runs a whole fixture file at once, so each file runs once and every
test looks its fixture up in the cached results by full name.
"""

import json
from dataclasses import dataclass, field
from functools import cache, lru_cache
from pathlib import Path
from typing import Annotated, Any, ClassVar, Dict, List, Tuple

from pydantic import TypeAdapter, ValidationError

from execution_testing.exceptions import (
    ExceptionMapper,
    ExceptionMapperValidator,
    UndefinedException,
)
from execution_testing.fixtures import (
    BaseFixture,
    BlockchainFixture,
    FixtureFormat,
)
from execution_testing.fixtures.blockchain import InvalidFixtureBlock
from execution_testing.rpc.rpc_types import ClientValidationError

from .ethereum_cli import EthereumCLI
from .file_utils import dump_files_to_directory
from .runner_interface import FixtureResult, RunnerResults

TRUSTED_EXIT_CODES = (0, 1)
"""
Exit codes after which the results are complete: every fixture passed, or
at least one failed. Nethermind and Erigon exit 0 either way.
"""

INTERFACE_FLAG = "--bal-sequential"
"""A flag only runners that speak the interface take."""


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
    return run


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
    """
    expected: Dict[int, Any] = {}
    if isinstance(fixture, BlockchainFixture):
        kind = "block"
        for index, block in enumerate(fixture.blocks):
            if isinstance(block, InvalidFixtureBlock):
                expected[index] = block.expect_exception
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


class ClientRunner(EthereumCLI):
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
        return None

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
        self, fixture_format: FixtureFormat, fixture_path: Path
    ) -> RunnerRun:
        """Run a fixture file once, and return the cached run afterwards."""
        command = self.runner_command(fixture_format)
        assert command is not None
        args = [*command, *self.runner_commands.json_flags, str(fixture_path)]
        result = self._run_command(args, read_only=[fixture_path])
        return parse_run(
            list(result.args), result.returncode, result.stdout, result.stderr
        )

    def consume_with_runner(
        self,
        fixture_format: FixtureFormat,
        fixture_path: Path,
        fixture_name: str | None = None,
        debug_output_path: Path | None = None,
    ) -> None:
        """
        Check one fixture, or every fixture in the file when `fixture_name`
        is `None`, against the runner's results.

        A named fixture must pass and give the reasons the fixture expects,
        read through the client's exception mapper. Without a name, as when
        `fill` verifies its output, only `pass` is checked.
        """
        run = self.run_fixture_file(fixture_format, fixture_path)
        if debug_output_path:
            dump_files_to_directory(
                debug_output_path,
                {
                    "consume_direct_args.py": run.command,
                    "consume_direct_returncode.txt": run.returncode,
                    "consume_direct_stdout.txt": run.stdout,
                    "consume_direct_stderr.txt": run.stderr,
                },
            )
        if run.error is not None:
            raise Exception(
                f"{run.error}:\n{' '.join(run.command)}\n\n"
                f"stderr:\n{run.stderr}"
            )
        if fixture_name is None:
            failed = [name for name, r in run.results.items() if not r.passed]
            if failed:
                raise AssertionError(
                    "Runner reported failures:\n" + "\n".join(failed)
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
