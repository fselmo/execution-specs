"""Fixture consumer tool abstract class."""

import json
import re
import warnings
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Sequence, Type

from execution_testing.exceptions import (
    EngineAPIError,
    ExceptionInstanceOrList,
    ExceptionMapper,
    UndefinedException,
)
from execution_testing.exceptions.exceptions.base import to_pipe_str
from execution_testing.fixtures import (
    BlockchainEngineFixture,
    BlockchainFixture,
    FixtureConsumer,
    FixtureFormat,
)
from execution_testing.fixtures.blockchain import InvalidFixtureBlock

from .ethereum_cli import EthereumCLI

ExpectedRejection = ExceptionInstanceOrList | EngineAPIError
"""An expected exception, or the JSON-RPC error code of an engine payload."""

JSON_RPC_ERROR_PATTERN = re.compile(r"^(-?\d+): ")
"""How a runner reports a payload rejected through a JSON-RPC error."""


class RejectionReasonError(Exception):
    """
    A client rejected the expected blocks, but for a reason that does not
    map to the exception the fixture expects.
    """


def expected_rejections(
    fixture: BlockchainFixture | BlockchainEngineFixture,
) -> List[ExpectedRejection | None]:
    """
    Return what each of the fixture's blocks (or engine payloads) expects,
    in order: `None` for a valid one.
    """
    if isinstance(fixture, BlockchainFixture):
        return [
            block.expect_exception
            if isinstance(block, InvalidFixtureBlock)
            else None
            for block in fixture.blocks
        ]
    return [
        payload.error_code
        if payload.error_code is not None
        else payload.validation_error
        for payload in fixture.payloads
    ]


def verify_rejections(
    expected: Sequence[ExpectedRejection | None],
    result: Dict[str, Any],
    exception_mapper: ExceptionMapper,
) -> None:
    """
    Check the rejections in one result of a client's runner.

    The result's `rejections` list names each rejected block by its index
    in the fixture and carries the client's raw error. Raise `Exception` if
    a block the fixture expects valid was rejected or an invalid one was
    not. Raise `RejectionReasonError` if an error does not map to the
    expected exception, so the caller can decide whether that fails.

    A result without `rejections` comes from a runner that predates the
    field; warn and skip the check.
    """
    if "rejections" not in result:
        warnings.warn(
            "The runner's results have no `rejections` field, so the "
            "reasons for rejected blocks are not checked.",
            stacklevel=2,
        )
        return
    reported = {r["index"]: r["error"] for r in result["rejections"]}

    wrong_outcomes: List[str] = []
    wrong_reasons: List[str] = []
    for index, want in enumerate(expected):
        error = reported.pop(index, None)
        if want is None:
            if error is not None:
                wrong_outcomes.append(
                    f"index {index}: rejected, but the fixture expects it "
                    f'to be valid: "{error}"'
                )
        elif error is None:
            wrong_outcomes.append(
                f"index {index}: the fixture expects "
                f"{_describe(want)}, but the runner reported no rejection"
            )
        else:
            mismatch = _reason_mismatch(want, error, exception_mapper)
            if mismatch:
                wrong_reasons.append(f"index {index}: {mismatch}")
    for index, error in reported.items():
        wrong_outcomes.append(
            f"index {index}: rejected, but the fixture has no such block: "
            f'"{error}"'
        )

    if wrong_outcomes:
        raise Exception(
            "Client rejections do not match the fixture's invalid blocks:\n"
            + "\n".join(wrong_outcomes)
        )
    if wrong_reasons:
        raise RejectionReasonError(
            "Client rejected a block for an unexpected reason "
            f"(mapper: {exception_mapper.mapper_name}):\n"
            + "\n".join(wrong_reasons)
        )


def _describe(
    want: ExpectedRejection,
) -> str:
    if isinstance(want, EngineAPIError):
        return f"JSON-RPC error {want.value} ({want.name})"
    return f'"{to_pipe_str(want)}"'


def _reason_mismatch(
    want: ExpectedRejection,
    error: str,
    exception_mapper: ExceptionMapper,
) -> str | None:
    """Describe why `error` does not match `want`, or return `None`."""
    json_rpc_error = JSON_RPC_ERROR_PATTERN.match(error)
    if isinstance(want, EngineAPIError):
        # The engine simulators judge a JSON-RPC error on its code alone.
        if json_rpc_error and int(json_rpc_error.group(1)) == want.value:
            return None
        return f'expected {_describe(want)}, got "{error}"'
    if json_rpc_error:
        return (
            f"expected {_describe(want)}, got a JSON-RPC error instead "
            f'of an invalid status: "{error}"'
        )
    got = exception_mapper.message_to_exception(error)
    if isinstance(got, UndefinedException):
        return (
            f'expected {_describe(want)}, got "{error}", which the mapper '
            "does not map to any exception"
        )
    wanted = want if isinstance(want, list) else [want]
    if any(exception in got for exception in wanted):
        return None
    return (
        f'expected {_describe(want)}, got "{error}" (mapped to '
        f'"{to_pipe_str(got)}")'
    )


@lru_cache(maxsize=4)
def _load_fixture_file(fixture_path: Path) -> Dict[str, Any]:
    """Load a fixture file once for all the tests consumed from it."""
    with open(fixture_path) as f:
        return json.load(f)


class FixtureConsumerTool(FixtureConsumer, EthereumCLI):
    """
    Fixture consumer tool abstract base class which should be inherited by all
    fixture consumer tool implementations.
    """

    registered_tools: List[Type["FixtureConsumerTool"]] = []
    default_tool: Type["FixtureConsumerTool"] | None = None
    exception_mapper: ExceptionMapper | None = None

    def __init_subclass__(cls, *, fixture_formats: List[FixtureFormat]):
        """Register all subclasses of FixtureConsumerTool as possible tools."""
        FixtureConsumerTool.register_tool(cls)
        cls.fixture_formats = fixture_formats

    def check_rejections(
        self,
        fixture_format: FixtureFormat,
        fixture_path: Path,
        fixture_name: str | None,
        results: List[Dict[str, Any]],
    ) -> None:
        """
        Check the rejections in the runner's results for `fixture_name`
        against the fixture's expected exceptions; see `verify_rejections`.
        """
        if fixture_name is None or fixture_format not in (
            BlockchainFixture,
            BlockchainEngineFixture,
        ):
            return
        assert self.exception_mapper is not None, (
            f"{self.__class__.__name__} has no exception mapper"
        )
        # Some runners report the name without the test file path.
        named = [r for r in results if fixture_name.endswith(r["name"])]
        if not named:
            raise Exception(f"No runner result for {fixture_name}")
        fixture = fixture_format.model_validate(
            _load_fixture_file(fixture_path)[fixture_name]
        )
        assert isinstance(
            fixture, (BlockchainFixture, BlockchainEngineFixture)
        )
        expected = expected_rejections(fixture)
        for result in named:
            verify_rejections(expected, result, self.exception_mapper)
