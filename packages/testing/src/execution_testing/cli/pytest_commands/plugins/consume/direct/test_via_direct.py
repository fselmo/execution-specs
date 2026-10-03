"""
Executes a JSON test fixture directly against a client using a dedicated client
interface similar to geth's EVM 'blocktest' command.
"""

import warnings
from pathlib import Path

from execution_testing.client_clis.fixture_consumer_tool import (
    RejectionReasonError,
)
from execution_testing.fixtures import FixtureConsumer
from execution_testing.fixtures.consume import (
    TestCaseIndexFile,
    TestCaseStream,
)


def test_fixture(
    test_case: TestCaseIndexFile | TestCaseStream,
    fixture_consumer: FixtureConsumer,
    fixture_path: Path,
    test_dump_dir: Path | None,
    strict_exception_matching: bool,
) -> None:
    """
    Generic test function used to call the fixture consumer with a given
    fixture file path and a fixture name (for a single test run).
    """
    try:
        fixture_consumer.consume_fixture(
            test_case.format,
            fixture_path,
            fixture_name=test_case.id,
            debug_output_path=test_dump_dir,
        )
    except RejectionReasonError as e:
        if strict_exception_matching:
            raise
        warnings.warn(str(e), stacklevel=1)
