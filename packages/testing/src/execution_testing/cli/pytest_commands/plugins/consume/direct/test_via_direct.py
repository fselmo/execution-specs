"""
Executes a JSON test fixture directly against a client using a dedicated client
interface similar to geth's EVM 'blocktest' command.
"""

from pathlib import Path

import pytest

from execution_testing.client_clis.client_runner import (
    BalMode,
    ClientRunner,
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
    bal_mode: BalMode,
    require_bal_parallel: bool,
) -> None:
    """
    Generic test function used to call the fixture consumer with a given
    fixture file path and a fixture name (for a single test run).
    """
    if isinstance(
        fixture_consumer, ClientRunner
    ) and fixture_consumer.speaks_runner_interface(test_case.format):
        fixture_consumer.consume_with_runner(
            test_case.format,
            fixture_path,
            fixture_name=test_case.id,
            debug_output_path=test_dump_dir,
            bal_mode=bal_mode,
            require_bal_parallel=require_bal_parallel,
        )
        return
    if bal_mode != "parallel":
        pytest.skip(
            f"{fixture_consumer.__class__.__name__} does not speak the "
            f"client runner interface, so it has no {bal_mode} mode"
        )
    fixture_consumer.consume_fixture(
        test_case.format,
        fixture_path,
        fixture_name=test_case.id,
        debug_output_path=test_dump_dir,
    )
