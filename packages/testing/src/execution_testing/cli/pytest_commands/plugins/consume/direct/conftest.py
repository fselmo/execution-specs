"""
A pytest plugin that configures the consume command to act as a test runner for
"direct" client fixture consumer interfaces.

For example, via go-ethereum's `evm blocktest` or `evm statetest` commands.
"""

import json
import tempfile
import warnings
from pathlib import Path
from typing import Any, Generator, List

import pytest

from execution_testing.base_types import to_json
from execution_testing.cli.pytest_commands.plugins.consume.consume import (
    FixturesSource,
)
from execution_testing.client_clis.client_runner import (
    BAL_MODE_FLAGS,
    BalMode,
)
from execution_testing.client_clis.ethereum_cli import (
    EthereumCLI,
    parse_executable,
)
from execution_testing.client_clis.fixture_consumer_tool import (
    FixtureConsumerTool,
)
from execution_testing.fixtures import (
    BaseFixture,
    BlockchainEngineFixture,
    BlockchainFixture,
    FixtureFormat,
    StateFixture,
)
from execution_testing.fixtures.consume import (
    TestCaseIndexFile,
    TestCaseStream,
)
from execution_testing.fixtures.file import Fixtures

DIRECT_FIXTURE_FORMATS: list[FixtureFormat] = [
    StateFixture,
    BlockchainFixture,
    BlockchainEngineFixture,
]
"""
Formats a direct consumer may take; Blockchain Engine Tests need a binary
that speaks the client runner interface.
"""


class CollectOnlyCLI(EthereumCLI):
    """A dummy CLI for use with `--collect-only`."""

    def __init__(self) -> None:  # noqa: D107
        pass


class CollectOnlyFixtureConsumer(
    FixtureConsumerTool,
    CollectOnlyCLI,
    fixture_formats=list(BaseFixture.formats.values()),
):
    """A dummy fixture consumer for use with `--collect-only`."""

    def consume_fixture(self, *args: Any, **kwargs: Any) -> None:  # noqa: D102
        pass


def parse_bal_modes(value: str) -> List[str]:
    """Parse `--bal-modes` into a list of known modes."""
    modes = [mode.strip() for mode in value.split(",") if mode.strip()]
    unknown = [mode for mode in modes if mode not in BAL_MODE_FLAGS]
    if unknown or not modes:
        raise ValueError(
            f"Unknown BAL modes {unknown}; choose from {list(BAL_MODE_FLAGS)}"
        )
    return modes


def pytest_addoption(parser: pytest.Parser) -> None:  # noqa: D103
    consume_group = parser.getgroup(
        "consume_direct",
        "Arguments related to consuming fixtures via a client",
    )

    consume_group.addoption(
        "--bin",
        action="append",
        dest="fixture_consumer_bin",
        type=parse_executable,
        default=[],
        help=(
            "A client's test runner binary, such as geth's `evm`: a host "
            "path, or `docker:<image>` to run the image's entrypoint, or "
            "`docker:<image>#<binary>` to run another binary in the image. "
            "Flag can be used multiple times to specify multiple fixture "
            "consumer binaries."
        ),
    )
    consume_group.addoption(
        "--bal-modes",
        action="store",
        dest="bal_modes",
        type=parse_bal_modes,
        default=None,
        help=(
            "Comma-separated ways to execute blocks with access lists, each "
            "run as its own test: `parallel` (the runner's default), "
            "`sequential` and `withhold` (block tests only). Needs a binary "
            "that speaks the client runner interface; without the flag, "
            "tests run once, in parallel mode, with unchanged test ids."
        ),
    )
    consume_group.addoption(
        "--require-bal-parallel",
        action="store_true",
        dest="require_bal_parallel",
        default=False,
        help=(
            "Fail, instead of warning, when a valid block with an access "
            "list does not run on the parallel executor, or a block falls "
            "back to the sequential one, in the parallel mode."
        ),
    )
    consume_group.addoption(
        "--traces",
        action="store_true",
        dest="consumer_collect_traces",
        default=False,
        help=(
            "Collect traces of the execution information from the fixture "
            "consumer tool."
        ),
    )
    debug_group = parser.getgroup("debug", "Arguments defining debug behavior")
    debug_group.addoption(
        "--dump-dir",
        action="store",
        dest="base_dump_dir",
        type=Path,
        default=None,
        help="Path to dump the fixture consumer tool debug output.",
    )


def pytest_configure(config: pytest.Config) -> None:  # noqa: D103
    config.supported_fixture_formats = DIRECT_FIXTURE_FORMATS  # type: ignore[attr-defined]
    fixture_consumers = []
    for fixture_consumer_bin_path in config.getoption("fixture_consumer_bin"):
        fixture_consumers.append(
            FixtureConsumerTool.from_binary_path(
                binary_path=fixture_consumer_bin_path,
                trace=config.getoption("consumer_collect_traces"),
            )
        )
    if config.option.markers:
        return
    elif not fixture_consumers and config.option.collectonly:
        warnings.warn(
            (
                "No fixture consumer binaries provided; using a dummy "
                "consumer for collect-only; all possible fixture formats "
                "will be collected. Specify fixture consumer(s) via `--bin` "
                "to see actual collection results."
            ),
            stacklevel=1,
        )
        fixture_consumers = [CollectOnlyFixtureConsumer()]
    elif not fixture_consumers:
        pytest.exit(
            "No fixture consumer binaries provided; please specify a binary "
            "path via `--bin`."
        )
    config.fixture_consumers = fixture_consumers  # type: ignore[attr-defined]
    # Collect only the formats some binary can consume, so a binary without
    # the runner interface collects no Blockchain Engine Tests.
    config.supported_fixture_formats = [  # type: ignore[attr-defined]
        fixture_format
        for fixture_format in DIRECT_FIXTURE_FORMATS
        if any(
            fixture_consumer.can_consume(fixture_format)
            for fixture_consumer in fixture_consumers
        )
    ]


@pytest.fixture(scope="function")
def test_dump_dir(
    request: pytest.FixtureRequest, fixture_path: Path, fixture_name: str
) -> Path | None:
    """The directory to write evm debug output to."""
    base_dump_dir = request.config.getoption("base_dump_dir")
    if not base_dump_dir:
        return None
    if len(fixture_name) > 142:
        # ensure file name is not too long for eCryptFS
        fixture_name = fixture_name[:70] + "..." + fixture_name[-70:]
    return base_dump_dir / fixture_path.stem / fixture_name.replace("/", "-")


@pytest.fixture
def fixture_path(
    test_case: TestCaseIndexFile | TestCaseStream,
    fixtures_source: FixturesSource,
) -> Generator[Path, None, None]:
    """
    Path to the current JSON fixture file.

    If the fixture source is stdin, the fixture is written to a temporary json
    file.
    """
    if fixtures_source.is_stdin:
        assert isinstance(test_case, TestCaseStream)
        temp_dir = tempfile.TemporaryDirectory()
        fixture_path = (
            Path(temp_dir.name) / f"{test_case.id.replace('/', '_')}.json"
        )
        fixtures = Fixtures({test_case.id: test_case.fixture})
        with open(fixture_path, "w") as f:
            json.dump(to_json(fixtures), f, indent=4)
        yield fixture_path
        temp_dir.cleanup()
    else:
        assert isinstance(test_case, TestCaseIndexFile)
        yield fixtures_source.path / test_case.json_path


@pytest.fixture(scope="function")
def fixture_name(test_case: TestCaseIndexFile | TestCaseStream) -> str:
    """Name of the current fixture."""
    return test_case.id


@pytest.fixture
def bal_mode() -> BalMode:
    """The BAL mode when `--bal-modes` is not given."""
    return "parallel"


@pytest.fixture
def require_bal_parallel(request: pytest.FixtureRequest) -> bool:
    """Whether a block that did not run in parallel fails its test."""
    return request.config.getoption("require_bal_parallel")


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Parametrize test cases for every fixture consumer and BAL mode."""
    metafunc.parametrize(
        "fixture_consumer",
        (
            pytest.param(
                fixture_consumer, id=str(fixture_consumer.__class__.__name__)
            )
            for fixture_consumer in metafunc.config.fixture_consumers  # type: ignore[attr-defined]
        ),
    )
    bal_modes = metafunc.config.getoption("bal_modes")
    if bal_modes:
        metafunc.parametrize(
            "bal_mode",
            [pytest.param(mode, id=f"bal_{mode}") for mode in bal_modes],
        )


def bal_mode_applies(fixture_format: FixtureFormat, mode: str) -> bool:
    """
    Return whether a BAL mode applies to a format: only blockchain formats
    have access lists, and only block tests can withhold them.
    """
    if mode == "parallel":
        return True
    if mode == "withhold":
        return fixture_format == BlockchainFixture
    return fixture_format in (BlockchainFixture, BlockchainEngineFixture)


def pytest_collection_modifyitems(
    config: pytest.Config, items: List[pytest.Item]
) -> None:
    """
    Deselect the tests a binary cannot run, as when ethrex's `blocktest`
    meets an engine fixture, and the BAL modes a format has no use for.
    """
    selected, deselected = [], []
    for item in items:
        assert isinstance(item, pytest.Function)
        params = item.callspec.params
        test_case = params["test_case"]
        fixture_consumer = params["fixture_consumer"]
        mode = params.get("bal_mode", "parallel")
        assert isinstance(test_case, (TestCaseIndexFile, TestCaseStream))
        assert isinstance(fixture_consumer, FixtureConsumerTool)
        assert isinstance(mode, str)
        if fixture_consumer.can_consume(test_case.format) and bal_mode_applies(
            test_case.format, mode
        ):
            selected.append(item)
        else:
            deselected.append(item)
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = selected
