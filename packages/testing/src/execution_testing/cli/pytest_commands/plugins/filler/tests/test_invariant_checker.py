"""Test filling with `--invariant-checks`."""

import textwrap

import pytest

FORK = "Amsterdam"

TEST_MODULE_DIR = "tests/amsterdam/dummy_test_module"

# Each block writes a different slot, so a block checked against another
# block's witness breaks the witness bounds.
TWO_BLOCK_MODULE = textwrap.dedent(
    """\
    import pytest

    from execution_testing import (
        Account,
        Alloc,
        Block,
        BlockchainTestFiller,
        Hash,
        Op,
        Transaction,
    )

    @pytest.mark.valid_at("{fork}")
    def test_case(blockchain_test: BlockchainTestFiller, pre: Alloc) -> None:
        contract = pre.deploy_contract(
            Op.SSTORE(Op.CALLDATALOAD(0), 1)
        )
        sender = pre.fund_eoa()

        def write(slot: int) -> Transaction:
            return Transaction(sender=sender, to=contract, data=Hash(slot))

        blockchain_test(
            pre=pre,
            post={{contract: Account(storage={{1: 1, 2: 1}})}},
            blocks=[Block(txs=[write(1)]), Block(txs=[write(2)])],
        )
    """
)

# Plants a violation to show that one reaches the fill as a warning.
VIOLATING_CONFTEST = textwrap.dedent(
    """\
    import pytest

    from execution_testing.specs import invariants
    from execution_testing.specs.invariants import InvariantViolation

    @pytest.fixture(autouse=True)
    def planted_violation(monkeypatch):
        monkeypatch.setattr(
            invariants,
            "check_nonce_monotonicity",
            lambda *args: [
                InvariantViolation(invariant="planted", message="")
            ],
        )
    """
)

AS_ERROR = (
    "error::execution_testing.specs.invariants.InvariantViolationWarning"
)


def fill(pytester: pytest.Pytester, *args: str) -> pytest.RunResult:
    """Fill the two-block module at the pinned fork with the checks on."""
    module_dir = pytester.path / TEST_MODULE_DIR
    module_dir.mkdir(parents=True)
    module = module_dir / "test_dummy.py"
    module.write_text(TWO_BLOCK_MODULE.format(fork=FORK))
    pytester.copy_example(
        name="src/execution_testing/cli/pytest_commands/pytest_ini_files/pytest-fill.ini"
    )
    # An in-process run restores `sys.modules` but not the `ethereum`
    # package's `trace` attribute, so a second run's t8n installs its tracer
    # on the first run's `ethereum.trace` while the EVM emits to a new one.
    # Each fill gets its own process instead.
    return pytester.runpytest_subprocess(
        "-c",
        "pytest-fill.ini",
        "--fork",
        FORK,
        "--no-html",
        "--output",
        "fixtures",
        "--invariant-checks",
        *args,
        str(module.relative_to(pytester.path)),
    )


def test_cached_formats_use_their_own_witness(
    pytester: pytest.Pytester,
) -> None:
    """
    Fill two formats of one test, the second from the t8n output cache, with
    violations as errors: each block is checked against its own witness.
    """
    result = fill(
        pytester,
        "-m",
        "blockchain_test or blockchain_test_engine",
        "-W",
        AS_ERROR,
    )
    result.assert_outcomes(passed=2, failed=0)


def test_violation_warns(pytester: pytest.Pytester) -> None:
    """A violation reaches the fill as a warning and the test still passes."""
    (pytester.path / "conftest.py").write_text(VIOLATING_CONFTEST)
    result = fill(pytester, "-m", "blockchain_test")
    result.assert_outcomes(passed=1, failed=0)
    result.stdout.fnmatch_lines(["*InvariantViolationWarning: [[]planted]*"])


def test_violation_fails_when_warnings_are_errors(
    pytester: pytest.Pytester,
) -> None:
    """With the warning made an error, as in CI, a violation fails the fill."""
    (pytester.path / "conftest.py").write_text(VIOLATING_CONFTEST)
    result = fill(pytester, "-m", "blockchain_test", "-W", AS_ERROR)
    result.assert_outcomes(passed=0, failed=1)
