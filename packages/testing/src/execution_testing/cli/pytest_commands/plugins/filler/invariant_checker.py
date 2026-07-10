"""
Enable chain-invariant checking during fill.

When ``--invariant-checks`` is passed, every filled block is checked
against global chain invariants (ether conservation, gas accounting,
nonce monotonicity — see ``execution_testing.specs.invariants``).
Violations are emitted as ``InvariantViolationWarning`` warnings and
recorded in the fixture's ``_info`` metadata, so a run can be audited
without failing tests while the invariant ledger is validated against
the full suite.
"""

import pytest

from execution_testing.specs.invariants import enable_invariant_checks


def pytest_addoption(parser: pytest.Parser) -> None:
    """Add the `--invariant-checks` command-line option to pytest."""
    group = parser.getgroup("filler", "Arguments defining filler behavior")
    group.addoption(
        "--invariant-checks",
        action="store_true",
        dest="invariant_checks",
        default=False,
        help=(
            "Check global chain invariants (ether conservation, gas "
            "accounting, nonce monotonicity) on every filled block. "
            "Violations are reported as warnings and recorded in "
            "fixture metadata."
        ),
    )


def pytest_configure(config: pytest.Config) -> None:
    """Enable invariant checks when requested."""
    if config.getoption("invariant_checks", default=False):
        enable_invariant_checks()
