"""Check chain invariants on every filled block (`fill --invariant-checks`)."""

import pytest

from execution_testing.specs.invariants import enable_invariant_checks


def pytest_addoption(parser: pytest.Parser) -> None:
    """Add the `--invariant-checks` command-line option to pytest."""
    group = parser.getgroup("debug", "Arguments defining debug behavior")
    group.addoption(
        "--invariant-checks",
        action="store_true",
        dest="invariant_checks",
        default=False,
        help=(
            "Check chain invariants (ether conservation, gas accounting, "
            "nonces, block access list) on every filled block and warn "
            "with InvariantViolationWarning on each violation."
        ),
    )


@pytest.hookimpl(trylast=True)
def pytest_configure(config: pytest.Config) -> None:
    """Enable the checks and the transition tool's access witness."""
    if not config.getoption("invariant_checks"):
        return
    enable_invariant_checks()
    # Absent when the filler exits early, e.g. for `--help`.
    t8n = getattr(config, "t8n", None)
    if t8n is not None:
        t8n.compute_bal_witness = True


def pytest_unconfigure(config: pytest.Config) -> None:
    """Disable the checks so an in-process pytester run leaves no trace."""
    if config.getoption("invariant_checks"):
        enable_invariant_checks(False)
