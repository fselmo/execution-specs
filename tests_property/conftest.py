"""
Property-based tests for spec components.

This suite is intentionally separate from `tests/` (which is collected by
the `fill` command) and runs as plain pytest with Hypothesis:

    just test-spec-properties
    just test-spec-properties --hypothesis-profile=nightly

Profiles:
- `ci` (default): derandomized so CI is reproducible; failures print the
  reproducing `@example(...)` blob. Check found regressions in as explicit
  `@example(...)` decorators on the failing test.
- `dev`: randomized exploration for local runs.
- `nightly`: large randomized budget for scheduled runs.
"""

import pytest
from hypothesis import HealthCheck, settings

settings.register_profile(
    "ci",
    derandomize=True,
    max_examples=200,
    print_blob=True,
)
settings.register_profile(
    "dev",
    max_examples=200,
    print_blob=True,
)
settings.register_profile(
    "nightly",
    max_examples=5000,
    print_blob=True,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile("ci")


# Fork-specific modules (vm.gas, transactions) are exercised on the most
# recent forks; shared modules (trie, rlp, state) are fork-independent.
PROPERTY_TEST_FORKS = ["osaka", "amsterdam"]


@pytest.fixture(scope="session", params=PROPERTY_TEST_FORKS)
def fork_name(request: pytest.FixtureRequest) -> str:
    """Name of the fork module under test."""
    return str(request.param)
