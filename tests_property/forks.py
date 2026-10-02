"""Forks the property suite runs on, taken from the spec's fork list."""

from typing import List

from ethereum_spec_tools.forks import Hardfork

ALL_FORKS = [fork.short_name for fork in Hardfork.discover()]

# Blob-parameter-only forks copy their parent with a new blob schedule, so
# the latest fork's parent is the last fork that is not one of them.
_FEATURE_FORKS = [f for f in ALL_FORKS if not f.startswith("bpo")]

# The latest fork and its parent.
PROPERTY_TEST_FORKS = _FEATURE_FORKS[-2:]


def is_at_or_after(fork_name: str, introduced_in: str) -> bool:
    """Return whether `fork_name` is `introduced_in` or a later fork."""
    return ALL_FORKS.index(fork_name) >= ALL_FORKS.index(introduced_in)


def forks_from(introduced_in: str) -> List[str]:
    """Return the tested forks that include a feature, by its first fork."""
    forks = [
        f for f in PROPERTY_TEST_FORKS if is_at_or_after(f, introduced_in)
    ]
    if not forks:
        raise ValueError(f"no tested fork at or after {introduced_in}")
    return forks


def past_fork(fork_name: str) -> List[str]:
    """Return `fork_name` alone, for a rule that only that fork follows."""
    if fork_name not in ALL_FORKS:
        raise ValueError(f"unknown fork: {fork_name}")
    return [fork_name]
