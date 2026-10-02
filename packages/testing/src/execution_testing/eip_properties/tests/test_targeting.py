"""Tests for reading a fork's added precompiles off the manifest."""

from execution_testing.forks import Osaka, Prague

from ..targeting import (
    added_precompiles,
    parent_fork,
)


def test_parent_fork_is_the_preceding_fork() -> None:
    """Prague is the parent Osaka is descended from."""
    parent = parent_fork(Osaka)
    assert parent is not None
    assert parent.name() == Prague.name()


def test_added_precompiles_match_manifest() -> None:
    """Osaka introduces p256verify (0x100) and nothing else."""
    assert added_precompiles(Osaka) == [0x100]


def test_prague_added_bls_precompiles() -> None:
    """Prague introduces the BLS12-381 precompile range 0x0b-0x11."""
    assert added_precompiles(Prague) == list(range(0x0B, 0x12))
