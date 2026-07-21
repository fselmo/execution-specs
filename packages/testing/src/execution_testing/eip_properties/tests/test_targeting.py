"""Tests for aiming the fuzzer at a fork's changed surface."""

from execution_testing.forks import Osaka, Prague

from ..targeting import (
    added_precompiles,
    fuzz_precompile_targets,
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


def test_targets_cover_all_precompiles() -> None:
    """Every precompile is a possible target, up-weighted or not."""
    targets = set(fuzz_precompile_targets(Osaka))
    all_precompiles = {
        int.from_bytes(bytes(a), "big") for a in Osaka.precompiles()
    }
    assert targets == all_precompiles


def test_new_precompiles_are_up_weighted() -> None:
    """A fork's introduced precompile appears more often than an old one."""
    targets = fuzz_precompile_targets(Osaka, new_weight=5)
    assert targets.count(0x100) == 5
    assert targets.count(0x01) == 1
