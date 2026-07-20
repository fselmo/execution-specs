"""
Fork-change-covariant parametrization: write an archetype once, run it on
every fork transition (including future ones) sourced from the manifest.

The existing fork-covariant markers (``with_all_precompiles`` etc.) are
*state*-covariant — they parametrize over what a fork *has*. This is the
complementary *change*-covariant axis: parametrize over what a fork *changed*
versus its parent, drawn from ``diff_forks``. An archetype test decorated with
``with_each_change(kind)`` is generated once per matching change across every
adjacent fork pair, so a new fork is covered automatically the moment it is
added — no per-fork test rewriting.

This lives in the pure-property layer (plain ``pytest.mark.parametrize`` over
fork pairs), which needs no fill machinery and has no "fork lacks this change
kind" edge case. Archetypes that require full block execution graduate to a
fill-side covariant marker; see the design doc for that path.
"""

from typing import Callable, List, Optional, Tuple

import pytest

from execution_testing.forks import Fork, get_forks

from .manifest import Change, ChangeKind, changes_of_kind

ForkPair = Tuple[Fork, Fork]


def adjacent_fork_pairs() -> List[ForkPair]:
    """
    All (parent, child) pairs of consecutive non-transition forks.

    Sourced from ``get_forks()`` so a newly added fork automatically joins
    the list — and thus every archetype that parametrizes over it.
    """
    forks = [f for f in get_forks() if not f.is_transition_fork]
    return list(zip(forks, forks[1:], strict=False))


def manifest_cases(
    kind: ChangeKind, fork_pairs: Optional[List[ForkPair]] = None
) -> List[Tuple[Fork, Fork, Change]]:
    """Every (parent, child, change) of ``kind`` across the fork pairs."""
    pairs = fork_pairs if fork_pairs is not None else adjacent_fork_pairs()
    cases: List[Tuple[Fork, Fork, Change]] = []
    for parent, child in pairs:
        for change in changes_of_kind(parent, child, kind):
            cases.append((parent, child, change))
    return cases


def with_each_change(
    kind: ChangeKind,
    *,
    fork_pairs: Optional[List[ForkPair]] = None,
) -> Callable:
    """
    Parametrize a test over every fork-to-fork change of ``kind``.

    The test signature receives ``(parent, child, change)``. Sourced from the
    fork diff, not hand-enumerated, so it covers every transition — present
    and future.
    """
    cases = manifest_cases(kind, fork_pairs)
    ids = [
        f"{parent.name()}->{child.name()}:{change.name}"
        for parent, child, change in cases
    ]
    return pytest.mark.parametrize("parent, child, change", cases, ids=ids)
