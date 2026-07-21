"""
Point the differential fuzzer at the surface a fork changed.

``diff_forks`` says *what* a fork changed; this turns that into *where the
fuzzer aims*. A fork's newly-added precompiles are the densest divergence
risk -- decade-old ecrecover is not where a new consensus bug hides, a
freshly-added curve operation is -- so the generator up-weights the
precompiles a fork introduced relative to its parent. Which precompiles are
"new" is read from the manifest's ``PRECOMPILE_ADDED`` changes, then mapped
back to concrete addresses; the manifest stays the single authority on what
changed, and the fuzzer is its consumer.
"""

from typing import List, Optional

from execution_testing.forks import Fork, get_forks

from .manifest import ChangeKind, changes_of_kind


def parent_fork(fork: Fork) -> Optional[Fork]:
    """The preceding non-transition fork, or ``None`` for the first."""
    forks = [f for f in get_forks() if not f.is_transition_fork]
    names = [f.name() for f in forks]
    try:
        index = names.index(fork.name())
    except ValueError:
        return None
    return forks[index - 1] if index > 0 else None


def added_precompiles(fork: Fork) -> List[int]:
    """Precompile addresses ``fork`` introduced relative to its parent."""
    parent = parent_fork(fork)
    if parent is None:
        return []
    added = {
        change.after
        for change in changes_of_kind(
            parent, fork, ChangeKind.PRECOMPILE_ADDED
        )
    }
    return [
        int.from_bytes(bytes(a), "big")
        for a in fork.precompiles()
        if str(a) in added
    ]


def fuzz_precompile_targets(fork: Fork, *, new_weight: int = 5) -> List[int]:
    """
    All of ``fork``'s precompiles, with the ones it introduced repeated
    ``new_weight`` times so a seeded ``rng.choice`` biases toward the changed
    surface while still covering the battle-tested rest.
    """
    all_addresses = [
        int.from_bytes(bytes(a), "big") for a in fork.precompiles()
    ]
    new = set(added_precompiles(fork))
    weighted: List[int] = []
    for address in all_addresses:
        weighted.extend([address] * (new_weight if address in new else 1))
    return weighted
