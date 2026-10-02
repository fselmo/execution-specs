"""
The precompiles a fork introduced relative to its parent.

``diff_forks`` says *what* a fork changed; this maps the manifest's
``PRECOMPILE_ADDED`` changes back to concrete addresses, so the manifest
stays the single authority on what changed.
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
