"""
EIP property-testing support: derive what to test from what a fork changes.

See ``manifest.py`` for the change-detector that turns a fork-to-fork diff into
an EIP-attributed, archetype-mapped manifest.
"""

from .manifest import (
    Change,
    ChangeKind,
    changes_of_kind,
    derived_checklist_sections,
    diff_forks,
)

__all__ = [
    "Change",
    "ChangeKind",
    "changes_of_kind",
    "derived_checklist_sections",
    "diff_forks",
]
