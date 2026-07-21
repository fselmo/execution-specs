"""
EIP property-testing support: derive what to test from what a fork changes.

See ``manifest.py`` for the change-detector that turns a fork-to-fork diff into
an EIP-attributed, archetype-mapped manifest.
"""

from .covariant import (
    adjacent_fork_pairs,
    manifest_cases,
    with_each_change,
)
from .manifest import (
    Change,
    ChangeKind,
    changes_of_kind,
    derived_checklist_sections,
    diff_forks,
)
from .structural import HEADER_FIELD_FEATURES, built_header_at_fork
from .targeting import (
    added_precompiles,
    fuzz_precompile_targets,
    parent_fork,
)

__all__ = [
    "HEADER_FIELD_FEATURES",
    "Change",
    "ChangeKind",
    "added_precompiles",
    "adjacent_fork_pairs",
    "built_header_at_fork",
    "changes_of_kind",
    "derived_checklist_sections",
    "diff_forks",
    "fuzz_precompile_targets",
    "manifest_cases",
    "parent_fork",
    "with_each_change",
]
