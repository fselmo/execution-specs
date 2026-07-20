"""
Archetype tests sourced from the fork change manifest.

These demonstrate the change-covariant mechanism: a single test body,
decorated with ``with_each_change(kind)``, is generated once per matching
change across every adjacent fork pair — sourced from ``diff_forks``, never
hand-enumerated per fork. Add a new fork and it is covered automatically.

The property here is deliberately *assumption-free* (no baked-in expected
value, so it cannot encode a wrong claim into a canonical fixture): every
formula an EIP mixin declares changed must be *observably* different from the
parent fork's implementation. A verbatim re-declaration is a no-op override —
dead code or a mistake — and this catches it, while confirming the manifest's
override-diff is not reporting phantom changes.

Richer, execution-level differential archetypes (behavior differs from the
parent fork only on the changed surface) need an oracle from outside the fork
surface and are a separate slice; this proves the covariant-source mechanism.
"""

import inspect
from typing import Optional

import pytest
from execution_testing.eip_properties import (
    Change,
    ChangeKind,
    with_each_change,
)
from execution_testing.forks import Fork


def _method_source(fork: Fork, name: str) -> Optional[str]:
    """Source of ``name`` as resolved on ``fork`` (None if not a method)."""
    attr = getattr(fork, name, None)
    func = getattr(attr, "__func__", None)
    if func is None:
        return None
    try:
        return inspect.getsource(func)
    except (OSError, TypeError):
        return None


@with_each_change(ChangeKind.FORMULA_CHANGED)
def test_declared_formula_change_is_observable(
    parent: Fork, child: Fork, change: Change
) -> None:
    """
    A formula an EIP declares changed must differ from the parent fork's.

    Sourced from the manifest across every fork pair, not hand-written per
    fork. A verbatim re-declaration (identical source) is a no-op override
    worth flagging.
    """
    child_source = _method_source(child, change.name)
    parent_source = _method_source(parent, change.name)
    if child_source is None or parent_source is None:
        pytest.skip(f"{change.name} does not resolve to a comparable method")
    assert child_source != parent_source, (
        f"{child.name()} declares {change.name} changed from "
        f"{parent.name()}, but the implementation is identical "
        "(no-op override)"
    )
