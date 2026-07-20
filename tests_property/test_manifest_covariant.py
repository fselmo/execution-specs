"""
Prototype: a property test sourced entirely from the fork change manifest.

This demonstrates the mechanism the archetype layer will use — a single test
body parametrized by ``diff_forks`` rather than by hand-enumerated, per-fork
data. The framework supplies the cases from the fork diff; the test never
mentions a specific fork or change.

The property here is deliberately *assumption-free* (no baked-in expected
value, so it cannot encode a wrong claim into a canonical fixture): every
formula an EIP mixin declares changed must be *observably* different from the
parent fork's implementation. A verbatim re-declaration is a no-op override —
dead code or a mistake — and this catches it. It also confirms the manifest's
override-diff is not reporting phantom changes.

Richer, execution-level differential archetypes (behavior differs from the
parent fork only on the changed surface) ride on the cross-fork differential
oracle and are a separate slice; this proves the covariant-source mechanism.
"""

import inspect
from typing import List, Tuple

import pytest
from execution_testing.eip_properties import ChangeKind, changes_of_kind
from execution_testing.forks import Amsterdam, Fork, Osaka, Prague

# Adjacent fork pairs to source changes from. One test body, many forks.
FORK_PAIRS: List[Tuple[Fork, Fork]] = [
    (Prague, Osaka),
    (Osaka, Amsterdam),
]


def _formula_changes() -> List[Tuple[Fork, Fork, str]]:
    cases: List[Tuple[Fork, Fork, str]] = []
    for parent, child in FORK_PAIRS:
        for change in changes_of_kind(
            parent, child, ChangeKind.FORMULA_CHANGED
        ):
            cases.append((parent, child, change.name))
    return cases


def _method_source(fork: Fork, name: str) -> str | None:
    """Source of ``name`` as resolved on ``fork`` (None if not a method)."""
    attr = getattr(fork, name, None)
    func = getattr(attr, "__func__", None)
    if func is None:
        return None
    try:
        return inspect.getsource(func)
    except (OSError, TypeError):
        return None


FORMULA_CHANGES = _formula_changes()


def test_manifest_has_formula_changes() -> None:
    """The fork diff yields formula changes to parametrize over."""
    assert FORMULA_CHANGES, "expected formula changes across the fork pairs"


@pytest.mark.parametrize(
    "parent, child, name",
    FORMULA_CHANGES,
    ids=[f"{p.name()}->{c.name()}:{n}" for p, c, n in FORMULA_CHANGES],
)
def test_declared_formula_change_is_observable(
    parent: Fork, child: Fork, name: str
) -> None:
    """
    A formula an EIP declares changed must differ from the parent fork's.

    Sourced from the manifest, not hand-written per fork. A verbatim
    re-declaration (identical source) is a no-op override worth flagging.
    """
    child_source = _method_source(child, name)
    parent_source = _method_source(parent, name)
    if child_source is None or parent_source is None:
        pytest.skip(f"{name} does not resolve to a comparable method")
    assert child_source != parent_source, (
        f"{child.name()} declares {name} changed from {parent.name()}, "
        f"but the implementation is identical (no-op override)"
    )
