"""Tests for deriving a fork's change manifest from its typed surface."""

from execution_testing.forks import Amsterdam, Osaka, Prague

from ..manifest import (
    Change,
    ChangeKind,
    derived_checklist_sections,
    diff_forks,
    interaction_pairs,
)


def _find(changes: list[Change], name: str) -> Change:
    matches = [c for c in changes if c.name == name]
    assert len(matches) == 1, f"expected exactly one {name!r}, got {matches}"
    return matches[0]


def test_transaction_gas_limit_cap_attributed_to_eip7825() -> None:
    """A new per-tx bound is detected, classified, and attributed."""
    changes = diff_forks(Prague, Osaka)
    cap = _find(changes, "transaction_gas_limit_cap")
    assert cap.kind == ChangeKind.BOUND_ADDED
    assert cap.before is None and int(cap.after) == 16777216
    assert cap.eips == ["EIP7825"]
    assert "New Transaction-Validity Constraint" in cap.checklist_sections


def test_bal_header_field_attributed_to_eip7928() -> None:
    """A new header field flips a feature flag, attributed to its EIP."""
    changes = diff_forks(Osaka, Amsterdam)
    bal = _find(changes, "header_bal_hash_required")
    assert bal.kind == ChangeKind.FEATURE_ENABLED
    assert bal.eips == ["EIP7928"]
    assert bal.checklist_sections == ["New Block Header Field"]


def test_new_opcodes_detected() -> None:
    """Opcodes added to the valid set are surfaced as opcode_added."""
    changes = diff_forks(Osaka, Amsterdam)
    added = [c for c in changes if c.kind == ChangeKind.OPCODE_ADDED]
    assert added, "expected new opcodes Osaka -> Amsterdam"
    assert all(c.before is None for c in added)


def test_gas_constants_detected() -> None:
    """Individual GasCosts field changes are surfaced (not just the object)."""
    changes = diff_forks(Osaka, Amsterdam)
    gas = [c for c in changes if c.kind == ChangeKind.GAS_CONSTANT]
    assert len(gas) >= 10
    assert any(c.name == "gas_costs.TX_BASE" for c in gas)


def test_formula_change_via_override_diff() -> None:
    """A calculator a new EIP mixin overrides shows as formula_changed."""
    changes = diff_forks(Osaka, Amsterdam)
    formulas = [c for c in changes if c.kind == ChangeKind.FORMULA_CHANGED]
    assert any(
        c.name == "transaction_intrinsic_cost_calculator" for c in formulas
    )
    assert all(c.detector == "override" for c in formulas)


def test_derived_sections_are_real_checklist_sections() -> None:
    """Derived sections are a subset of the checklist's real section names."""
    real_sections = {
        "New Opcode",
        "New Precompile",
        "Removed Precompile",
        "New System Contract",
        "New Transaction Type",
        "New Block Header Field",
        "New Block Body Field",
        "Gas Cost Changes",
        "Gas Refunds Changes",
        "Blob Count Changes",
        "New Execution Layer Request",
        "New Transaction-Validity Constraint",
        "Modified Transaction-Validity Constraint",
        "Block-Level Validation Constraint",
    }
    derived = derived_checklist_sections(diff_forks(Osaka, Amsterdam))
    assert derived
    assert derived <= real_sections


def test_no_changes_for_same_fork() -> None:
    """A fork against itself yields no changes."""
    assert diff_forks(Amsterdam, Amsterdam) == []


def test_interaction_pairs_finds_co_owned_formulas() -> None:
    """EIPs co-overriding the same calculator form an interaction pair."""
    pairs = interaction_pairs(Osaka, Amsterdam)
    shared = pairs[("EIP2780", "EIP7981")]
    assert "transaction_intrinsic_cost_calculator" in shared


def test_interaction_pairs_exclude_value_noise() -> None:
    """Value-level co-attribution (gas constants) never forms a pair."""
    pairs = interaction_pairs(Osaka, Amsterdam)
    for methods in pairs.values():
        assert not any(m.startswith("gas_costs.") for m in methods)


def test_interaction_pairs_empty_for_same_fork() -> None:
    """A fork against itself has no interactions."""
    assert interaction_pairs(Amsterdam, Amsterdam) == {}


def test_changes_for_eip_finds_the_introducing_fork_and_changes() -> None:
    """EIP-1153 (transient storage) shipped in Cancun with TLOAD/TSTORE."""
    from execution_testing.forks import Cancun

    from ..manifest import changes_for_eip, fork_introducing_eip

    assert fork_introducing_eip(1153) == Cancun
    changes = changes_for_eip(1153)
    assert changes
    names = {c.name for c in changes}
    assert "gas_costs.OPCODE_TLOAD" in names
    assert "gas_costs.OPCODE_TSTORE" in names


def test_changes_for_eip_attribution_is_manifest_coarse() -> None:
    """
    Shared-method changes are attributed to every co-shipping EIP, so the
    result is a superset of what the EIP strictly owns -- a documented
    property of the override-diff, pinned here so it is not mistaken for a
    per-EIP-exact list.
    """
    from ..manifest import changes_for_eip

    # EIP-1153 and EIP-4844 both ship in Cancun and both override gas_costs,
    # so 4844's point-evaluation gas is attributed to 1153 as well.
    names = {c.name for c in changes_for_eip(1153)}
    assert "gas_costs.PRECOMPILE_POINT_EVALUATION" in names


def test_changes_for_unknown_eip_is_empty() -> None:
    """An EIP no fork introduces yields no changes and no fork."""
    from ..manifest import changes_for_eip, fork_introducing_eip

    assert changes_for_eip(999999) == []
    assert fork_introducing_eip(999999) is None
