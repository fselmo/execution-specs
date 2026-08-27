"""Tests for the multi-client differential comparison logic."""

from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from execution_testing.forks import Osaka

from ..fuzzer_bridge import differential
from ..fuzzer_bridge.differential import (
    _fork_by_name,
    compare_results,
    evaluate_case,
)

NO_CASE: Any = None
NO_FORK: Any = None


def _result(**overrides: Any) -> Any:
    """A stand-in transition Result with the fields compare_results reads."""
    base = dict(
        state_root="0xaaa",
        receipts_root="0xbbb",
        logs_hash="0xccc",
        gas_used=21000,
        withdrawals_root=None,
        blob_gas_used=None,
        requests_hash=None,
        block_access_list_hash=None,
        rejected_transactions=[],
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _rejected(*indices: int) -> List[Any]:
    return [SimpleNamespace(index=i) for i in indices]


def _fake_transition(behaviour: Dict[str, Any]) -> Any:
    """
    Stand-in for `_transition` keyed by tool: tools are plain strings and
    map either to a result or to an exception to raise.
    """

    def transition(tool: Any, *_args: Any, **_kwargs: Any) -> Any:
        outcome = behaviour[tool]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    return transition


def test_fork_by_name_roundtrips() -> None:
    """A fork name resolves back to the fork (for worker reconstruction)."""
    assert _fork_by_name("Osaka") is Osaka


def test_fork_by_name_rejects_unknown() -> None:
    """An unknown fork name raises rather than silently mis-resolving."""
    with pytest.raises(ValueError):
        _fork_by_name("NotAFork")


def test_identical_results_agree() -> None:
    """Identical results produce no divergences."""
    assert compare_results({"eels": _result(), "geth": _result()}) == []


def test_single_client_divergence_names_the_client() -> None:
    """With one client, a differing field singles that client out."""
    divergences = compare_results(
        {"eels": _result(), "geth": _result(state_root="0xzzz")}
    )
    assert len(divergences) == 1
    d = divergences[0]
    assert d.field == "state_root"
    assert d.values == {"eels": "0xaaa", "geth": "0xzzz"}
    assert d.minority == ["geth"]


def test_majority_isolates_the_odd_client_out() -> None:
    """Across several tools, the minority is whoever disagrees with most."""
    divergences = compare_results(
        {
            "eels": _result(),
            "geth": _result(),
            "nethermind": _result(gas_used=42000),
        }
    )
    assert len(divergences) == 1
    assert divergences[0].field == "gas_used"
    assert divergences[0].minority == ["nethermind"]


def test_tie_sides_with_eels() -> None:
    """A tie is broken in favour of the reference implementation."""
    divergences = compare_results(
        {
            "eels": _result(),
            "geth": _result(state_root="0xzzz"),
            "besu": _result(state_root="0xzzz"),
            "reth": _result(),
        }
    )
    assert sorted(divergences[0].minority) == ["besu", "geth"]


def test_tie_without_eels_lists_every_side() -> None:
    """Without EELS to break a tie, every tool is reported."""
    divergences = compare_results(
        {"geth": _result(), "besu": _result(state_root="0xzzz")}
    )
    assert sorted(divergences[0].minority) == ["besu", "geth"]


def test_none_fields_are_skipped() -> None:
    """A field missing on any tool is never a divergence."""
    divergences = compare_results(
        {"eels": _result(), "geth": _result(withdrawals_root="0x1")}
    )
    assert divergences == []


def test_multiple_field_divergences() -> None:
    """Each differing field is reported."""
    divergences = compare_results(
        {"eels": _result(), "geth": _result(state_root="0xzzz", gas_used=1)}
    )
    assert {d.field for d in divergences} == {"state_root", "gas_used"}


def test_rejected_transaction_set_divergence() -> None:
    """Differing rejected-transaction sets are reported."""
    divergences = compare_results(
        {
            "eels": _result(rejected_transactions=_rejected(0)),
            "geth": _result(rejected_transactions=_rejected()),
        }
    )
    assert len(divergences) == 1
    assert divergences[0].field == "rejected_transactions"
    assert divergences[0].minority == ["geth"]


def test_evaluate_all_raise_is_agreement(monkeypatch: Any) -> None:
    """Every tool rejecting the input is agreement, not a finding."""
    monkeypatch.setattr(
        differential,
        "_transition",
        _fake_transition({"eels": ValueError("x"), "geth": ValueError("y")}),
    )
    outcome = evaluate_case({"eels": "eels", "geth": "geth"}, NO_CASE, NO_FORK)
    assert not outcome.diverged
    assert outcome.errors == {"eels": "ValueError: x", "geth": "ValueError: y"}


def test_evaluate_asymmetric_failure_is_divergence(monkeypatch: Any) -> None:
    """One tool failing where another succeeds is a divergence."""
    monkeypatch.setattr(
        differential,
        "_transition",
        _fake_transition({"eels": _result(), "geth": ValueError("rejected")}),
    )
    outcome = evaluate_case({"eels": "eels", "geth": "geth"}, NO_CASE, NO_FORK)
    assert outcome.diverged
    assert outcome.errors == {"geth": "ValueError: rejected"}
    assert outcome.divergences == []


def test_evaluate_reports_the_minority(monkeypatch: Any) -> None:
    """A full evaluation carries the majority view through."""
    monkeypatch.setattr(
        differential,
        "_transition",
        _fake_transition(
            {
                "eels": _result(),
                "geth": _result(),
                "besu": _result(gas_used=1),
            }
        ),
    )
    outcome = evaluate_case(
        {"eels": "eels", "geth": "geth", "besu": "besu"}, NO_CASE, NO_FORK
    )
    assert outcome.diverged
    assert outcome.divergences[0].minority == ["besu"]


def test_tiered_skips_eels_when_clients_agree(monkeypatch: Any) -> None:
    """With agreeing clients, the reference is never consulted."""
    calls: List[str] = []

    def transition(tool: Any, *_args: Any, **_kwargs: Any) -> Any:
        calls.append(tool)
        return _result()

    monkeypatch.setattr(differential, "_transition", transition)
    outcome = evaluate_case(
        {"eels": "eels", "geth": "geth", "besu": "besu"},
        NO_CASE,
        NO_FORK,
        tiered=True,
    )
    assert not outcome.diverged
    assert not outcome.eels_ran
    assert "eels" not in calls


def test_tiered_runs_eels_to_adjudicate(monkeypatch: Any) -> None:
    """Disagreeing clients bring EELS in, and it settles the minority."""
    monkeypatch.setattr(
        differential,
        "_transition",
        _fake_transition(
            {
                "eels": _result(),
                "geth": _result(),
                "besu": _result(gas_used=1),
            }
        ),
    )
    outcome = evaluate_case(
        {"eels": "eels", "geth": "geth", "besu": "besu"},
        NO_CASE,
        NO_FORK,
        tiered=True,
    )
    assert outcome.eels_ran
    assert outcome.divergences[0].minority == ["besu"]
    assert set(outcome.divergences[0].values) == {"eels", "geth", "besu"}


def test_tiered_client_failure_brings_eels_in(monkeypatch: Any) -> None:
    """A client rejecting what another accepts is adjudicated, not skipped."""
    monkeypatch.setattr(
        differential,
        "_transition",
        _fake_transition(
            {
                "eels": _result(),
                "geth": _result(),
                "besu": ValueError("rejected"),
            }
        ),
    )
    outcome = evaluate_case(
        {"eels": "eels", "geth": "geth", "besu": "besu"},
        NO_CASE,
        NO_FORK,
        tiered=True,
    )
    assert outcome.eels_ran
    assert outcome.diverged
    assert outcome.errors == {"besu": "ValueError: rejected"}


def test_tiered_with_one_client_always_runs_eels(monkeypatch: Any) -> None:
    """One client cannot adjudicate itself; EELS always runs."""
    monkeypatch.setattr(
        differential,
        "_transition",
        _fake_transition({"eels": _result(), "geth": _result()}),
    )
    outcome = evaluate_case(
        {"eels": "eels", "geth": "geth"}, NO_CASE, NO_FORK, tiered=True
    )
    assert outcome.eels_ran
