"""Tests for the EELS-vs-client differential comparison logic."""

from types import SimpleNamespace
from typing import Any, List

from ..fuzzer_bridge import differential
from ..fuzzer_bridge.differential import _compare, _evaluate


def _result(**overrides: Any) -> Any:
    """A stand-in transition Result with the fields _compare reads."""
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


def test_identical_results_agree() -> None:
    """Identical results produce no divergences."""
    assert _compare(_result(), _result()) == []


def test_state_root_divergence() -> None:
    """A differing state root is reported as one divergence."""
    divergences = _compare(_result(), _result(state_root="0xzzz"))
    assert len(divergences) == 1
    assert divergences[0].field == "state_root"
    assert divergences[0].eels == "0xaaa"
    assert divergences[0].client == "0xzzz"


def test_multiple_field_divergences() -> None:
    """Each differing field is reported."""
    divergences = _compare(
        _result(),
        _result(state_root="0xzzz", gas_used=42000),
    )
    fields = {d.field for d in divergences}
    assert fields == {"state_root", "gas_used"}


def test_none_fields_are_skipped() -> None:
    """A field that is None on either side is never a divergence."""
    # withdrawals_root is None on both by default; set only on one side.
    divergences = _compare(_result(), _result(withdrawals_root=None))
    assert divergences == []


def test_rejected_transaction_set_divergence() -> None:
    """Differing rejected-transaction sets are reported."""
    divergences = _compare(
        _result(rejected_transactions=_rejected(0)),
        _result(rejected_transactions=_rejected()),
    )
    assert len(divergences) == 1
    assert divergences[0].field == "rejected_transactions"


def test_evaluate_both_raise_is_agreement(monkeypatch: Any) -> None:
    """When both tools reject the input, that is agreement, not a finding."""

    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise ValueError("invalid input")

    monkeypatch.setattr(differential, "_transition", boom)
    dummy: Any = object()
    divergences, error = _evaluate(dummy, dummy, dummy, dummy)
    assert divergences == []
    assert error is None


def test_evaluate_asymmetric_failure_is_divergence(monkeypatch: Any) -> None:
    """One tool failing where the other succeeds is a divergence."""
    calls = {"n": 0}

    def sometimes(*_args: Any, **_kwargs: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 1:
            return _result()
        raise ValueError("client rejected")

    monkeypatch.setattr(differential, "_transition", sometimes)
    dummy: Any = object()
    divergences, error = _evaluate(dummy, dummy, dummy, dummy)
    assert error is not None
    assert "asymmetric failure" in error
