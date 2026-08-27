"""Tests for the baseline gate that keeps stale clients out of a run."""

from typing import Any

import pytest

from ..fuzzer_bridge import baseline as baseline_module
from ..fuzzer_bridge import differential
from ..fuzzer_bridge.baseline import StaleClientError, check_baseline
from .test_differential import NO_FORK, _fake_transition, _result


def test_clean_baseline_returns_zero_counts(monkeypatch: Any) -> None:
    """Agreeing clients pass with a zero divergence count each."""
    monkeypatch.setattr(
        differential,
        "_transition",
        _fake_transition({"eels": _result(), "geth": _result()}),
    )
    monkeypatch.setattr(
        baseline_module, "generate_fuzzer_output", lambda *_: None
    )
    monkeypatch.setattr(differential, "_prepare", lambda case, _fork: case)
    counts = check_baseline(
        NO_FORK, {"eels": "eels", "geth": "geth"}, range(3)
    )
    assert counts == {"geth": 0}


def test_stale_client_is_named_with_its_count(monkeypatch: Any) -> None:
    """A client disagreeing with EELS stops the run and is named."""
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
    monkeypatch.setattr(
        baseline_module, "generate_fuzzer_output", lambda *_: None
    )
    monkeypatch.setattr(differential, "_prepare", lambda case, _fork: case)
    tools = {"eels": "eels", "geth": "geth", "besu": "besu"}
    with pytest.raises(StaleClientError, match="besu: 3/3") as info:
        check_baseline(NO_FORK, tools, range(3))
    assert info.value.stale == {"besu": 3}
    assert "geth" not in str(info.value)


def test_failing_client_counts_as_stale(monkeypatch: Any) -> None:
    """A client that rejects what EELS accepts is stale too."""
    monkeypatch.setattr(
        differential,
        "_transition",
        _fake_transition({"eels": _result(), "geth": ValueError("no")}),
    )
    monkeypatch.setattr(
        baseline_module, "generate_fuzzer_output", lambda *_: None
    )
    monkeypatch.setattr(differential, "_prepare", lambda case, _fork: case)
    with pytest.raises(StaleClientError, match="geth: 2/2"):
        check_baseline(NO_FORK, {"eels": "eels", "geth": "geth"}, range(2))
