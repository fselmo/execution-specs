"""Tests for the reach gate: landed capabilities must keep firing."""

import pytest

from execution_testing.cli.fuzzer_bridge import reach_gate
from execution_testing.cli.fuzzer_bridge.generator import GENERATOR_VERSION
from execution_testing.cli.fuzzer_bridge.reach_gate import (
    BASELINE_GENERATOR_VERSION,
    GATE_EVENTS,
    GATE_FRAMES,
    StaleGateBaselineError,
    check_reach_gate,
    compute_gate_baseline,
)
from execution_testing.forks import Amsterdam


def test_gate_baseline_matches_the_generator_version() -> None:
    """A generator bump must re-baseline the gate, never skip it."""
    assert GENERATOR_VERSION == BASELINE_GENERATOR_VERSION, (
        "GENERATOR_VERSION bumped: re-baseline the reach gate with "
        "compute_gate_baseline(fork, range(400)) and update reach_gate.py"
    )


def test_landed_capabilities_still_fire() -> None:
    """The gate seeds fire every declared event and frame cell."""
    assert check_reach_gate(Amsterdam) == []


def test_gate_detects_a_dark_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A declared target the seeds cannot fire is reported missing."""
    monkeypatch.setattr(
        reach_gate, "GATE_EVENTS", GATE_EVENTS | {"never-happens"}
    )
    monkeypatch.setattr(
        reach_gate,
        "GATE_FRAMES",
        GATE_FRAMES | {(0, "halt", "NeverRaisedError")},
    )
    missing = check_reach_gate(Amsterdam)
    assert "event never-happens" in missing
    assert "depth 0 halt NeverRaisedError" in missing


def test_stale_baseline_fails_loudly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A version mismatch refuses to run and says how to re-baseline."""
    monkeypatch.setattr(reach_gate, "BASELINE_GENERATOR_VERSION", -1)
    with pytest.raises(StaleGateBaselineError, match="Re-baseline"):
        check_reach_gate(Amsterdam)


def test_compute_gate_baseline_yields_a_cover() -> None:
    """
    The re-baseline helper picks seeds from the range that cover
    everything it measured.
    """
    baseline = compute_gate_baseline(Amsterdam, range(3))
    assert baseline["generator_version"] == GENERATOR_VERSION
    assert set(baseline["seeds"]) <= set(range(3))
    assert baseline["events"] and baseline["frames"]
