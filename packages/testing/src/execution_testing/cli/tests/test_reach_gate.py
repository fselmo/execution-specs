"""Tests for the reach gate: landed capabilities must keep firing."""

import math

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


def test_the_baseline_window_is_derived_from_the_rarest_target() -> None:
    """
    A fixed window is a constant a rarer motif silently invalidates.

    Occurrences are Poisson, so a window of n misses a target of rate p
    with probability exp(-n * p); the width is solved from the stated
    miss bound and the rarest observed rate. A motif drawn at 0.005 is
    covered by 1200 seeds, one at 0.002 is not, and the window has to
    widen by itself rather than by someone noticing.
    """
    from execution_testing.cli.fuzzer_bridge.reach_gate import (
        GATE_MISS_PROBABILITY,
        required_gate_seeds,
    )

    common = required_gate_seeds({("frame", "x"): 6}, 1200)
    rare = required_gate_seeds({("frame", "x"): 2}, 1200)
    assert rare > common, "a rarer target must widen the window"

    # The bound holds at the returned width.
    for count, sample in ((6, 1200), (2, 1200), (1, 400)):
        window = required_gate_seeds({("frame", "x"): count}, sample)
        rate = count / sample
        assert math.exp(-window * rate) <= GATE_MISS_PROBABILITY + 1e-9


def test_a_target_never_seen_does_not_set_the_window() -> None:
    """
    Zero occurrences give no rate. Such a target is either genuinely
    dark, which the gate reports, or rarer than the probe measures,
    which a wider probe answers -- neither is an infinite window.
    """
    from execution_testing.cli.fuzzer_bridge.reach_gate import (
        required_gate_seeds,
    )

    assert required_gate_seeds({("frame", "x"): 0}, 400) == 400
    mixed = required_gate_seeds({("frame", "x"): 0, ("frame", "y"): 4}, 400)
    assert mixed == required_gate_seeds({("frame", "y"): 4}, 400)
