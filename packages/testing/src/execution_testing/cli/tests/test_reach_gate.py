"""Tests for the reach gate: landed capabilities must keep firing."""

import math
from pathlib import Path
from typing import Any

import pytest

from execution_testing.cli.fuzzer_bridge import reach_gate
from execution_testing.cli.fuzzer_bridge.generator import GENERATOR_VERSION
from execution_testing.cli.fuzzer_bridge.reach_gate import (
    BASELINE_GENERATOR_VERSION,
    GATE_BAL_CELLS,
    GATE_EVENTS,
    GATE_FRAMES,
    StaleGateBaselineError,
    bal_gate_floor,
    check_reach_gate,
    compute_gate_baseline,
    required_gate_seeds,
)
from execution_testing.forks import Amsterdam


def test_gate_baseline_matches_the_generator_version() -> None:
    """A generator bump must re-baseline the gate, never skip it."""
    assert GENERATOR_VERSION == BASELINE_GENERATOR_VERSION, (
        "GENERATOR_VERSION bumped: re-baseline the reach gate with "
        "compute_gate_baseline(fork, range(400)) and update reach_gate.py"
    )


def _reach_log() -> Path:
    """The tracked reach log at the repository root."""
    for directory in Path(__file__).resolve().parents:
        candidate = directory / "reach_log.jsonl"
        if candidate.exists():
            return candidate
    raise FileNotFoundError("reach_log.jsonl not found above the tests")


def test_a_generator_version_ships_with_its_rate_records() -> None:
    """
    A version bump re-draws every case, and the reach gate only sees a
    capability go dark, not go rare. So each bump appends an event-rate and
    a composition-density record, and its event counts show no drop against
    the previous version's beyond what sampling explains. Versions 12 to 15
    were bumped without either record, and nothing noticed.
    """
    import json

    from execution_testing.cli.fuzzer_bridge.density import (
        block_step_drops,
        significant_drops,
    )

    records = [
        json.loads(line) for line in _reach_log().read_text().splitlines()
    ]

    def latest(kind: str, version: int) -> Any:
        found = [
            r
            for r in records
            if r.get("kind") == kind and r.get("generator_version") == version
        ]
        return found[-1] if found else None

    how = (
        "append `signature_baseline.event_rate_record(fork, range(400))` "
        "and `density.density_record(fork, range(400))` to reach_log.jsonl"
    )
    current = latest("event-rates", GENERATOR_VERSION)
    assert current is not None, f"no v{GENERATOR_VERSION} event-rates: {how}"
    assert latest("composition-density", GENERATOR_VERSION) is not None, (
        f"no v{GENERATOR_VERSION} composition-density record: {how}"
    )
    previous = latest("event-rates", GENERATOR_VERSION - 1)
    assert previous is not None, (
        f"no v{GENERATOR_VERSION - 1} event-rates record to compare against"
    )

    def counts(record: Any) -> Any:
        return {name: e["count"] for name, e in record["rates"].items()}

    assert (
        significant_drops(
            counts(previous),
            counts(current),
            previous["seeds"],
            current["seeds"],
        )
        == []
    )

    # Per-block execution: every block the generator draws must run user
    # code, and a later block's opcodes per case must not drop. One gas
    # budget spent in draw order once left later blocks starved, and a
    # growing block count would do it again.
    blocks = current.get("block_code")
    assert blocks, f"v{GENERATOR_VERSION} event-rates lacks block_code"
    dark = [n for n, b in blocks.items() if b["cases"] and not b["code"]]
    assert dark == [], f"blocks drawn but never running code: {dark}"
    assert block_step_drops(previous.get("block_code", {}), blocks) == []


def test_a_starved_later_block_is_a_regression() -> None:
    """
    The slice-2 starvation in miniature: block 2 still runs code in most
    cases, so a presence count barely moves, but it runs far fewer opcodes
    per case. The same numbers read the other way, or a block that only
    changed how often it is drawn, are not drops.
    """
    from execution_testing.cli.fuzzer_bridge.density import block_step_drops

    fair = {"2": {"steps": [3000, 800, 0, 1500, 2200] * 40}}
    starved = {"2": {"steps": [700, 200, 0, 300, 500] * 40}}
    fewer_draws = {"2": {"steps": [3000, 800, 0, 1500, 2200] * 8}}
    assert block_step_drops(fair, starved)
    assert block_step_drops(starved, fair) == []
    assert block_step_drops(fair, fewer_draws) == []


def test_a_rare_event_s_noise_is_not_a_regression() -> None:
    """
    The false alarm that shaped the check: `child-revert` fell 6 to 2 in
    400 seeds between v15 and v16 and rose 11 to 25 on the next 2000. A
    drop as large as the v6-to-v9 collapse still has to be caught.
    """
    from execution_testing.cli.fuzzer_bridge.density import significant_drops

    assert (
        significant_drops({"child-revert": 6}, {"child-revert": 2}, 400, 400)
        == []
    )
    assert significant_drops({"x": 297}, {"x": 133}, 400, 400)


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


def test_gate_detects_a_dark_bal_cell(monkeypatch: pytest.MonkeyPatch) -> None:
    """A gated BAL cell that stops being reached fails like any target."""
    dark = ("vm.instructions.storage.sload", "storage_read", "never")
    monkeypatch.setattr(reach_gate, "GATE_BAL_CELLS", GATE_BAL_CELLS | {dark})
    missing = check_reach_gate(Amsterdam)
    assert missing == ["bal vm.instructions.storage.sload storage_read never"]


def test_the_bal_floor_is_the_window_turned_around() -> None:
    """
    A cell gated at the floor is one the window samples within the miss
    bound, and one below it is not -- so gating never widens the window.
    """
    window, sample = 2094, 5000
    floor = bal_gate_floor(window, sample)
    assert required_gate_seeds({"cell": floor}, sample) <= window
    assert required_gate_seeds({"cell": floor - 1}, sample) > window
