"""
Measure execution-signature novelty on the current generator.

This is the baseline the future corpus-growth scheduler is judged against:
before a corpus lane exists, fill a seed range serially, fold each case's
signature into a running set-union, and report how many cases were novel. A
signal only earns its keep if novelty-guided growth later beats this
fresh-seed-only curve at equal budget.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from execution_testing.evm_tools.t8n.evm_trace.signature import Signature
    from execution_testing.forks import Fork


class NoveltyTracker:
    """
    Promote a case as novel when it extends L0 (frames) or L1 (events).

    L2 (bigrams) is folded in and reported but never drives promotion: the
    400-seed saturation curve showed raw bigrams are a long tail that keeps
    growing (~1.3 new pairs/seed at seed 400), so bigram-in-the-union
    promotes ~half of all fresh seeds indefinitely -- a tie-breaker signal,
    not a driver, exactly as the design classified it.
    """

    def __init__(self) -> None:
        self._frames: Set[Tuple[int, str, str]] = set()
        self._events: Set[str] = set()
        self._bigrams: Set[Tuple[str, str]] = set()

    def observe(self, signature: "Signature") -> bool:
        """Fold a signature in; return whether L0 or L1 grew (set-union)."""
        before = len(self._frames) + len(self._events)
        self._frames |= signature.frames
        self._events |= signature.events
        self._bigrams |= signature.bigrams
        after = len(self._frames) + len(self._events)
        return after > before

    def counts(self) -> Tuple[int, int, int]:
        """Return the distinct (frames, events, bigrams) totals seen."""
        return len(self._frames), len(self._events), len(self._bigrams)

    def unreached_events(self) -> List[str]:
        """L1 events the run never fired -- the generator's target list."""
        from execution_testing.evm_tools.t8n.evm_trace.signature import (
            KNOWN_EVENTS,
        )

        return sorted(KNOWN_EVENTS - self._events)

    def unreached_frames(self) -> List[Tuple[int, str, str]]:
        """Enumerated L0 cells the run never reached (the reach map)."""
        from execution_testing.evm_tools.t8n.evm_trace.signature import (
            CALL_OPS,
            DEPTH_BUCKETS,
            KNOWN_HALT_KINDS,
        )

        cells = [
            (bucket, "call", op)
            for bucket in DEPTH_BUCKETS
            for op in sorted(CALL_OPS)
        ] + [
            (bucket, "halt", halt)
            for bucket in DEPTH_BUCKETS
            for halt in sorted(KNOWN_HALT_KINDS)
        ]
        return [cell for cell in cells if cell not in self._frames]


def render_unreached(tracker: NoveltyTracker) -> str:
    """Render the never-fired events and never-reached frame cells."""
    events = tracker.unreached_events()
    frames = tracker.unreached_frames()
    lines = [f"unreached events ({len(events)}): " + ", ".join(events)]
    lines.append(f"unreached frame cells ({len(frames)}):")
    for bucket, kind, name in frames:
        lines.append(
            f"  depth>={bucket} {kind} {name}"
            if bucket == 3
            else f"  depth {bucket}  {kind} {name}"
        )
    return "\n".join(lines)


@dataclass
class BaselineReport:
    """Novelty statistics for a seed range on the current generator."""

    seeds: int
    novel: int
    frames: int
    events: int
    bigrams: int
    max_depth: int

    def summary(self) -> str:
        """Render the report as one line."""
        return (
            f"novel {self.novel}/{self.seeds}; "
            f"distinct frames={self.frames} events={self.events} "
            f"bigrams={self.bigrams}; max depth {self.max_depth}"
        )


@dataclass
class CurveRow:
    """Cumulative novelty at one checkpoint of the saturation curve."""

    seeds: int
    novel: int
    frames: int
    events: int
    bigrams: int
    unfillable: int


def novelty_curve(
    fork: "Fork",
    seeds: range,
    *,
    checkpoint: int = 50,
    tracker: "Optional[NoveltyTracker]" = None,
) -> "List[CurveRow]":
    """
    Fill seeds serially, recording per-layer novelty at checkpoints.

    The curve's shape -- which layers saturate and how fast -- sets the
    promotion rate a corpus scheduler should expect, and is the input to
    freezing the gate's minimum effect. The unfillable rate rides along so
    a later generator change that shifts fillability shows up in the same
    table.
    """
    from execution_testing.cli.fuzzer_bridge.campaign import fill_case
    from execution_testing.cli.fuzzer_bridge.generator import (
        generate_fuzzer_output,
    )
    from execution_testing.client_clis.clis.execution_specs import (
        ExecutionSpecsTransitionTool,
    )

    eels = ExecutionSpecsTransitionTool()
    eels.compute_signature = True
    tracker = tracker if tracker is not None else NoveltyTracker()
    rows: List[CurveRow] = []
    novel = unfillable = done = 0
    for seed in seeds:
        eels.last_signature = None
        try:
            fill_case(generate_fuzzer_output(fork, seed), fork, eels)
        except Exception:  # noqa: BLE001 - unfillable is data
            unfillable += 1
        else:
            signature = eels.last_signature
            if signature is not None and tracker.observe(signature):
                novel += 1
        done += 1
        if done % checkpoint == 0 or done == len(seeds):
            frames, events, bigrams = tracker.counts()
            rows.append(
                CurveRow(done, novel, frames, events, bigrams, unfillable)
            )
    return rows


def render_curve(rows: "List[CurveRow]") -> str:
    """Render the curve as a compact table."""
    lines = ["seeds  novel  frames  events  bigrams  unfillable"]
    for row in rows:
        lines.append(
            f"{row.seeds:5d}  {row.novel:5d}  {row.frames:6d}  "
            f"{row.events:6d}  {row.bigrams:7d}  {row.unfillable:10d}"
        )
    return "\n".join(lines)


def signature_baseline(fork: "Fork", seeds: range) -> BaselineReport:
    """Fill each seed serially and measure signature novelty (set-union)."""
    from execution_testing.cli.fuzzer_bridge.campaign import fill_case
    from execution_testing.cli.fuzzer_bridge.generator import (
        generate_fuzzer_output,
    )
    from execution_testing.client_clis.clis.execution_specs import (
        ExecutionSpecsTransitionTool,
    )

    eels = ExecutionSpecsTransitionTool()
    eels.compute_signature = True
    tracker = NoveltyTracker()
    novel = 0
    max_depth = 0
    for seed in seeds:
        eels.last_signature = None
        fill_case(generate_fuzzer_output(fork, seed), fork, eels)
        signature = eels.last_signature
        if signature is not None:
            max_depth = max(max_depth, signature.max_depth)
            if tracker.observe(signature):
                novel += 1
    frames, events, bigrams = tracker.counts()
    return BaselineReport(
        len(seeds), novel, frames, events, bigrams, max_depth
    )
