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
from typing import TYPE_CHECKING, FrozenSet, List, Optional, Set, Tuple

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

    def unreached_frames(
        self, fork: "Optional[Fork]" = None
    ) -> List[Tuple[int, str, str]]:
        """
        Enumerated L0 cells the run never reached (the reach map).

        With a fork, the product space is derived from the fork's own
        surface, so a new fork's new exception shows up as an unreached
        cell instead of being silently absent.
        """
        from execution_testing.evm_tools.t8n.evm_trace.signature import (
            CALL_OPS,
            DEPTH_BUCKETS,
            KNOWN_HALT_KINDS,
        )

        if fork is not None:
            call_ops, halt_kinds = fork_reach_space(fork)
        else:
            call_ops, halt_kinds = CALL_OPS, KNOWN_HALT_KINDS
        cells = [
            (bucket, "call", op)
            for bucket in DEPTH_BUCKETS
            for op in sorted(call_ops)
        ] + [
            (bucket, "halt", halt)
            for bucket in DEPTH_BUCKETS
            for halt in sorted(halt_kinds)
        ]
        return [cell for cell in cells if cell not in self._frames]


def fork_reach_space(
    fork: "Fork",
) -> Tuple[FrozenSet[str], FrozenSet[str]]:
    """
    Derive the L0 product space from the fork's own surface.

    Call kinds come from the fork's opcode set and halt kinds from its
    exception classes -- the KNOWN_EVENTS canonical-registry principle,
    one level up.
    """
    import importlib
    import inspect

    from execution_testing.evm_tools.t8n.evm_trace.signature import (
        CALL_OPS,
    )

    package = f"ethereum.forks.{fork.name().lower()}.vm"
    ops = importlib.import_module(f"{package}.instructions").Ops
    exceptions = importlib.import_module(f"{package}.exceptions")
    halt_kinds = {"STOP"} | {
        name
        for name, cls in inspect.getmembers(exceptions, inspect.isclass)
        if cls.__module__ == exceptions.__name__ and name != "ExceptionalHalt"
    }
    return (
        frozenset(op.name for op in ops) & CALL_OPS,
        frozenset(halt_kinds),
    )


_GAS_TO_REACH_DEPTH_LIMIT = 30_000_000_000
"""Roughly 2600 * (64/63)**1024: the transaction gas the 63/64 rule needs
to still leave a workable remainder at depth 1024. A fork whose tx-gas cap
sits below this cannot reach the call-depth limit."""


def unreachable_on_fork(
    fork: "Fork",
) -> Tuple[FrozenSet[str], FrozenSet[Tuple[int, str, str]]]:
    """Events and frame cells that cannot occur on this fork."""
    from execution_testing.evm_tools.t8n.evm_trace.signature import (
        DEPTH_BUCKETS,
    )

    events: Set[str] = set()
    # AddressCollision raises only on the transaction-level create path,
    # before any frame exists; the in-EVM CREATE* collision consumes the
    # child grant and pushes 0 without raising (`generic_create`), so it
    # is never a frame halt kind.
    cells = {(0, "halt", "WriteInStaticContext")} | {
        (bucket, "halt", "AddressCollision") for bucket in DEPTH_BUCKETS
    }
    cap = fork.transaction_gas_limit_cap()
    if cap is not None and cap < _GAS_TO_REACH_DEPTH_LIMIT:
        events.add("call-depth-limit")
        cells |= {
            (bucket, "halt", "StackDepthLimitError")
            for bucket in DEPTH_BUCKETS
        }
    return frozenset(events), frozenset(cells)


def render_unreached(
    tracker: NoveltyTracker, fork: "Optional[Fork]" = None
) -> str:
    """Render never-fired events and never-reached cells, fork-aware."""
    dead_events: FrozenSet[str] = frozenset()
    dead_cells: FrozenSet[Tuple[int, str, str]] = frozenset()
    if fork is not None:
        dead_events, dead_cells = unreachable_on_fork(fork)
    events = [
        event
        for event in tracker.unreached_events()
        if event not in dead_events
    ]
    frames = [
        cell
        for cell in tracker.unreached_frames(fork)
        if cell not in dead_cells
    ]
    lines = [f"unreached events ({len(events)}): " + ", ".join(events)]
    lines.append(f"unreached frame cells ({len(frames)}):")
    for bucket, kind, name in frames:
        lines.append(
            f"  depth>={bucket} {kind} {name}"
            if bucket == 3
            else f"  depth {bucket}  {kind} {name}"
        )
    if dead_events or dead_cells:
        dead = sorted(dead_events) + [
            f"depth{'>=' if bucket == 3 else ' '}{bucket} {kind} {name}"
            for bucket, kind, name in sorted(dead_cells)
        ]
        lines.append(
            f"unreachable on this fork ({len(dead)}): " + "; ".join(dead)
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
