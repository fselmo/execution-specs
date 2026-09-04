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
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    FrozenSet,
    List,
    Optional,
    Set,
    Tuple,
)

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
        self._tx_types: Set[int] = set()

    def observe(self, signature: "Signature") -> bool:
        """Fold a signature in; return whether L0 or L1 grew (set-union)."""
        before = len(self._frames) + len(self._events) + len(self._tx_types)
        self._frames |= signature.frames
        self._events |= signature.events
        self._tx_types |= signature.tx_types
        self._bigrams |= signature.bigrams
        after = len(self._frames) + len(self._events) + len(self._tx_types)
        return after > before

    def counts(self) -> Tuple[int, int, int]:
        """Return the distinct (frames, events, bigrams) totals seen."""
        return len(self._frames), len(self._events), len(self._bigrams)

    def unreached_tx_types(self, fork: "Fork") -> List[int]:
        """Transaction types the fork accepts that no case carried."""
        return sorted(set(fork.tx_types()) - self._tx_types)

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


TRACER_INVISIBLE_HALTS: FrozenSet[str] = frozenset(
    {"AddressCollision", "InvalidContractPrefix"}
)
"""Halts that are reachable and behaviorally witnessable but NOT
signature-visible -- the fourth witness category. EELS raises them in
`process_create_message`'s finalization (and the tx-level create path),
which sets `evm.error` without an `OpException`, so the signature tracer
never records them. This is an EELS trace-completeness gap, not a fork
limit; the fix is one `evm_trace` emit upstream. The motifs that reach
them (0xEF initcode, repeated-salt CREATE2) serve the client differential,
where these paths have historically split implementations. Do not invent
an L1 event for them -- see the note in `signature.EVENT_WITNESSES`."""


_GAS_TO_REACH_DEPTH_LIMIT = 30_000_000_000
"""Roughly 2600 * (64/63)**1024: the transaction gas the 63/64 rule needs
to still leave a workable remainder at depth 1024. A fork whose tx-gas cap
sits below this cannot reach the call-depth limit."""


TX_TYPE_NAMES: Dict[int, str] = {
    0: "legacy",
    1: "access-list",
    2: "fee-market",
    3: "blob",
    4: "set-code",
}

BLIND_BUCKETS: Tuple[str, ...] = (
    "no-tier",
    "no-tx-type",
    "parameter-not-varied",
)
"""Why a target is dark. Three different costs, three different collapse
risks, three different guards; flattening them into one "unreachable"
is the move that let precompile funding hide in a config line.

- ``no-tier``: needs a generation tier that does not exist (block-level
  fields such as withdrawals and requests).
- ``no-tx-type``: needs a transaction type the generator cannot emit.
  Derived from the fork's types minus `GENERATED_TX_TYPES`, never
  hand-listed, so widening generation moves the entry by itself.
- ``parameter-not-varied``: the motif exists but a parameter that
  selects the case is held fixed.
"""

GENERATOR_BLIND_TARGETS: Dict[str, Tuple[str, str]] = {
    "phantom-read feasibility": (
        "no-tier",
        "block-level generation: blocks filled to near the gas limit "
        "carrying withdrawal or consolidation requests",
    ),
    "withdrawals in the BAL": (
        "no-tier",
        "block-level generation: withdrawals are a block field, not a "
        "transaction",
    ),
    "cold SSTORE at the stipend gate": (
        "parameter-not-varied",
        "warm and cold are not paired explicitly at the stipend gate",
    ),
    "SELFDESTRUCT log suppression": (
        "parameter-not-varied",
        "the destructor motif does not vary beneficiary (self / other) "
        "or balance (zero / nonzero)",
    ),
}
"""Named targets the map has no cell for. A dimension with no cell is
not rare, it is absent, and the map cannot rank what it cannot see;
naming it here is what makes it rankable."""


def generator_blind(fork: "Fork") -> Dict[str, List[Tuple[str, str]]]:
    """
    Dark targets grouped by bucket, with the reason for each.

    The ``no-tx-type`` bucket is computed from the fork and the
    generator's own declaration, so it cannot drift from what the
    generator does.
    """
    from execution_testing.cli.fuzzer_bridge.generator import (
        GENERATED_TX_TYPES,
    )

    grouped: Dict[str, List[Tuple[str, str]]] = {b: [] for b in BLIND_BUCKETS}
    for target, (bucket, reason) in GENERATOR_BLIND_TARGETS.items():
        grouped[bucket].append((target, reason))
    for tx_type in sorted(set(fork.tx_types()) - GENERATED_TX_TYPES):
        name = TX_TYPE_NAMES.get(tx_type, f"type {tx_type}")
        grouped["no-tx-type"].append(
            (f"tx type {tx_type} ({name})", "the generator does not emit it")
        )
    return grouped


def unreachable_on_fork(
    fork: "Fork",
) -> Tuple[FrozenSet[str], FrozenSet[Tuple[int, str, str]]]:
    """Events and frame cells that cannot occur on this fork."""
    from execution_testing.evm_tools.t8n.evm_trace.signature import (
        DEPTH_BUCKETS,
    )

    events: Set[str] = set()
    # Tracer-invisible-but-reachable halts (see TRACER_INVISIBLE_HALTS):
    # a distinct category from fork-impossible cells. They occur in EELS
    # and are behaviorally witnessable, but are raised off the trace
    # stream, so the signature cannot carry them. Grouped here only so the
    # reach map does not report them as perpetually-missing targets.
    cells = {(0, "halt", "WriteInStaticContext")} | {
        (bucket, "halt", name)
        for bucket in DEPTH_BUCKETS
        for name in TRACER_INVISIBLE_HALTS
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
    if fork is not None:
        tx_types = tracker.unreached_tx_types(fork)
        lines.append(
            f"unreached tx types ({len(tx_types)}): "
            + ", ".join(f"{t} ({TX_TYPE_NAMES.get(t, '?')})" for t in tx_types)
        )
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
    if fork is not None:
        for blind_bucket, entries in generator_blind(fork).items():
            if not entries:
                continue
            lines.append(f"generator-blind, {blind_bucket} ({len(entries)}):")
            for target, reason in entries:
                lines.append(f"  {target} -- {reason}")
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


def event_rates(fork: "Fork", seeds: range) -> Dict[str, Dict[str, int]]:
    """
    Per-event firing rate over a seed range: first-firing seed + count.

    The reach gate proves a capability exists; it is structurally blind
    to one quietly becoming rare -- its chosen seeds still fire, and a
    re-baseline will hunt for seeds that fire even a nearly-unreachable
    event. This is the trend a human reads to catch that: append a
    record per GENERATOR_VERSION bump and compare the counts.
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
    rates: Dict[str, Dict[str, int]] = {}
    for seed in seeds:
        eels.last_signature = None
        try:
            fill_case(generate_fuzzer_output(fork, seed), fork, eels)
        except Exception:  # noqa: BLE001 - unfillable is data
            continue
        signature = eels.last_signature
        if signature is None:
            continue
        for event in signature.events:
            entry = rates.setdefault(event, {"first": seed, "count": 0})
            entry["count"] += 1
    return rates


RATE_FLOOR_FRACTION = 0.01
"""Soft floor: an event firing in under 1% of fillable cases is one bad
weight change from dark, and the reach gate (which proves existence, not
rate) cannot see it. Below this the trend warns -- it never auto-corrects.
Fixing a sub-floor rate by hand-tuning weights would contaminate the
distribution-arms comparison; that experiment is where weights are set."""


def rate_floor_warnings(record: Dict[str, Any]) -> List[str]:
    """Events firing below the soft floor -- the ones near going dark."""
    seeds = record["seeds"]
    floor = RATE_FLOOR_FRACTION * seeds
    return sorted(
        f"{event} {entry['count']}/{seeds}"
        for event, entry in record["rates"].items()
        if entry["count"] < floor
    )


def event_rate_record(fork: "Fork", seeds: range) -> Dict[str, Any]:
    """One trendable reach-log record of per-event firing rates."""
    from datetime import datetime, timezone

    from execution_testing.cli.fuzzer_bridge.generator import (
        GENERATOR_VERSION,
    )
    from execution_testing.cli.mutation.reach_log import eels_commit

    record = {
        "kind": "event-rates",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "eels_commit": eels_commit(),
        "fork": fork.name(),
        "generator_version": GENERATOR_VERSION,
        "seeds": len(seeds),
        "rate_floor_fraction": RATE_FLOOR_FRACTION,
        "rates": event_rates(fork, seeds),
    }
    record["below_floor"] = rate_floor_warnings(record)
    return record


def render_event_rates(record: Dict[str, Any]) -> str:
    """Render one event-rate record as a small table, flagging the floor."""
    seeds = record["seeds"]
    floor = RATE_FLOOR_FRACTION * seeds
    lines = [
        f"event rates (generator v{record['generator_version']}, "
        f"{record['fork']}, {seeds} seeds; floor "
        f"{RATE_FLOOR_FRACTION:.0%}):"
    ]
    for event, entry in sorted(record["rates"].items()):
        flag = "  <- below floor" if entry["count"] < floor else ""
        lines.append(
            f"  {event}: {entry['count']}/{seeds} "
            f"(first seed {entry['first']}){flag}"
        )
    return "\n".join(lines)
