"""
The reach gate: landed capabilities must keep firing.

A capability regression -- an event or enumerated frame cell the
generator could reach going dark after a refactor or a distribution
change -- must fail like a broken test, not wait for a human to notice
it in the unreached map. The baseline below was measured on the
400-seed Amsterdam curve: a greedy cover chose the fewest seeds that
together fire every reached L1 event and every reached cell of the
enumerated fork space. Cases are deterministic from
``(fork, GENERATOR_VERSION, seed)``, so the gate is deterministic.

Re-baseline deliberately, never silently: the version guard fails first
with instructions, and ``compute_gate_baseline`` produces the
replacement constants, so a generator bump can never quietly weaken the
gate.

The gate detects dark, not rare: a capability dropping from 10% of
cases to 0.1% still passes while the chosen seeds fire. Pair every
re-baseline with an event-rate record
(``signature_baseline.event_rate_record``) appended to the reach log --
the trend a human reads to catch a capability quietly becoming rare.
"""

from math import ceil, log
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
    from execution_testing.forks import Fork


class StaleGateBaselineError(AssertionError):
    """The gate baseline no longer matches the generator or fork."""


BASELINE_GENERATOR_VERSION = 15
BASELINE_FORK = "Amsterdam"

GATE_SEEDS: Tuple[int, ...] = (
    54,
    243,
    1224,
    2357,
    2953,
    4664,
)
"""Greedy cover over a 5000-seed baseline at v15: together these fire
every target below.

Re-baseline over at least `GATE_BASELINE_SEEDS`, which is measured
rather than chosen -- see `required_gate_seeds`. A narrower window
reports its own sampling as a regression: at 400 seeds this map lost
`OutOfBoundsRead` at depths 2 and 3, and seeds 400-800 reach both while
800-1200 reach neither."""

GATE_BASELINE_SEEDS = 2100
"""Baseline window, from the rarest gated cell's measured rate.

`(3, "halt", "OutOfBoundsRead")` occurs 11 times in 5000 cases at v15,
a rate of 0.0022, which needs 2094 seeds to clear a 1% miss probability
(at v14 it was 14 in 6000 and 1977). Recheck it with `required_gate_seeds`
whenever a motif is added: a draw at 0.002 needs nearly 2800, and the
number moving is the signal. A 2000-seed probe of v15 put the rarest cell
at 2/2000 and asked for 4606; the small sample, not the generator, was
what moved."""

GATE_EVENTS: FrozenSet[str] = frozenset(
    {
        "call-entry-oog",
        "child-exception",
        "child-revert",
        "child-state-gas-spill",
        "create",
        "precompile",
        "refund-clamp",
        "revert",
        "sstore-stipend",
        "state-gas",
        "state-gas-from-reservoir",
        "state-gas-interleave",
        "state-gas-reservoir",
        "tx-state-gas",
        "tx-state-gas-spill",
    }
)

_ALL_CALLS = (
    "CALL",
    "CALLCODE",
    "CREATE",
    "CREATE2",
    "DELEGATECALL",
    "STATICCALL",
)

_DEEP_HALTS = (
    "InvalidJumpDestError",
    "InvalidOpcode",
    "InvalidParameter",
    "KZGProofError",
    "OutOfBoundsRead",
    "OutOfGasError",
    "Revert",
    "STOP",
    "StackOverflowError",
    "StackUnderflowError",
    "WriteInStaticContext",
)
# Which rare halts land deep shifts between generator versions as the
# motif weights move; the baseline records what a version actually
# reaches, and the event-rate and density trends watch the rates.

_GATE_CELLS: Dict[int, Dict[str, Tuple[str, ...]]] = {
    0: {
        "call": _ALL_CALLS,
        "halt": (
            "InvalidJumpDestError",
            "InvalidOpcode",
            "InvalidParameter",
            "KZGProofError",
            "OutOfBoundsRead",
            "OutOfGasError",
            "Revert",
            "STOP",
            "StackOverflowError",
            "StackUnderflowError",
        ),
    },
    1: {
        "call": _ALL_CALLS,
        "halt": (
            "InvalidJumpDestError",
            "InvalidOpcode",
            "InvalidParameter",
            "KZGProofError",
            "OutOfBoundsRead",
            "OutOfGasError",
            "Revert",
            "STOP",
            "StackOverflowError",
            "StackUnderflowError",
            "WriteInStaticContext",
        ),
    },
    2: {"call": _ALL_CALLS, "halt": _DEEP_HALTS},
    3: {"call": _ALL_CALLS, "halt": _DEEP_HALTS},
}

GATE_FRAMES: FrozenSet[Tuple[int, str, str]] = frozenset(
    (bucket, kind, name)
    for bucket, kinds in _GATE_CELLS.items()
    for kind, names in kinds.items()
    for name in names
)


def check_reach_gate(fork: "Fork") -> List[str]:
    """
    Fill the gate seeds; return every declared target that went dark.

    An empty list means every landed capability still fires. A gate seed
    that fails to fill raises -- that too is a regression.
    """
    from execution_testing.cli.fuzzer_bridge.campaign import fill_case
    from execution_testing.cli.fuzzer_bridge.generator import (
        GENERATOR_VERSION,
        generate_fuzzer_output,
    )
    from execution_testing.client_clis.clis.execution_specs import (
        ExecutionSpecsTransitionTool,
    )

    if (
        GENERATOR_VERSION != BASELINE_GENERATOR_VERSION
        or fork.name() != BASELINE_FORK
    ):
        raise StaleGateBaselineError(
            f"gate baseline is for generator "
            f"v{BASELINE_GENERATOR_VERSION} on {BASELINE_FORK}, got "
            f"v{GENERATOR_VERSION} on {fork.name()}. Re-baseline "
            f"deliberately: compute_gate_baseline(fork, range(400)) and "
            f"update this module's constants."
        )

    eels = ExecutionSpecsTransitionTool()
    eels.compute_signature = True
    events: Set[str] = set()
    frames: Set[Tuple[int, str, str]] = set()
    for seed in GATE_SEEDS:
        eels.last_signature = None
        fill_case(generate_fuzzer_output(fork, seed), fork, eels)
        signature = eels.last_signature
        if signature is not None:
            events |= signature.events
            frames |= signature.frames

    missing = [f"event {name}" for name in sorted(GATE_EVENTS - events)]
    missing += [
        f"depth{'>=' if bucket == 3 else ' '}{bucket} {kind} {name}"
        for bucket, kind, name in sorted(GATE_FRAMES - frames)
    ]
    return missing


GATE_MISS_PROBABILITY = 0.01
"""How often a baseline window may miss a gated target by chance.

The gate compares a fresh baseline against the recorded one, so a cell
the window happened not to sample reads as a regression. That is not
hypothetical: re-baselining v14 over 400 seeds reported
`OutOfBoundsRead` lost at depths 2 and 3, and it was sampling --
seeds 400-800 reach both, seeds 800-1200 reach neither, because the
motif behind them draws at 0.005.
"""


def required_gate_seeds(
    occurrences: Dict[Any, int],
    sample: int,
    miss_probability: float = GATE_MISS_PROBABILITY,
) -> int:
    """
    The window width the rarest gated target needs.

    Occurrences are Poisson at rate `p` per case, so a window of `n`
    misses a target with probability `exp(-n * p)`. Solving for the
    stated bound gives `n = ln(1 / miss) / p_min`, and the rarest
    observed target sets `p_min`.

    Derived rather than fixed for the same reason the no-tx-type bucket
    is derived from the fork: a rare motif added later widens the window
    by itself. A constant would leave the next one -- a draw at 0.002 is
    2.4 expected in 1200 seeds and a 9% miss rate -- reporting its own
    sampling as a regression, which is the failure this exists to stop.

    A target observed zero times contributes no rate and is excluded: it
    is either genuinely dark, which the gate reports, or rarer than the
    probe can measure, which a wider probe answers.

    The estimate is only as good as its probe, and a thin probe reads
    low. Measured on 1200 seeds the rarest cell showed 1 occurrence and
    this returned 5527; measured on 6000 the same cell showed 14, a rate
    of 0.0023, and the requirement is 1977. Probe wide, then set the
    window from the result.
    """
    seen = [count for count in occurrences.values() if count]
    if not seen or sample <= 0:
        return sample
    rarest_rate = min(seen) / sample
    return ceil(log(1 / miss_probability) / rarest_rate)


def _rarest(occurrences: Dict[Any, int], sample: int) -> Optional[str]:
    """The scarcest observed target and its rate, for the record."""
    seen = {k: v for k, v in occurrences.items() if v}
    if not seen or sample <= 0:
        return None
    item, count = min(seen.items(), key=lambda kv: kv[1])
    return f"{item[0]} {item[1]} at {count}/{sample}"


def _bal_items(observation: Any, seed: int) -> Set[Any]:
    """
    The witnessed BAL cells one baseline case reached.

    A recorder call with no derived reason is the runtime witness saying
    the static walk missed a caller, and a baseline is exactly where that
    has to stop the run: gating a space that is known to be incomplete
    would freeze the omission into the constants.
    """
    from execution_testing.cli.fuzzer_bridge.bal_reach import witness_kind

    if observation is None:
        return set()
    if observation.unattributed:
        raise StaleGateBaselineError(
            f"seed {seed}: recorder calls with no derived reason "
            f"{dict(observation.unattributed)}; the BAL derivation missed "
            "a caller. Fix the derivation before re-baselining."
        )
    return {
        ("bal", cell) for cell in observation.cells if witness_kind(cell[0])
    }


def compute_gate_baseline(fork: "Fork", seeds: range) -> Dict[str, Any]:
    """
    Measure per-seed signatures and greedy-cover a fresh baseline.

    Returns the replacement constants for this module: the chosen seeds
    and the events/cells they cover (events plus reached cells of the
    enumerated fork space). Run over the full baseline range (400) when
    re-baselining after a GENERATOR_VERSION bump.
    """
    from execution_testing.cli.fuzzer_bridge.bal_reach import observer_spec
    from execution_testing.cli.fuzzer_bridge.campaign import fill_case
    from execution_testing.cli.fuzzer_bridge.generator import (
        GENERATOR_VERSION,
        generate_fuzzer_output,
    )
    from execution_testing.cli.fuzzer_bridge.signature_baseline import (
        fork_reach_space,
    )
    from execution_testing.client_clis.clis.execution_specs import (
        ExecutionSpecsTransitionTool,
    )
    from execution_testing.evm_tools.t8n.evm_trace.signature import (
        DEPTH_BUCKETS,
    )

    call_ops, halt_kinds = fork_reach_space(fork)
    enumerated = {
        (bucket, "call", op) for bucket in DEPTH_BUCKETS for op in call_ops
    } | {
        (bucket, "halt", halt)
        for bucket in DEPTH_BUCKETS
        for halt in halt_kinds
    }

    eels = ExecutionSpecsTransitionTool()
    eels.compute_signature = True
    eels.bal_reach = observer_spec(fork)
    per_seed: Dict[int, Set[Any]] = {}
    for seed in seeds:
        eels.last_signature = None
        eels.last_bal_observation = None
        try:
            fill_case(generate_fuzzer_output(fork, seed), fork, eels)
        except Exception:  # noqa: BLE001 - unfillable seeds are skipped
            continue
        signature = eels.last_signature
        if signature is None:
            continue
        items: Set[Any] = {("event", name) for name in signature.events}
        items |= {
            ("frame", cell) for cell in signature.frames if cell in enumerated
        }
        items |= _bal_items(eels.last_bal_observation, seed)
        per_seed[seed] = items

    uncovered = set().union(*per_seed.values()) if per_seed else set()
    targets = set(uncovered)
    chosen: List[int] = []
    while uncovered:
        best = max(per_seed, key=lambda s: len(per_seed[s] & uncovered))
        gain = per_seed[best] & uncovered
        if not gain:
            break
        chosen.append(best)
        uncovered -= gain

    occurrences: Dict[Any, int] = {}
    for items in per_seed.values():
        for item in items:
            occurrences[item] = occurrences.get(item, 0) + 1

    return {
        "generator_version": GENERATOR_VERSION,
        "fork": fork.name(),
        "seeds": sorted(chosen),
        "events": sorted(t[1] for t in targets if t[0] == "event"),
        "frames": sorted(t[1] for t in targets if t[0] == "frame"),
        "bal_cells": sorted(t[1] for t in targets if t[0] == "bal"),
        "bal_occurrences": {
            "|".join(item[1]): count
            for item, count in sorted(occurrences.items())
            if item[0] == "bal"
        },
        "required_seeds": required_gate_seeds(occurrences, len(per_seed)),
        "rarest": _rarest(occurrences, len(per_seed)),
    }
