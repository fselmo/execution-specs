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

from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    FrozenSet,
    List,
    Set,
    Tuple,
)

if TYPE_CHECKING:
    from execution_testing.forks import Fork


class StaleGateBaselineError(AssertionError):
    """The gate baseline no longer matches the generator or fork."""


BASELINE_GENERATOR_VERSION = 12
BASELINE_FORK = "Amsterdam"

GATE_SEEDS: Tuple[int, ...] = (
    7,
    48,
    108,
    115,
    116,
    120,
    311,
    365,
)
"""Greedy cover over the 400-seed baseline: together these fire every
target below."""

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
        "state-gas-reservoir",
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


def compute_gate_baseline(fork: "Fork", seeds: range) -> Dict[str, Any]:
    """
    Measure per-seed signatures and greedy-cover a fresh baseline.

    Returns the replacement constants for this module: the chosen seeds
    and the events/cells they cover (events plus reached cells of the
    enumerated fork space). Run over the full baseline range (400) when
    re-baselining after a GENERATOR_VERSION bump.
    """
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
    per_seed: Dict[int, Set[Any]] = {}
    for seed in seeds:
        eels.last_signature = None
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

    return {
        "generator_version": GENERATOR_VERSION,
        "fork": fork.name(),
        "seeds": sorted(chosen),
        "events": sorted(t[1] for t in targets if t[0] == "event"),
        "frames": sorted(t[1] for t in targets if t[0] == "frame"),
    }
