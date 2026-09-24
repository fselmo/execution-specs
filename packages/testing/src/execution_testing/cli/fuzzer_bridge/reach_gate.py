"""
The reach gate: landed capabilities must keep firing.

A capability regression -- an event or enumerated frame cell the
generator could reach going dark after a refactor or a distribution
change -- must fail like a broken test, not wait for a human to notice
it in the unreached map. The baseline below was measured over 5000
Amsterdam seeds: a greedy cover chose the fewest seeds that together
fire every reached L1 event, every reached cell of the enumerated fork
space, and every BAL cell the window samples reliably (see
`bal_gate_floor`). Cases are deterministic from
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


BASELINE_GENERATOR_VERSION = 17
BASELINE_FORK = "Amsterdam"

GATE_SEEDS: Tuple[int, ...] = (
    312,
    494,
    505,
    776,
    783,
    871,
    3037,
    3550,
    3930,
    4598,
    4777,
)
"""Greedy cover over a 5000-seed baseline at v17: together these fire
every target below.

Re-baseline over at least `GATE_BASELINE_SEEDS`, which is measured
rather than chosen -- see `required_gate_seeds`. A narrower window
reports its own sampling as a regression: at 400 seeds this map lost
`OutOfBoundsRead` at depths 2 and 3, and seeds 400-800 reach both while
800-1200 reach neither."""

GATE_BASELINE_SEEDS = 2400
"""Baseline window, from the rarest gated cell's measured rate.

`(3, "halt", "StackOverflowError")` occurs 10 times in 5000 cases at
v17, a rate of 0.0020, which needs 2303 seeds to clear a 1% miss
probability (`OutOfBoundsRead` at depth 3: 10 in 5000 and 2303 at v16,
11 in 5000 and 2094 at v15; 14 in 6000 and 1977 at v14). Recheck it
with `required_gate_seeds` whenever a motif is added; the number moving
is the signal. A 2000-seed probe of v15 put the rarest cell at 2/2000
and asked for 4606; the small sample, not the generator, was what
moved."""

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


GATE_BAL_CELLS: FrozenSet[Tuple[str, str, str]] = frozenset(
    {
        ("fork.check_transaction", "touched_account", "exceptional_halt"),
        ("fork.check_transaction", "touched_account", "out_of_gas"),
        ("fork.check_transaction", "touched_account", "revert"),
        ("fork.check_transaction", "touched_account", "success"),
        ("fork.disburse_gas_fees", "balance_change", "exceptional_halt"),
        ("fork.disburse_gas_fees", "balance_change", "out_of_gas"),
        ("fork.disburse_gas_fees", "balance_change", "revert"),
        ("fork.disburse_gas_fees", "balance_change", "success"),
        ("fork.disburse_gas_fees", "touched_account", "exceptional_halt"),
        ("fork.disburse_gas_fees", "touched_account", "out_of_gas"),
        ("fork.disburse_gas_fees", "touched_account", "revert"),
        ("fork.disburse_gas_fees", "touched_account", "success"),
        (
            "fork.process_checked_system_transaction",
            "touched_account",
            "success",
        ),
        ("fork.process_withdrawals", "balance_change", "success"),
        ("fork.process_withdrawals", "touched_account", "success"),
        ("fork.update_sender_state", "balance_change", "exceptional_halt"),
        ("fork.update_sender_state", "balance_change", "out_of_gas"),
        ("fork.update_sender_state", "balance_change", "revert"),
        ("fork.update_sender_state", "balance_change", "success"),
        ("fork.update_sender_state", "nonce_change", "exceptional_halt"),
        ("fork.update_sender_state", "nonce_change", "out_of_gas"),
        ("fork.update_sender_state", "nonce_change", "revert"),
        ("fork.update_sender_state", "nonce_change", "success"),
        ("fork.update_sender_state", "touched_account", "exceptional_halt"),
        ("fork.update_sender_state", "touched_account", "out_of_gas"),
        ("fork.update_sender_state", "touched_account", "revert"),
        ("fork.update_sender_state", "touched_account", "success"),
        (
            "vm.eoa_delegation.calculate_delegation_cost",
            "touched_account",
            "exceptional_halt",
        ),
        (
            "vm.eoa_delegation.calculate_delegation_cost",
            "touched_account",
            "out_of_gas",
        ),
        (
            "vm.eoa_delegation.calculate_delegation_cost",
            "touched_account",
            "revert",
        ),
        (
            "vm.eoa_delegation.calculate_delegation_cost",
            "touched_account",
            "success",
        ),
        (
            "vm.eoa_delegation.resolve_delegated_code_address",
            "touched_account",
            "exceptional_halt",
        ),
        (
            "vm.eoa_delegation.resolve_delegated_code_address",
            "touched_account",
            "out_of_gas",
        ),
        (
            "vm.eoa_delegation.resolve_delegated_code_address",
            "touched_account",
            "revert",
        ),
        (
            "vm.eoa_delegation.resolve_delegated_code_address",
            "touched_account",
            "success",
        ),
        (
            "vm.eoa_delegation.set_delegation",
            "code_change",
            "exceptional_halt",
        ),
        ("vm.eoa_delegation.set_delegation", "code_change", "out_of_gas"),
        ("vm.eoa_delegation.set_delegation", "code_change", "revert"),
        ("vm.eoa_delegation.set_delegation", "code_change", "success"),
        (
            "vm.eoa_delegation.set_delegation",
            "nonce_change",
            "exceptional_halt",
        ),
        ("vm.eoa_delegation.set_delegation", "nonce_change", "out_of_gas"),
        ("vm.eoa_delegation.set_delegation", "nonce_change", "revert"),
        ("vm.eoa_delegation.set_delegation", "nonce_change", "success"),
        (
            "vm.eoa_delegation.set_delegation",
            "touched_account",
            "exceptional_halt",
        ),
        ("vm.eoa_delegation.set_delegation", "touched_account", "out_of_gas"),
        ("vm.eoa_delegation.set_delegation", "touched_account", "revert"),
        ("vm.eoa_delegation.set_delegation", "touched_account", "success"),
        (
            "vm.eoa_delegation.validate_authorization",
            "touched_account",
            "exceptional_halt",
        ),
        (
            "vm.eoa_delegation.validate_authorization",
            "touched_account",
            "out_of_gas",
        ),
        (
            "vm.eoa_delegation.validate_authorization",
            "touched_account",
            "revert",
        ),
        (
            "vm.eoa_delegation.validate_authorization",
            "touched_account",
            "success",
        ),
        (
            "vm.instructions.environment.balance",
            "touched_account",
            "exceptional_halt",
        ),
        (
            "vm.instructions.environment.balance",
            "touched_account",
            "out_of_gas",
        ),
        ("vm.instructions.environment.balance", "touched_account", "revert"),
        ("vm.instructions.environment.balance", "touched_account", "success"),
        (
            "vm.instructions.environment.extcodecopy",
            "touched_account",
            "out_of_gas",
        ),
        (
            "vm.instructions.environment.extcodehash",
            "touched_account",
            "exceptional_halt",
        ),
        (
            "vm.instructions.environment.extcodehash",
            "touched_account",
            "out_of_gas",
        ),
        (
            "vm.instructions.environment.extcodesize",
            "touched_account",
            "exceptional_halt",
        ),
        (
            "vm.instructions.environment.extcodesize",
            "touched_account",
            "out_of_gas",
        ),
        (
            "vm.instructions.environment.extcodesize",
            "touched_account",
            "success",
        ),
        (
            "vm.instructions.environment.self_balance",
            "touched_account",
            "exceptional_halt",
        ),
        (
            "vm.instructions.environment.self_balance",
            "touched_account",
            "out_of_gas",
        ),
        (
            "vm.instructions.environment.self_balance",
            "touched_account",
            "revert",
        ),
        (
            "vm.instructions.environment.self_balance",
            "touched_account",
            "success",
        ),
        ("vm.instructions.storage.sload", "storage_read", "exceptional_halt"),
        ("vm.instructions.storage.sload", "storage_read", "out_of_gas"),
        ("vm.instructions.storage.sload", "storage_read", "revert"),
        ("vm.instructions.storage.sload", "storage_read", "success"),
        ("vm.instructions.storage.sstore", "storage_read", "exceptional_halt"),
        ("vm.instructions.storage.sstore", "storage_read", "out_of_gas"),
        ("vm.instructions.storage.sstore", "storage_read", "revert"),
        ("vm.instructions.storage.sstore", "storage_read", "success"),
        (
            "vm.instructions.storage.sstore",
            "storage_write",
            "exceptional_halt",
        ),
        ("vm.instructions.storage.sstore", "storage_write", "out_of_gas"),
        ("vm.instructions.storage.sstore", "storage_write", "revert"),
        ("vm.instructions.storage.sstore", "storage_write", "success"),
        (
            "vm.instructions.storage.sstore",
            "touched_account",
            "exceptional_halt",
        ),
        ("vm.instructions.storage.sstore", "touched_account", "out_of_gas"),
        ("vm.instructions.storage.sstore", "touched_account", "revert"),
        ("vm.instructions.storage.sstore", "touched_account", "success"),
        ("vm.instructions.system.call", "touched_account", "exceptional_halt"),
        ("vm.instructions.system.call", "touched_account", "out_of_gas"),
        ("vm.instructions.system.call", "touched_account", "revert"),
        ("vm.instructions.system.call", "touched_account", "success"),
        (
            "vm.instructions.system.callcode",
            "touched_account",
            "exceptional_halt",
        ),
        ("vm.instructions.system.callcode", "touched_account", "out_of_gas"),
        ("vm.instructions.system.callcode", "touched_account", "revert"),
        ("vm.instructions.system.callcode", "touched_account", "success"),
        (
            "vm.instructions.system.create",
            "touched_account",
            "exceptional_halt",
        ),
        ("vm.instructions.system.create", "touched_account", "out_of_gas"),
        ("vm.instructions.system.create", "touched_account", "success"),
        (
            "vm.instructions.system.delegatecall",
            "touched_account",
            "exceptional_halt",
        ),
        (
            "vm.instructions.system.delegatecall",
            "touched_account",
            "out_of_gas",
        ),
        ("vm.instructions.system.delegatecall", "touched_account", "revert"),
        ("vm.instructions.system.delegatecall", "touched_account", "success"),
        (
            "vm.instructions.system.generic_create",
            "nonce_change",
            "exceptional_halt",
        ),
        (
            "vm.instructions.system.generic_create",
            "nonce_change",
            "out_of_gas",
        ),
        ("vm.instructions.system.generic_create", "nonce_change", "revert"),
        ("vm.instructions.system.generic_create", "nonce_change", "success"),
        (
            "vm.instructions.system.generic_create",
            "touched_account",
            "exceptional_halt",
        ),
        (
            "vm.instructions.system.generic_create",
            "touched_account",
            "out_of_gas",
        ),
        ("vm.instructions.system.generic_create", "touched_account", "revert"),
        (
            "vm.instructions.system.generic_create",
            "touched_account",
            "success",
        ),
        ("vm.instructions.system.selfdestruct", "balance_change", "success"),
        ("vm.instructions.system.selfdestruct", "touched_account", "success"),
        (
            "vm.instructions.system.staticcall",
            "touched_account",
            "exceptional_halt",
        ),
        ("vm.instructions.system.staticcall", "touched_account", "out_of_gas"),
        ("vm.instructions.system.staticcall", "touched_account", "revert"),
        ("vm.instructions.system.staticcall", "touched_account", "success"),
        (
            "vm.interpreter.charge_value_transfer_to_non_alive_account",
            "touched_account",
            "exceptional_halt",
        ),
        (
            "vm.interpreter.charge_value_transfer_to_non_alive_account",
            "touched_account",
            "out_of_gas",
        ),
        (
            "vm.interpreter.charge_value_transfer_to_non_alive_account",
            "touched_account",
            "revert",
        ),
        (
            "vm.interpreter.charge_value_transfer_to_non_alive_account",
            "touched_account",
            "success",
        ),
        ("vm.interpreter.create_evm", "touched_account", "exceptional_halt"),
        ("vm.interpreter.create_evm", "touched_account", "out_of_gas"),
        ("vm.interpreter.create_evm", "touched_account", "revert"),
        ("vm.interpreter.create_evm", "touched_account", "success"),
        ("vm.interpreter.process_call", "balance_change", "exceptional_halt"),
        ("vm.interpreter.process_call", "balance_change", "out_of_gas"),
        ("vm.interpreter.process_call", "balance_change", "revert"),
        ("vm.interpreter.process_call", "balance_change", "success"),
        ("vm.interpreter.process_call", "touched_account", "exceptional_halt"),
        ("vm.interpreter.process_call", "touched_account", "out_of_gas"),
        ("vm.interpreter.process_call", "touched_account", "revert"),
        ("vm.interpreter.process_call", "touched_account", "success"),
        ("vm.interpreter.process_create", "nonce_change", "exceptional_halt"),
        ("vm.interpreter.process_create", "nonce_change", "out_of_gas"),
        ("vm.interpreter.process_create", "nonce_change", "revert"),
        ("vm.interpreter.process_create", "nonce_change", "success"),
        (
            "vm.interpreter.process_create",
            "touched_account",
            "exceptional_halt",
        ),
        ("vm.interpreter.process_create", "touched_account", "out_of_gas"),
        ("vm.interpreter.process_create", "touched_account", "revert"),
        ("vm.interpreter.process_create", "touched_account", "success"),
    }
)
"""BAL cells the baseline window samples reliably: 134 of the
147 reached over 5000 seeds at v17, each seen at least
`bal_gate_floor` = 10 times. The rest are `BAL_CELLS_BELOW_WINDOW`."""

BAL_CELLS_BELOW_WINDOW: Dict[Tuple[str, str, str], int] = {
    ("fork.process_transaction", "code_change", "success"): 1,
    ("fork.process_transaction", "nonce_change", "success"): 9,
    ("fork.process_transaction", "storage_read", "success"): 9,
    ("fork.process_transaction", "touched_account", "success"): 9,
    (
        "vm.instructions.environment.extcodecopy",
        "touched_account",
        "exceptional_halt",
    ): 7,
    (
        "vm.instructions.environment.extcodecopy",
        "touched_account",
        "revert",
    ): 1,
    (
        "vm.instructions.environment.extcodecopy",
        "touched_account",
        "success",
    ): 3,
    (
        "vm.instructions.environment.extcodehash",
        "touched_account",
        "revert",
    ): 3,
    (
        "vm.instructions.environment.extcodehash",
        "touched_account",
        "success",
    ): 9,
    (
        "vm.instructions.environment.extcodesize",
        "touched_account",
        "revert",
    ): 9,
    ("vm.instructions.system.create", "touched_account", "revert"): 5,
    (
        "vm.instructions.system.selfdestruct",
        "touched_account",
        "out_of_gas",
    ): 3,
    ("vm.interpreter.process_create", "code_change", "success"): 7,
}
"""Reached in the 5000-seed baseline but fewer than `bal_gate_floor` times,
with their occurrence counts. Listed so they stay visible rather than gated:
the window that would sample them reliably is far wider than the one the
gate runs on, and the rate record is the instrument for rare."""


def check_reach_gate(fork: "Fork") -> List[str]:
    """
    Fill the gate seeds; return every declared target that went dark.

    An empty list means every landed capability still fires. A gate seed
    that fails to fill raises -- that too is a regression.
    """
    from execution_testing.cli.fuzzer_bridge.bal_reach import observer_spec
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
    eels.bal_reach = observer_spec(fork)
    events: Set[str] = set()
    frames: Set[Tuple[int, str, str]] = set()
    bal: Set[Tuple[str, str, str]] = set()
    for seed in GATE_SEEDS:
        eels.last_signature = None
        eels.last_bal_observation = None
        fill_case(generate_fuzzer_output(fork, seed), fork, eels)
        signature = eels.last_signature
        if signature is not None:
            events |= signature.events
            frames |= signature.frames
        bal |= {
            item[1] for item in _bal_items(eels.last_bal_observation, seed)
        }

    missing = [f"event {name}" for name in sorted(GATE_EVENTS - events)]
    missing += [
        f"depth{'>=' if bucket == 3 else ' '}{bucket} {kind} {name}"
        for bucket, kind, name in sorted(GATE_FRAMES - frames)
    ]
    missing += [
        f"bal {reason} {kind} {outcome}"
        for reason, kind, outcome in sorted(GATE_BAL_CELLS - bal)
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


def bal_gate_floor(
    window: int,
    sample: int,
    miss_probability: float = GATE_MISS_PROBABILITY,
) -> int:
    """
    How often a BAL cell must occur in `sample` cases to be gated.

    The inverse of `required_gate_seeds`: a window of `window` seeds
    samples a cell at rate `p` with the stated miss probability only when
    `p >= ln(1 / miss) / window`. The window stays the one the events and
    frame cells already need, and a BAL cell rarer than it can sample is
    listed as reached but below the window rather than allowed to widen
    it. Gating the two cells seen once in 5000 would have needed a window
    of 23,026 seeds, a re-baseline long enough that people stop running
    it, which is worse than not gating those two. The gate detects dark,
    not rare; the rate record is the instrument for rare.
    """
    return ceil(sample * log(1 / miss_probability) / window)


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

    occurrences: Dict[Any, int] = {}
    for items in per_seed.values():
        for item in items:
            occurrences[item] = occurrences.get(item, 0) + 1
    base = {k: v for k, v in occurrences.items() if k[0] != "bal"}
    window = required_gate_seeds(base, len(per_seed))
    floor = bal_gate_floor(window, len(per_seed))
    below_window = {
        k[1]: v for k, v in occurrences.items() if k[0] == "bal" and v < floor
    }
    targets = {
        k for k, v in occurrences.items() if k[0] != "bal" or v >= floor
    }
    uncovered = set(targets)
    chosen: List[int] = []
    while uncovered:
        best = max(per_seed, key=lambda s: len(per_seed[s] & uncovered))
        gain = per_seed[best] & uncovered
        if not gain:
            break
        chosen.append(best)
        uncovered -= gain

    gated = {k: v for k, v in occurrences.items() if k in targets}
    return {
        "generator_version": GENERATOR_VERSION,
        "fork": fork.name(),
        "seeds": sorted(chosen),
        "events": sorted(t[1] for t in targets if t[0] == "event"),
        "frames": sorted(t[1] for t in targets if t[0] == "frame"),
        "bal_cells": sorted(t[1] for t in targets if t[0] == "bal"),
        "bal_floor": floor,
        "bal_below_window": {
            "|".join(cell): count
            for cell, count in sorted(below_window.items())
        },
        "required_seeds": required_gate_seeds(gated, len(per_seed)),
        "rarest": _rarest(gated, len(per_seed)),
    }
