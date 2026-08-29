"""
An aggregates-only EELS tracer: the layered execution signature.

The signature is computed from the ``(evm, event)`` trace stream EELS already
emits on every fill, and is used to promote novel cases into the corpus. It is
deliberately cheap and local -- each event contributes independently, so no
fragile call/halt pairing is needed:

- L0 ``frames``: the set of ``(depth, kind, name)`` frame events -- which call
  kinds fired at which depths, and which halt kinds ended a frame at which
  depth. Captures "did we get deep" and the shape of the call/halt surface.
- L1 ``events``: rare/exceptional event tags, derived from the stream and the
  live ``Evm`` -- a child exception, a revert, a create, a precompile call, a
  state-gas charge, an SSTORE at/below the 2300 stipend, a refund clamped by
  the EIP-3529 fifth, a call at the 1024 depth ceiling. The 63/64 starvation is
  deliberately omitted: reproducing it needs the op's memory/extra costs
  (computed in the op body, invisible at ``OpStart``), so it stays covered by
  the CREATE2-self-copy motif.
- L2 ``bigrams``: the set of consecutive executed-opcode pairs.

Novelty is set-union across all three layers (see the fuzzer's NoveltyTracker).
"""

from dataclasses import dataclass
from typing import FrozenSet, Optional, Set, Tuple

from ethereum.trace import (
    EvmStop,
    OpException,
    OpStart,
    PrecompileStart,
    StateGasAndRefund,
    TraceEvent,
    TransactionEnd,
)

CALL_OPS = frozenset(
    {"CALL", "CALLCODE", "DELEGATECALL", "STATICCALL", "CREATE", "CREATE2"}
)

EVENT_WITNESSES = {
    "create": "behavioral",
    "revert": "behavioral",
    "child-revert": "behavioral",
    "child-exception": "behavioral",
    "precompile": "behavioral",
    "state-gas": "behavioral",
    "sstore-stipend": "behavioral",
    "refund-clamp": "behavioral",
    "call-depth-limit": "behavioral",
    "call-entry-oog": "behavioral",
}
"""Every L1 tag the tracer can emit, with the witness kind that validates
its detector -- an event registers here only with one:

- ``behavioral``: a post-state or gas footprint of the same real execution
  proves the phenomenon without the tracer.
- ``trace``: an independent reader of EELS's own EIP-3155 output (a
  different code path from this tracer) confirms it.
- ``analytic``: the expected value is computable from the input (e.g. the
  bigram set of a straight-line program).

The witness validates the detector's claim about what EELS did; whether
EELS itself is right is a different claim, owned by the invariants, the
property suite, and the client differential.

There is a fourth category that is deliberately NOT here: halts that are
reachable and behaviorally witnessable but not signature-visible, because
EELS raises them off the trace stream (its ``process_create_message``
finalization sets ``evm.error`` without an ``OpException``). Those --
AddressCollision, InvalidContractPrefix, and the rest of the
create-finalization class -- are recorded in ``TRACER_INVISIBLE_HALTS``
and marked unreachable in the signature. Do NOT invent an L1 event to
"reach" them: that would fabricate a signal for a phenomenon the trace
stream genuinely does not carry. The real fix is upstream (one
``evm_trace`` emit in that finalization); until it lands the motifs earn
their keep in the client differential, not the signature."""

KNOWN_EVENTS = frozenset(EVENT_WITNESSES)
"""The unreached complement is computed against this set, so a new event
must be registered in EVENT_WITNESSES (with its witness kind) to count."""

KNOWN_HALT_KINDS = frozenset(
    {
        "STOP",
        "Revert",
        "OutOfGasError",
        "InvalidOpcode",
        "StackUnderflowError",
        "StackDepthLimitError",
        "WriteInStaticContext",
    }
)
"""Halt kinds the L0 reach map enumerates (exception class names plus the
clean STOP); rarer exceptional halts still land in `frames` but are not part
of the enumerated complement."""

_DEPTH_BUCKET_CAP = 3  # L0 buckets depth into {0, 1, 2, >=3} so it saturates

DEPTH_BUCKETS = tuple(range(_DEPTH_BUCKET_CAP + 1))
"""The L0 depth buckets, for enumerating the reach map's product space."""


def _bucket(depth: int) -> int:
    """Bucket a raw frame depth into `{0, 1, 2, >=3}` for L0 novelty."""
    return depth if depth < _DEPTH_BUCKET_CAP else _DEPTH_BUCKET_CAP


_CALL_STIPEND = 2300  # EIP-2200: SSTORE forbidden at/below the call stipend
_STACK_DEPTH_LIMIT = 1024  # EIP-150 call-depth ceiling


def _gas_left(evm: object) -> Optional[int]:
    """Execution gas remaining, defensive across the EIP-8037 GasMeter move."""
    source = getattr(evm, "gas_meter", evm)
    value = getattr(source, "gas_left", None)
    return int(value) if value is not None else None


def _refund_is_clamped(evm: object) -> bool:
    """Whether the tx's raw refund exceeds the gas_used // 5 cap (EIP-3529)."""
    meter = getattr(evm, "gas_meter", None)
    tx_env = getattr(evm, "tx_env", None)
    if meter is None or tx_env is None:
        return False
    try:
        refund = int(meter.refund_counter)
        used_before_refund = (
            int(tx_env.gas_limit)
            - int(meter.gas_left)
            - int(meter.state_gas_left)
        )
    except (AttributeError, TypeError):
        return False
    return refund > used_before_refund // 5


@dataclass(frozen=True)
class Signature:
    """
    A case's layered execution signature: frames, events, bigrams.

    `max_depth` is telemetry, not novelty — the deepest frame reached (raw, not
    bucketed). It rides along so "did we get deep" survives L0's depth bucket,
    but it is merged by `max` and ignored by novelty set-union.
    """

    frames: FrozenSet[Tuple[int, str, str]]
    events: FrozenSet[str]
    bigrams: FrozenSet[Tuple[str, str]]
    max_depth: int = 0

    def is_empty(self) -> bool:
        """Return whether nothing was observed."""
        return not (self.frames or self.events or self.bigrams)


EMPTY_SIGNATURE = Signature(frozenset(), frozenset(), frozenset())


def merge_signatures(a: Signature, b: Signature) -> Signature:
    """Union two signatures layer by layer (e.g. across a case's blocks)."""
    return Signature(
        a.frames | b.frames,
        a.events | b.events,
        a.bigrams | b.bigrams,
        max(a.max_depth, b.max_depth),
    )


class SignatureTracer:
    """Accumulate an execution Signature from the ``(evm, event)`` stream."""

    def __init__(self) -> None:
        self._prev_op: Optional[str] = None
        self._bigrams: Set[Tuple[str, str]] = set()
        self._frames: Set[Tuple[int, str, str]] = set()
        self._events: Set[str] = set()
        self._max_depth = 0
        # True only between a CALL-family OpStart and the next OpStart or
        # PrecompileStart: the window in which an OutOfGasError means the
        # caller could not afford to enter the child at all. Cleared once
        # any child op runs (or a precompile begins), so a child-frame or
        # precompile-internal OOG is never mistaken for a call-entry OOG.
        self._call_pending = False

    def __call__(self, evm: object, event: TraceEvent) -> None:
        """Fold one trace event into the accumulating signature."""
        depth = int(getattr(evm, "depth", 0))
        self._max_depth = max(self._max_depth, depth)
        if isinstance(event, OpStart):
            name = event.op.name
            if self._prev_op is not None:
                self._bigrams.add((self._prev_op, name))
            self._prev_op = name
            # A new op has begun, so any pending call charged successfully.
            self._call_pending = False
            if name in CALL_OPS:
                self._frames.add((_bucket(depth), "call", name))
                self._call_pending = True
                if name in ("CREATE", "CREATE2"):
                    self._events.add("create")
                if depth >= _STACK_DEPTH_LIMIT:
                    self._events.add("call-depth-limit")
            elif name == "SSTORE":
                gas_left = _gas_left(evm)
                if gas_left is not None and gas_left <= _CALL_STIPEND:
                    self._events.add("sstore-stipend")
        elif isinstance(event, EvmStop):
            self._frames.add((_bucket(depth), "halt", event.op.name))
            self._call_pending = False
            if event.op.name == "REVERT":
                self._events.add("revert")
                if depth > 0:
                    self._events.add("child-revert")
        elif isinstance(event, OpException):
            # A REVERT reaches the tracer as OpException(Revert), never as
            # EvmStop(REVERT) -- the unreached map exposed the dead path.
            error_kind = type(event.error).__name__
            self._frames.add((_bucket(depth), "halt", error_kind))
            if self._entry_oog(error_kind):
                self._events.add("call-entry-oog")
            self._call_pending = False
            if error_kind == "Revert":
                self._events.add("revert")
                if depth > 0:
                    self._events.add("child-revert")
            elif depth > 0:
                self._events.add("child-exception")
        elif isinstance(event, PrecompileStart):
            self._call_pending = False
            self._events.add("precompile")
        elif isinstance(event, StateGasAndRefund):
            self._events.add("state-gas")
        elif isinstance(event, TransactionEnd):
            if _refund_is_clamped(evm):
                self._events.add("refund-clamp")

    def _entry_oog(self, error_kind: str) -> bool:
        """
        Whether this exception is a call op that died charging its entry
        cost: an OutOfGasError inside the pending window -- after a
        CALL-family OpStart, before any child op or precompile began.

        Kept as its own predicate so the witness tests can prove they
        discriminate: flipping it to fire on any OutOfGasError must turn
        the child-OOG and precompile-OOG near-misses red.
        """
        return self._call_pending and error_kind == "OutOfGasError"

    def signature(self) -> Signature:
        """Return the accumulated signature."""
        return Signature(
            frozenset(self._frames),
            frozenset(self._events),
            frozenset(self._bigrams),
            self._max_depth,
        )
