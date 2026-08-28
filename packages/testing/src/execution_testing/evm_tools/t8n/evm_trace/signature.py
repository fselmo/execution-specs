"""
An aggregates-only EELS tracer: the layered execution signature.

The signature is computed from the ``(evm, event)`` trace stream EELS already
emits on every fill, and is used to promote novel cases into the corpus. It is
deliberately cheap and local -- each event contributes independently, so no
fragile call/halt pairing is needed:

- L0 ``frames``: the set of ``(depth, kind, name)`` frame events -- which call
  kinds fired at which depths, and which halt kinds ended a frame at which
  depth. Captures "did we get deep" and the shape of the call/halt surface.
- L1 ``events``: rare/exceptional event tags derivable from the stream (a child
  exception, a revert, a create, a precompile call, a state-gas charge). Events
  needing a new spec-branch hook (SSTORE stipend crossing, refund clamp, 63/64
  starvation) are deferred to a later change.
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
)

_CALL_OPS = frozenset(
    {"CALL", "CALLCODE", "DELEGATECALL", "STATICCALL", "CREATE", "CREATE2"}
)

_DEPTH_BUCKET_CAP = 3  # L0 buckets depth into {0, 1, 2, >=3} so it saturates


def _bucket(depth: int) -> int:
    """Bucket a raw frame depth into `{0, 1, 2, >=3}` for L0 novelty."""
    return depth if depth < _DEPTH_BUCKET_CAP else _DEPTH_BUCKET_CAP


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

    def __call__(self, evm: object, event: TraceEvent) -> None:
        """Fold one trace event into the accumulating signature."""
        depth = int(getattr(evm, "depth", 0))
        self._max_depth = max(self._max_depth, depth)
        if isinstance(event, OpStart):
            name = event.op.name
            if self._prev_op is not None:
                self._bigrams.add((self._prev_op, name))
            self._prev_op = name
            if name in _CALL_OPS:
                self._frames.add((_bucket(depth), "call", name))
                if name in ("CREATE", "CREATE2"):
                    self._events.add("create")
        elif isinstance(event, EvmStop):
            self._frames.add((_bucket(depth), "halt", event.op.name))
            if event.op.name == "REVERT":
                self._events.add("revert")
                if depth > 0:
                    self._events.add("child-revert")
        elif isinstance(event, OpException):
            self._frames.add(
                (_bucket(depth), "halt", type(event.error).__name__)
            )
            if depth > 0:
                self._events.add("child-exception")
        elif isinstance(event, PrecompileStart):
            self._events.add("precompile")
        elif isinstance(event, StateGasAndRefund):
            self._events.add("state-gas")

    def signature(self) -> Signature:
        """Return the accumulated signature."""
        return Signature(
            frozenset(self._frames),
            frozenset(self._events),
            frozenset(self._bigrams),
            self._max_depth,
        )
