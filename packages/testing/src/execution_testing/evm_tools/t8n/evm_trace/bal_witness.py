"""
A witness of the storage slots execution accessed, for checking the BAL.

The BAL is built from the state tracker's read and write sets, so a slot the
tracker forgets is missing from those sets too. This tracer observes slots
from the trace stream instead. No trace event lands on the access itself, so
it records the slots an `SLOAD` or `SSTORE` started on and the slots it
finished on, and the BAL must sit between them: `ended <= BAL <= started`.
"""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, FrozenSet, List, Optional, Set, Tuple

from ethereum.trace import EvmTracer, OpEnd, OpException, OpStart, TraceEvent

if TYPE_CHECKING:
    from execution_testing.test_types.block_access_list import (
        BlockAccessList,
    )

SlotAccess = Tuple[int, int]
"""An accessed storage slot as `(account address, slot key)`."""

STORAGE_OPS = frozenset({"SLOAD", "SSTORE"})


@dataclass(frozen=True)
class BalWitness:
    """The storage slots a run started and finished accessing."""

    started: FrozenSet[SlotAccess] = frozenset()
    ended: FrozenSet[SlotAccess] = frozenset()


class BalWitnessTracer(EvmTracer):
    """Collect the storage slots each `SLOAD` and `SSTORE` touches."""

    def __init__(self) -> None:
        self._started: Set[SlotAccess] = set()
        self._ended: Set[SlotAccess] = set()
        self._pending: Optional[SlotAccess] = None

    def __call__(self, evm: Any, event: TraceEvent) -> None:
        """Record the slot of a storage op when it starts and ends."""
        if isinstance(event, OpStart):
            self._pending = None
            # The slot key is on top of the stack, and `current_target` is
            # the storage owner under DELEGATECALL and CALLCODE too. An op
            # on an empty stack fails before it touches storage.
            if event.op.name in STORAGE_OPS and evm.stack:
                target = int.from_bytes(evm.current_target, "big")
                self._pending = (target, int(evm.stack[-1]))
                self._started.add(self._pending)
        elif isinstance(event, OpEnd):
            if self._pending is not None:
                self._ended.add(self._pending)
            self._pending = None
        elif isinstance(event, OpException):
            self._pending = None

    def witness(self) -> BalWitness:
        """Return the slots observed so far."""
        return BalWitness(frozenset(self._started), frozenset(self._ended))


def bal_slots(bal: "BlockAccessList") -> FrozenSet[SlotAccess]:
    """Return every storage slot the BAL names, read or changed."""
    slots: Set[SlotAccess] = set()
    for entry in bal.root:
        address = int.from_bytes(entry.address, "big")
        for slot in entry.storage_changes:
            slots.add((address, int(slot.slot)))
        for read in entry.storage_reads:
            slots.add((address, int(read)))
    return frozenset(slots)


@dataclass
class BalDisagreement:
    """Slots on which the BAL broke one side of the witness bounds."""

    kind: str
    slots: Tuple[SlotAccess, ...] = field(default_factory=tuple)

    def __str__(self) -> str:
        """Render the disagreement with a sample of the slots."""
        sample = ", ".join(
            f"{address:#042x}:{slot:#x}" for address, slot in self.slots[:3]
        )
        return f"{self.kind} ({len(self.slots)}): {sample}"


def check_bal_relation(
    witness: BalWitness, listed: FrozenSet[SlotAccess]
) -> List[BalDisagreement]:
    """Check `ended <= listed <= started`, reporting each side that broke."""
    disagreements = []
    dropped = witness.ended - listed
    if dropped:
        disagreements.append(
            BalDisagreement(
                "accessed but absent from the BAL", tuple(sorted(dropped))
            )
        )
    invented = listed - witness.started
    if invented:
        disagreements.append(
            BalDisagreement(
                "in the BAL but never accessed", tuple(sorted(invented))
            )
        )
    return disagreements
