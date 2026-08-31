"""
An independent witness for the block access list.

The BAL is built from the state tracker's own read and write sets
(`build_block_access_list` feeds directly from `block_state.storage_reads`
and `account_reads`), so comparing the list against those sets tests only
the sort-and-encode step. It cannot answer the question that matters --
whether the tracker recorded the accesses execution actually performed --
because a forgotten access is missing from both sides.

This observes accesses from the `(evm, event)` trace stream instead, a
different code path from the builder, so a tracker that drops an access
disagrees with it. That is the "every client agrees, the spec is wrong"
class: a BAL bug here is invisible to any cross-client comparison,
because every client matching the reference reproduces it.

Why a sandwich rather than an equality
--------------------------------------

The trace stream carries no event at the moment an access is performed.
`SSTORE` charges its access cost, checks it, *then* performs the access,
then charges state gas -- so an op can raise before accessing (recorded
by neither) or after accessing (recorded by the tracker alone). Neither
`OpStart` nor `OpEnd` lands on the access itself:

- committing at `OpStart` counts ops that died on the gas gate, an
  over-count;
- committing at `OpEnd` drops ops that accessed and then died on the
  state charge, an under-count.

So the witness reports both, and the invariant is the sandwich they
bracket: `ended <= BAL <= started`. It is weaker than equality and still
two-sided -- a dropped access breaks the lower bound, an invented one
breaks the upper. Closing it to an equality needs one `evm_trace` emit at
the access point in the fork's storage instructions; until that lands
upstream the sandwich is the strongest independent statement available.

Scope: storage slots, deliberately
----------------------------------

Account-level access has sources no opcode names -- the sender, the
coinbase, withdrawal targets, system contracts -- so an opcode-derived
account set is not comparable to the BAL's without modelling all of them,
and that model would be the assumption this exists to avoid.

Do not "complete" this by adding an account-level check sourced from the
tracker's own `account_reads`. That is the original tautology one level
up: the collection being checked and the collection doing the checking
would again be the same one, and an account the tracker forgot would be
absent from both sides. An account-level witness needs an independent
observation of the same kind as this one, or it is worse than nothing --
it reads as coverage while proving that a set equals itself.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from ethereum.trace import OpEnd, OpException, OpStart, TraceEvent

SlotAccess = Tuple[int, int]
"""An accessed storage slot as `(account address, slot key)`, both ints."""

STORAGE_OPS = frozenset({"SLOAD", "SSTORE"})
"""Ops whose access the BAL records. Both take the key on top of the
stack, and both act on the frame's storage context, so `current_target`
is the account under `DELEGATECALL` and `CALLCODE` as well."""


@dataclass
class BalWitness:
    """The bracketing observations a run produced."""

    started: FrozenSet[SlotAccess] = frozenset()
    """Slots an access was *attempted* on. A superset of the truth: an op
    that failed its gas gate never reached the state."""

    ended: FrozenSet[SlotAccess] = frozenset()
    """Slots an access *completed* on. A subset of the truth: an op that
    accessed and then failed its state charge is missing here."""


class BalWitnessTracer:
    """Accumulate bracketing storage-access observations from the stream."""

    def __init__(self) -> None:
        self._started: Set[SlotAccess] = set()
        self._ended: Set[SlotAccess] = set()
        self._pending: Optional[SlotAccess] = None

    def __call__(self, evm: object, event: TraceEvent) -> None:
        """Fold one trace event into the accumulating witness."""
        if isinstance(event, OpStart):
            self._pending = None
            if event.op.name not in STORAGE_OPS:
                return
            access = self._access(evm)
            if access is not None:
                self._pending = access
                self._started.add(access)
        elif isinstance(event, OpEnd):
            if self._pending is not None:
                self._ended.add(self._pending)
            self._pending = None
        elif isinstance(event, OpException):
            self._pending = None

    @staticmethod
    def _access(evm: object) -> Optional[SlotAccess]:
        """The slot the op on the stack is about to touch, if readable."""
        stack = getattr(evm, "stack", None)
        target = getattr(evm, "current_target", None)
        if not stack or target is None:
            return None
        return (int.from_bytes(bytes(target), "big"), int(stack[-1]))

    def witness(self) -> BalWitness:
        """Return the accumulated observations."""
        return BalWitness(frozenset(self._started), frozenset(self._ended))


def bal_slots(blocks: List[Dict[str, Any]]) -> FrozenSet[SlotAccess]:
    """
    Every storage slot the serialized block access lists name.

    Reads and changes both count: the BAL splits a slot by whether it was
    written, and the question here is only whether it was accessed. An
    account may appear with every change list empty, so the walk is over
    entries rather than over non-empty lists -- emptiness is not absence.
    """
    slots: Set[SlotAccess] = set()
    for block in blocks:
        for entry in block.get("blockAccessList", []) or []:
            address = int(entry["address"], 16)
            for change in entry.get("storageChanges", []) or []:
                slots.add((address, int(change["slot"], 16)))
            for read in entry.get("storageReads", []) or []:
                slots.add((address, int(read, 16)))
    return frozenset(slots)


def bal_slots_from_model(bal: Any) -> FrozenSet[SlotAccess]:
    """
    Every storage slot a decoded `BlockAccessList` names.

    The model-side twin of `bal_slots`, for callers holding the decoded
    list rather than fixture JSON. Same rule: walk every account entry,
    not the non-empty lists, because an account can appear with all of
    them empty.
    """
    # `BlockAccessList` is a root model wrapping the account list, so
    # iterating the model itself yields pydantic fields, not entries.
    entries = getattr(bal, "root", bal) or []
    slots: Set[SlotAccess] = set()
    for entry in entries:
        address = int.from_bytes(bytes(entry.address), "big")
        for slot in entry.storage_changes or []:
            slots.add((address, int(slot.slot)))
        for read in entry.storage_reads or []:
            slots.add((address, int(read)))
    return frozenset(slots)


def bracket_width(witness: BalWitness) -> int:
    """
    How many slots the two observations disagree about.

    The gap is the accesses that began and did not complete -- ops that
    died between charging their access cost and settling their state gas.
    Worth recording per case rather than only passing or failing: a gap
    that widens across generator versions means more accesses are dying on
    the state charge, which is reach on the EIP-8037 surface and is
    otherwise invisible.
    """
    return len(witness.started - witness.ended)


@dataclass
class BalDisagreement:
    """One side of the sandwich the block access list broke."""

    kind: str
    slots: Tuple[SlotAccess, ...] = field(default_factory=tuple)

    def __str__(self) -> str:
        """Render the disagreement with a sample of the slots."""
        sample = ", ".join(
            f"{address:#042x}:{slot:#x}" for address, slot in self.slots[:3]
        )
        return f"{self.kind} ({len(self.slots)}): {sample}"


def check_bal_against_witness(
    witness: BalWitness, blocks: List[Dict[str, Any]]
) -> List[BalDisagreement]:
    """Check the relation against block access lists in fixture JSON."""
    return check_bal_relation(witness, bal_slots(blocks))


def check_bal_relation(
    witness: BalWitness, listed: FrozenSet[SlotAccess]
) -> List[BalDisagreement]:
    """
    Check `ended <= listed <= started`, reporting each side that broke.

    A slot whose access completed but that the list omits means the
    tracker dropped an access. A slot the list names that execution never
    attempted means it invented one. Neither is visible to a cross-client
    comparison, because a client matching the reference reproduces both.
    """
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
