"""
Which reason put each address in the block access list, observed at runtime.

The BAL reach space is derived statically: a reason is the first function
outside the state tracker on a path to a recorder. This observer applies
the same rule to the running spec. It wraps every binding of the tracker's
recorder functions for the duration of one fill, and on each call walks up
the Python stack past the tracker to the first frame outside it. That frame
is the reason, and whether its name is in the derived set is the check:
a name outside the set is a caller the static walk missed, reported rather
than folded into whichever derived reason sits further up the stack.

Outcome is a join, not something the call site can know. An entry made
inside an EVM frame takes the outcome of that frame, resolved when the
frame's `EvmStop` or `OpException` arrives. An entry made outside any
frame -- a fork phase such as `update_sender_state` or
`disburse_gas_fees` -- takes its transaction's outcome, keyed on the
transaction's own state object. The transaction can close before its
phase entries arrive (`TransactionEnd` is traced before the fees are
disbursed), so closed transactions keep their outcome for late entries.

Nothing here touches `src/ethereum`: the wrapping is undone when the fill
returns.
"""

import importlib
import pkgutil
import sys
from collections import Counter, defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterator,
    List,
    Mapping,
    Optional,
    Set,
    Tuple,
)

from ethereum.state import EMPTY_CODE_HASH
from ethereum.trace import EvmStop, OpException, TraceEvent, TransactionEnd

TRACKER_MODULE = "state_tracker"

ACCOUNT_FIELDS: Mapping[str, str] = {
    "balance_change": "balance",
    "nonce_change": "nonce",
    "code_change": "code_hash",
}
"""Which account field each account-write entry kind diffs. Declared
because the builder names kinds and the account names fields; a kind the
fork adds without a row here raises in `BalReachObserver` rather than
being dropped."""


def group_outcome(halt: Optional[str]) -> str:
    """
    The BAL outcome for a frame or transaction that ended with `halt`.

    `None` is success. The grouping is the one the reach space enumerates,
    so the observer and the space cannot disagree about what an outcome is.
    """
    if halt is None:
        return "success"
    if halt == "Revert":
        return "revert"
    if "OutOfGas" in halt:
        return "out_of_gas"
    return "exceptional_halt"


class _Tally:
    """
    Stand in for one tracker collection during one call, counting adds.

    Forwards everything to the real set or dict, which may be shared with
    the block state, so the fill sees exactly what it would have. It only
    counts the calls that put something into the collection, because
    whether a conditional recorder recorded is whether that statement ran:
    checking what the collection holds afterwards cannot tell, since a
    written slot was almost always read first and re-adding it to a set
    changes nothing.
    """

    def __init__(self, target: Any) -> None:
        self.target = target
        self.added = 0

    def add(self, item: Any) -> None:
        self.added += 1
        self.target.add(item)

    def __setitem__(self, key: Any, value: Any) -> None:
        self.added += 1
        self.target[key] = value

    def __getitem__(self, key: Any) -> Any:
        return self.target[key]

    def __delitem__(self, key: Any) -> None:
        del self.target[key]

    def __contains__(self, key: Any) -> bool:
        return key in self.target

    def __iter__(self) -> Iterator[Any]:
        return iter(self.target)

    def __len__(self) -> int:
        return len(self.target)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.target, name)


@dataclass(frozen=True)
class BalReachSpec:
    """What the observer needs from the derivation, handed in by value."""

    package: str
    """The fork package, e.g. `ethereum.forks.amsterdam`."""
    reasons: FrozenSet[str]
    """Derived reason names, fork prefix stripped."""
    recorders: Mapping[str, FrozenSet[str]]
    """Tracker function name to the collections it records into."""
    fanout: Mapping[str, FrozenSet[str]]
    """Tracker collection kind to the builder's entry kinds."""
    conditional: FrozenSet[str] = frozenset()
    """Recorders whose every recording statement is behind a branch, so a
    call can record nothing; for these the observer counts what the call
    actually added rather than trusting the call."""
    attributes: Mapping[str, str] = field(default_factory=dict)
    """Tracker collection kind to its attribute on the transaction state,
    e.g. `storage_read -> storage_reads`."""


@dataclass(frozen=True)
class BalObservation:
    """What one fill showed about the BAL reach space."""

    cells: FrozenSet[Tuple[str, str, str]]
    aliases: FrozenSet[Tuple[str, str]]
    unattributed: Mapping[str, int]
    """`caller -> calls` for recorder calls whose first frame outside the
    tracker is not a derived reason. Non-empty means the static walk
    missed a caller."""
    closed_by_state: int
    """Entries whose frame the trace never closed, settled from the
    frame's own `evm.error` instead. A frame that executes no code -- a
    call or create into an account with none -- emits no `EvmStop` or
    `OpException`, so the trace cannot close it, but the spec still
    records how it ended. Counted apart so the fallback stays visible."""
    unresolved: int
    """Entries whose frame neither the trace nor the frame object could
    say how it ended. Not turned into cells: an outcome nobody saw is not
    claimed."""
    calls: int
    bindings: FrozenSet[Tuple[str, str]]
    """`(module, name)` of every recorder binding that was wrapped."""


class BalReachObserver:
    """Wrap the recorders during a fill and join entries to outcomes."""

    def __init__(self, spec: BalReachSpec) -> None:
        self.spec = spec
        self._prefix = spec.package + "."
        self._tracker = self._prefix + TRACKER_MODULE
        for kinds in spec.fanout.values():
            unmapped = {
                k
                for k in kinds
                if k.endswith("_change") and k not in ACCOUNT_FIELDS
            }
            if unmapped:
                raise LookupError(
                    f"account entry kinds with no field to diff: "
                    f"{sorted(unmapped)}; add them to ACCOUNT_FIELDS"
                )
        self._pending_frames: Dict[int, Tuple[Any, List[Tuple]]] = {}
        self._pending_txs: Dict[int, Tuple[Any, List[Tuple]]] = {}
        self._closed_txs: Dict[int, Tuple[Any, str]] = {}
        self._cells: Set[Tuple[str, str, str]] = set()
        self._reasons_at: Dict[int, Dict[Any, Set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )
        self._unattributed: Counter = Counter()
        self._unresolved = 0
        self._closed_by_state = 0
        self._calls = 0
        self._bindings: FrozenSet[Tuple[str, str]] = frozenset()
        self._originals: Dict[str, Callable] = {}

    def _modules(self) -> List[Any]:
        root = importlib.import_module(self.spec.package)
        return [root] + [
            importlib.import_module(m.name)
            for m in pkgutil.walk_packages(root.__path__, self._prefix)
        ]

    @contextmanager
    def installed(self) -> Iterator["BalReachObserver"]:
        """
        Wrap every binding of every recorder, by identity, then restore.

        By identity rather than by name: the recorders are imported by
        name into the modules that call them, so wrapping the defining
        module alone saw three quarters of the calls, and an aliased
        import would be missed by a name check.
        """
        tracker = importlib.import_module(self._tracker)
        self._originals = {
            name: getattr(tracker, name) for name in self.spec.recorders
        }
        by_identity = {id(fn): name for name, fn in self._originals.items()}
        wrappers = {
            name: self._wrap(name, fn) for name, fn in self._originals.items()
        }
        patched: List[Tuple[Any, str, Callable]] = []
        for module in self._modules():
            for attribute, value in list(vars(module).items()):
                name = by_identity.get(id(value))
                if name is not None and value is self._originals[name]:
                    setattr(module, attribute, wrappers[name])
                    patched.append((module, attribute, value))
        self._bindings = frozenset(
            (module.__name__[len(self._prefix) :], attribute)
            for module, attribute, _ in patched
        )
        try:
            yield self
        finally:
            for module, attribute, value in patched:
                setattr(module, attribute, value)

    def _wrap(self, name: str, original: Callable) -> Callable:
        def hooked(*args: Any, **kwargs: Any) -> Any:
            result, kinds = self.observe_call(name, original, args, kwargs)
            self._record(sys._getframe(1), args[0], args[1], kinds)
            return result

        hooked.__name__ = f"bal_reach_{name}"
        return hooked

    def observe_call(
        self,
        name: str,
        original: Callable,
        args: Tuple[Any, ...],
        kwargs: Mapping[str, Any],
    ) -> Tuple[Any, Set[str]]:
        """
        Run one recorder call; return its result and what it recorded.

        A recorder whose recording is entirely behind a branch is judged
        by the collection, not the call: `destroy_storage` with no pending
        writes records nothing, and crediting the call is how fee payment
        came to look like a storage read.
        """
        collections = self.spec.recorders[name]
        tx_state, address = args[0], args[1]
        tallies: Dict[str, _Tally] = {}
        if name in self.spec.conditional:
            for collection in collections:
                attribute = self.spec.attributes[collection]
                tallies[collection] = _Tally(getattr(tx_state, attribute))
        kinds: Set[str] = set()
        for collection in collections:
            if collection == "account_write":
                kinds |= self._account_kinds(tx_state, address, args[2])
            else:
                kinds |= self.spec.fanout.get(
                    collection, frozenset({collection})
                )
        if not tallies:
            return original(*args, **kwargs), kinds
        for collection, tally in tallies.items():
            setattr(tx_state, self.spec.attributes[collection], tally)
        try:
            result = original(*args, **kwargs)
        finally:
            for collection, tally in tallies.items():
                setattr(
                    tx_state, self.spec.attributes[collection], tally.target
                )
        recorded = {c for c, tally in tallies.items() if tally.added}
        kinds = {
            kind
            for collection in recorded
            for kind in self.spec.fanout.get(
                collection, frozenset({collection})
            )
        }
        return result, kinds

    def _account_kinds(
        self, tx_state: Any, address: Any, new: Any
    ) -> Set[str]:
        """
        Which account fields this write changes.

        The prior value comes from the spec's own lookup, with the read it
        records undone when it was not already there: a side-effecting
        read would add a touched entry the fill never made and change the
        list being observed.
        """
        getter = self._originals.get("get_account_optional")
        if getter is None:
            return set(ACCOUNT_FIELDS)
        reads = tx_state.account_reads
        already = address in reads
        before = getter(tx_state, address)
        if not already:
            reads.discard(address)
        changed = set()
        for kind, field_name in ACCOUNT_FIELDS.items():
            empty = EMPTY_CODE_HASH if field_name == "code_hash" else 0
            old = getattr(before, field_name) if before else empty
            now = getattr(new, field_name) if new else empty
            if old != now:
                changed.add(kind)
        return changed

    def _locate(self, frame: Any) -> Tuple[Optional[str], Optional[str], Any]:
        """
        The first frame outside the tracker, whether it is a derived
        reason, and the EVM frame the call was made in (if any).

        Returns `(reason, caller, evm)`: `reason` is set when the caller
        is derived, `caller` is its name either way.
        """
        evm = None
        own = __name__
        current = frame
        while current is not None:
            module = current.f_globals.get("__name__", "")
            if module in (self._tracker, own):
                current = current.f_back
                continue
            code = current.f_code
            if evm is None and "evm" in code.co_varnames:
                candidate = current.f_locals.get("evm")
                if type(candidate).__name__ == "Evm":
                    evm = candidate
            if module.startswith(self._prefix):
                caller = f"{module[len(self._prefix) :]}.{code.co_name}"
            else:
                caller = f"{module}.{code.co_name}"
            if caller in self.spec.reasons:
                return caller, caller, evm
            return None, caller, evm
        return None, "<no caller>", evm

    def _record(
        self, frame: Any, tx_state: Any, address: Any, kinds: Set[str]
    ) -> None:
        self._calls += 1
        reason, caller, evm = self._locate(frame)
        if reason is None:
            self._unattributed[caller] += 1
            return
        self._reasons_at[id(tx_state)][address].add(reason)
        entries = [(reason, kind) for kind in kinds]
        if not entries:
            return
        if evm is not None:
            holder = self._pending_frames.setdefault(id(evm), (evm, []))
            holder[1].extend(entries)
            return
        closed = self._closed_txs.get(id(tx_state))
        if closed is not None:
            self._settle(entries, closed[1])
            return
        holder = self._pending_txs.setdefault(id(tx_state), (tx_state, []))
        holder[1].extend(entries)

    def _settle(self, entries: List[Tuple], outcome: str) -> None:
        for reason, kind in entries:
            self._cells.add((reason, kind, outcome))

    def __call__(self, evm: Any, event: TraceEvent) -> None:
        """Resolve outcomes as frames and transactions end."""
        if isinstance(event, EvmStop):
            self._close_frame(evm, None)
        elif isinstance(event, OpException):
            self._close_frame(evm, type(event.error).__name__)
        elif isinstance(event, TransactionEnd):
            tx_env = getattr(evm, "tx_env", None)
            state = getattr(tx_env, "state", None)
            if state is None:
                return
            halt = None if event.error is None else type(event.error).__name__
            outcome = group_outcome(halt)
            self._closed_txs[id(state)] = (state, outcome)
            pending = self._pending_txs.pop(id(state), None)
            if pending is not None:
                self._settle(pending[1], outcome)

    def _close_frame(self, evm: Any, halt: Optional[str]) -> None:
        pending = self._pending_frames.pop(id(evm), None)
        if pending is not None:
            self._settle(pending[1], group_outcome(halt))

    def observation(self) -> BalObservation:
        """
        Everything the fill showed, with the leftovers accounted for.

        Frame entries the trace never closed settle from the frame's own
        `evm.error`, or are counted and dropped if even that is missing.
        Phase entries whose transaction never ended belong to the
        block-level phases (withdrawals), which have no execution to fail,
        so they settle as success.
        """
        missing = object()
        for evm, entries in self._pending_frames.values():
            error = getattr(evm, "error", missing)
            if error is missing:
                self._unresolved += len(entries)
                continue
            halt = None if error is None else type(error).__name__
            self._settle(entries, group_outcome(halt))
            self._closed_by_state += len(entries)
        self._pending_frames.clear()
        for _, entries in self._pending_txs.values():
            self._settle(entries, "success")
        self._pending_txs.clear()
        aliases: Set[Tuple[str, str]] = set()
        for by_address in self._reasons_at.values():
            for reasons in by_address.values():
                names = sorted(reasons)
                for index, first in enumerate(names):
                    for second in names[index + 1 :]:
                        aliases.add((first, second))
        return BalObservation(
            cells=frozenset(self._cells),
            aliases=frozenset(aliases),
            unattributed=dict(self._unattributed),
            closed_by_state=self._closed_by_state,
            unresolved=self._unresolved,
            calls=self._calls,
            bindings=self._bindings,
        )
