"""
The block access list's reach space, derived from the fork itself.

An address or slot enters the BAL for a *reason* (a destination access, a
withdrawal recipient, a coinbase tip) and enters as a *kind* (touched-only,
balance, nonce, code, storage read, storage change), under an *outcome*,
and sometimes *aliased* with another reason on the same address at the same
block access index. Those four axes are the cross-product a campaign is
measured against.

Every axis is derived from the fork's own source, the way halt kinds come
from its exception classes. A hand-written list is wrong in both
directions: it invents rows nobody can reach and omits the ones a new fork
adds. Measured against the human enumeration this replaces, the derivation
found four reasons it had missed and one phantom it had invented.
"""

import ast
import importlib
import inspect
import pkgutil
from collections import defaultdict
from typing import (
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Set,
    Tuple,
)

from execution_testing.forks import Fork

Reason = str
"""A qualified function name with the fork package prefix stripped, e.g.
`vm.instructions.system.selfdestruct`. Never a friendly label: a label is
a second name to keep in sync, and the identity has to be the thing the
fork actually calls."""

Kind = str
"""What the entry records, from the BAL builder's own `add_*` functions."""

Outcome = str
"""How the frame that caused the entry ended."""

Cell = Tuple[Reason, Kind, Outcome]
AliasCell = Tuple[Reason, Reason]

TRACKER_MODULE = "state_tracker"
"""Where the fork keeps the four collections the BAL is built from."""

BAL_MODULE = "block_access_lists"

_COLLECTIONS: Mapping[str, Kind] = {
    "account_reads": "touched",
    "storage_reads": "storage_read",
    "account_writes": "account_write",
    "storage_writes": "storage_write",
}
"""The tracker collections a recorder writes into, and the access each
stands for. These are the tracker's own field names, so a fork renaming
one fails loudly in `recorders` rather than quietly emptying the axis."""

PLUMBING: FrozenSet[str] = frozenset(
    {
        "copy_tx_state",
        "restore_tx_state",
        "incorporate_tx_into_block",
        "extract_block_diff",
    }
)
"""Tracker functions that move whole collections between states rather
than recording an access. They touch every collection, so left in they
would make every caller a reason for every kind."""


def _fork_package(fork: Fork) -> str:
    return f"ethereum.forks.{fork.name().lower()}"


def _module_asts(package: str) -> Dict[str, ast.Module]:
    """Every module of the fork package, parsed, keyed by short name."""
    root = importlib.import_module(package)
    names = [package] + [
        m.name for m in pkgutil.walk_packages(root.__path__, package + ".")
    ]
    trees: Dict[str, ast.Module] = {}
    for name in names:
        try:
            source = inspect.getsource(importlib.import_module(name))
        except (OSError, TypeError, ImportError):
            continue
        short = name[len(package) :].lstrip(".") or "__init__"
        trees[short] = ast.parse(source)
    return trees


def _records(fn: ast.FunctionDef) -> Set[Kind]:
    """
    Which collections this function actually writes into.

    Only `.add(...)` calls and subscript assignments record; a function
    that merely reads `tx_state.account_writes` to answer a query is not a
    recorder, and counting those gave `get_storage` a storage write it
    never performs.
    """
    kinds: Set[Kind] = set()
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add"
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr in _COLLECTIONS
        ):
            kinds.add(_COLLECTIONS[node.func.value.attr])
        if isinstance(node, ast.Assign):
            for target in node.targets:
                while isinstance(target, ast.Subscript):
                    target = target.value
                if (
                    isinstance(target, ast.Attribute)
                    and target.attr in _COLLECTIONS
                ):
                    kinds.add(_COLLECTIONS[target.attr])
    return kinds


def _functions(
    trees: Mapping[str, ast.Module],
) -> Dict[str, Tuple[str, ast.FunctionDef]]:
    """Every function in the fork, keyed by its qualified name."""
    found: Dict[str, Tuple[str, ast.FunctionDef]] = {}
    for module, tree in trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                found[f"{module}.{node.name}"] = (module, node)
    return found


def _callers(
    functions: Mapping[str, Tuple[str, ast.FunctionDef]],
) -> Dict[str, Set[str]]:
    """
    Reverse call graph over plain function calls, keyed by bare name.

    Attribute calls are deliberately excluded. The tracker's functions are
    imported by name and called as `get_account(tx_state, address)`, while
    `pre_state.get_account_optional(address)` is a different object's
    method that happens to share a name -- counting it made the BAL
    builder's own pre-state lookups look like reasons an address enters
    the list it is building.
    """
    graph: Dict[str, Set[str]] = defaultdict(set)
    for qualified, (_module, node) in functions.items():
        for inner in ast.walk(node):
            if isinstance(inner, ast.Call) and isinstance(
                inner.func, ast.Name
            ):
                graph[inner.func.id].add(qualified)
    return graph


def _kind_fanout(
    trees: Mapping[str, ast.Module],
) -> Dict[Kind, FrozenSet[Kind]]:
    """
    How a tracker collection becomes the builder's own entry kinds.

    The builder consumes each collection in its own loop and calls the
    `add_*` functions for what it finds, so one `account_write` fans out
    into the balance, nonce and code changes that `update_builder_from_tx`
    diffs. Read off those loops rather than stated, so a fork adding a
    fourth account field to the list widens the axis on its own.
    """
    tree = trees.get(BAL_MODULE)
    if tree is None:
        raise LookupError(f"no {BAL_MODULE} module")
    fanout: Dict[Kind, Set[Kind]] = defaultdict(set)
    for loop in [n for n in ast.walk(tree) if isinstance(n, ast.For)]:
        collections = {
            node.attr
            for node in ast.walk(loop.iter)
            if isinstance(node, ast.Attribute) and node.attr in _COLLECTIONS
        }
        if not collections:
            continue
        added = {
            node.func.id[len("add_") :]
            for node in ast.walk(loop)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id.startswith("add_")
        }
        for collection in collections:
            fanout[_COLLECTIONS[collection]] |= added
    return {source: frozenset(kinds) for source, kinds in fanout.items()}


def recorders(fork: Fork) -> Dict[str, FrozenSet[Kind]]:
    """
    The tracker functions that record an access, and what each records.

    Raises when no collection is found at all, which means the tracker's
    field names moved and every axis below would silently be empty.
    """
    package = _fork_package(fork)
    trees = _module_asts(package)
    if TRACKER_MODULE not in trees:
        raise LookupError(
            f"{package}: no {TRACKER_MODULE} module; the BAL reach space "
            "cannot be derived and must not be reported as empty"
        )
    found: Dict[str, FrozenSet[Kind]] = {}
    for node in ast.walk(trees[TRACKER_MODULE]):
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name in PLUMBING:
            continue
        kinds = _records(node)
        if kinds:
            found[node.name] = frozenset(kinds)
    if not found:
        raise LookupError(
            f"{package}.{TRACKER_MODULE}: no function records into any of "
            f"{sorted(_COLLECTIONS)}; the collections were renamed"
        )
    return found


def entry_kinds(fork: Fork) -> FrozenSet[Kind]:
    """
    What a BAL entry can record, in the builder's own vocabulary.

    Taken from the loops that consume each tracker collection rather than
    from the `add_*` functions the module happens to define, so a helper
    the builder defines but never calls on a collection cannot invent a
    kind nothing reaches.
    """
    fanout = _kind_fanout(_module_asts(_fork_package(fork)))
    return frozenset().union(*fanout.values())


def entry_reasons(fork: Fork) -> Dict[Reason, FrozenSet[Kind]]:
    """
    Why an address or slot enters the BAL, and what it enters as.

    A reason is any function that reaches a recorder without passing
    through another reason: propagation runs freely through the tracker's
    own helpers and stops at the first function outside it. An allow-list
    of "interesting" modules is what a hand enumeration looks like once it
    has been moved into the tool, and it silently dropped delegate
    resolution the first time this was written.
    """
    package = _fork_package(fork)
    trees = _module_asts(package)
    functions = _functions(trees)
    callers = _callers(functions)
    seeds = recorders(fork)

    reasons: Dict[Reason, Set[Kind]] = defaultdict(set)
    frontier: List[Tuple[str, FrozenSet[Kind]]] = [
        (f"{TRACKER_MODULE}.{name}", kinds) for name, kinds in seeds.items()
    ]
    seen: Set[Tuple[str, FrozenSet[Kind]]] = set(frontier)
    while frontier:
        qualified, kinds = frontier.pop()
        bare = qualified.rsplit(".", 1)[-1]
        for caller in callers.get(bare, ()):
            module, _node = functions[caller]
            if caller.rsplit(".", 1)[-1] in PLUMBING:
                continue
            if module == TRACKER_MODULE:
                # Still inside the tracker: keep walking outward, but the
                # tracker's own helpers are never themselves reasons.
                step = (caller, kinds)
                if step not in seen:
                    seen.add(step)
                    frontier.append(step)
                continue
            reasons[caller] |= kinds
    return {reason: frozenset(kinds) for reason, kinds in reasons.items()}


def outcomes(fork: Fork) -> FrozenSet[Outcome]:
    """
    How the frame that caused an entry ended.

    Grouped from the fork's exception classes rather than listed, so a new
    exception lands in `exceptional_halt` instead of going missing: the
    BAL cares whether the frame reverted, ran out of gas, or halted, not
    which of a dozen halts it was.
    """
    package = f"{_fork_package(fork)}.vm.exceptions"
    module = importlib.import_module(package)
    names = {
        name
        for name, cls in inspect.getmembers(module, inspect.isclass)
        if cls.__module__ == module.__name__ and name != "ExceptionalHalt"
    }
    grouped = {"success"}
    for name in names:
        if name == "Revert":
            grouped.add("revert")
        elif "OutOfGas" in name:
            grouped.add("out_of_gas")
        else:
            grouped.add("exceptional_halt")
    return frozenset(grouped)


def bal_reach_space(
    fork: Fork,
) -> Tuple[FrozenSet[Cell], FrozenSet[AliasCell]]:
    """
    The two cell families a campaign is measured against.

    `(reason, kind, outcome)` for how an entry arises, and unordered
    `(reason, reason)` pairs for aliasing -- the same address entered for
    two reasons at one block access index. Aliasing is a family of its own
    rather than a fourth dimension on the first, which would multiply the
    space by the number of pairs for no extra information.

    A reason is paired only with the kinds it can actually cause, which is
    what keeps most of the naive product from ever being enumerated.
    """
    reasons = entry_reasons(fork)
    fanout = _kind_fanout(_module_asts(_fork_package(fork)))
    ends = outcomes(fork)
    cells = {
        (reason, entry, outcome)
        for reason, kinds in reasons.items()
        for kind in kinds
        for entry in fanout.get(kind, frozenset({kind}))
        for outcome in ends
    }
    names = sorted(reasons)
    pairs = {
        (a, b) for index, a in enumerate(names) for b in names[index + 1 :]
    }
    return frozenset(cells), frozenset(pairs)


def alias_cells(
    reasons_by_address: Mapping[object, Iterable[Reason]],
) -> FrozenSet[AliasCell]:
    """
    The aliasing cells one case reached.

    Given the reasons that resolved to each address at a single block
    access index, every unordered pair of distinct reasons on one address
    is a cell. `sender == coinbase` falls out as the pair of whichever
    functions actually touched it, without anyone having named that case.
    """
    reached: Set[AliasCell] = set()
    for entered in reasons_by_address.values():
        names = sorted(set(entered))
        for index, first in enumerate(names):
            for second in names[index + 1 :]:
                reached.add((first, second))
    return frozenset(reached)


def unreached(
    fork: Fork,
    cells_seen: Iterable[Cell],
    aliases_seen: Iterable[AliasCell] = (),
) -> Tuple[List[Cell], List[AliasCell]]:
    """The derived space minus what a run actually reached."""
    cells, pairs = bal_reach_space(fork)
    return (
        sorted(cells - set(cells_seen)),
        sorted(pairs - set(aliases_seen)),
    )
