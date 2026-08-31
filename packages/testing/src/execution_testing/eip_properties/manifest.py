"""
Derive a fork's change manifest from its own typed surface.

A fork object is already a machine-readable description of the protocol: the
``BaseFork`` predicate surface (scalars, the ``GasCosts`` dataclass, opcode and
system-contract sets) plus the calculator methods each EIP mixin overrides.
Diffing two adjacent forks therefore yields, by construction, the set of things
the newer fork changed — the raw material for deciding what to test.

This module is the "consumption" layer the repo lacked: rather than a human
copying a checklist per EIP, the required-test surface is *derived* from the
fork the EIP is implemented in. Each change is attributed to the EIP mixin that
introduced it, classified by kind, and mapped to a property archetype and the
checklist section(s) it implies.

Three detectors, matching the three ways a change is expressed:

- **value-diff** — scalars, ``GasCosts`` fields, opcode/system-contract/
  precompile sets. Complete over everything parameterized by value.
- **override-diff** — calculator/formula methods a new EIP mixin overrides
  (pricing or state-transition logic a value cannot capture).
- source-diff — pure logic behind no fork method; out of scope here, left to
  the agent reading the spec diff.
"""

import dataclasses
import logging
import re
import warnings
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Dict, List, Optional, Set, Tuple, Type

from execution_testing.forks import Fork, get_forks

logger = logging.getLogger(__name__)

# Scalar predicates that describe the environment, not the protocol.
_METADATA = {
    "name",
    "ruleset_name",
    "solc_name",
    "transition_tool_name",
    "is_deployed",
    "blockchain_test_network_name",
}

# Calculator/formula methods worth surfacing from the override-diff. A change
# here is a pricing or state-transition logic change a value-diff cannot see.
_FORMULA_HINTS = ("calculator", "_calculate_", "_gas", "_map")


class ChangeKind(StrEnum):
    """How a fork-to-fork change is shaped."""

    BOUND_ADDED = "bound_added"  # None -> N: a quantity gains a limit
    LIMIT_CHANGED = "limit_changed"  # M -> N: an existing limit moves
    GAS_CONSTANT = "gas_constant"  # a GasCosts field changed
    OPCODE_ADDED = "opcode_added"
    OPCODE_REMOVED = "opcode_removed"
    SYSTEM_CONTRACT_ADDED = "system_contract_added"
    PRECOMPILE_ADDED = "precompile_added"
    PRECOMPILE_REMOVED = "precompile_removed"
    FEATURE_ENABLED = "feature_enabled"  # False -> True
    FEATURE_DISABLED = "feature_disabled"  # True -> False
    FORMULA_CHANGED = "formula_changed"  # override-diff
    VERSION_BUMP = "version_bump"  # engine API version
    VALUE_CHANGED = "value_changed"  # fallback


# ChangeKind -> checklist section(s) it implies (the archetype layer). Section
# names match the headings in the EIP testing checklist template.
_CHECKLIST_SECTIONS: Dict[ChangeKind, List[str]] = {
    ChangeKind.BOUND_ADDED: ["New Transaction-Validity Constraint"],
    ChangeKind.LIMIT_CHANGED: ["Modified Transaction-Validity Constraint"],
    ChangeKind.GAS_CONSTANT: ["Gas Cost Changes"],
    ChangeKind.OPCODE_ADDED: ["New Opcode"],
    ChangeKind.OPCODE_REMOVED: ["New Opcode"],
    ChangeKind.SYSTEM_CONTRACT_ADDED: ["New System Contract"],
    ChangeKind.PRECOMPILE_ADDED: ["New Precompile"],
    ChangeKind.PRECOMPILE_REMOVED: ["Removed Precompile"],
    ChangeKind.FEATURE_ENABLED: ["New Block Header Field"],
    ChangeKind.FEATURE_DISABLED: ["New Block Header Field"],
    ChangeKind.FORMULA_CHANGED: ["Gas Cost Changes"],
    ChangeKind.VERSION_BUMP: [],
    ChangeKind.VALUE_CHANGED: [],
}


@dataclass
class Change:
    """A single fork-to-fork change, attributed and classified."""

    name: str
    kind: ChangeKind
    before: Any
    after: Any
    detector: str  # "value" | "override"
    eips: List[str] = field(default_factory=list)

    @property
    def checklist_sections(self) -> List[str]:
        """Checklist section(s) this change implies."""
        return _CHECKLIST_SECTIONS.get(self.kind, [])

    def __str__(self) -> str:
        """Render the change as a one-line summary."""
        eips = ",".join(self.eips) or "?"
        return (
            f"[{eips}] {self.name}: {self.before} -> {self.after} "
            f"({self.kind})"
        )


def _eip_mixins(fork: Fork) -> List[Type]:
    return [c for c in fork.__mro__ if re.match(r"^EIP\d+$", c.__name__)]


def _new_mixins(fork_a: Fork, fork_b: Fork) -> List[Type]:
    """EIP mixins present in ``fork_b`` but not ``fork_a``."""
    old = {c.__name__ for c in _eip_mixins(fork_a)}
    return [c for c in _eip_mixins(fork_b) if c.__name__ not in old]


def _definers(name: str, mixins: List[Type]) -> List[str]:
    """Names of the ``mixins`` that define ``name`` in their own body."""
    return [c.__name__ for c in mixins if name in c.__dict__]


def _scalars(fork: Fork) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for name in dir(fork):
        if name.startswith("_") or name in _METADATA:
            continue
        attr = getattr(type(fork), name, None)
        if not isinstance(attr, classmethod) and not callable(
            getattr(fork, name, None)
        ):
            continue
        try:
            value = getattr(fork, name)()
        except Exception as exc:  # noqa: BLE001
            # Zero-argument probing legitimately trips methods that need
            # arguments or exist only on EIP mixins.
            logger.debug("%s.%s() raised %r; skipped", fork.name(), name, exc)
            continue
        if isinstance(value, (int, bool)) or value is None:
            out[name] = value
    return out


def _gas_costs(fork: Fork) -> Dict[str, Any]:
    try:
        costs = fork.gas_costs()
    except Exception:
        return {}
    return {f.name: getattr(costs, f.name) for f in dataclasses.fields(costs)}


def _string_set(fork: Fork, method: str) -> Set[str]:
    try:
        return {str(x) for x in getattr(fork, method)()}
    except Exception as exc:  # noqa: BLE001
        warnings.warn(
            f"{fork.name()}.{method}() raised {exc!r}; the manifest will "
            "report every entry as removed",
            stacklevel=2,
        )
        return set()


def _opcodes(fork: Fork) -> Set[str]:
    try:
        return {
            o.hex() if hasattr(o, "hex") else str(o)
            for o in fork.valid_opcodes()
        }
    except Exception as exc:  # noqa: BLE001
        warnings.warn(
            f"{fork.name()}.valid_opcodes() raised {exc!r}; the manifest "
            "will report every opcode as removed",
            stacklevel=2,
        )
        return set()


def _classify_scalar(before: Any, after: Any, name: str) -> ChangeKind:
    if "version" in name:
        return ChangeKind.VERSION_BUMP
    if isinstance(before, bool) or isinstance(after, bool):
        return (
            ChangeKind.FEATURE_ENABLED
            if after
            else ChangeKind.FEATURE_DISABLED
        )
    if before is None:
        return ChangeKind.BOUND_ADDED
    if after is None:
        return ChangeKind.VALUE_CHANGED
    return ChangeKind.LIMIT_CHANGED


def diff_forks(fork_a: Fork, fork_b: Fork) -> List[Change]:
    """Return the manifest of changes from ``fork_a`` to ``fork_b``."""
    new_mixins = _new_mixins(fork_a, fork_b)
    changes: List[Change] = []

    def add(
        name: str,
        kind: ChangeKind,
        before: Any,
        after: Any,
        detector: str,
        producer: str,
    ) -> None:
        changes.append(
            Change(
                name=name,
                kind=kind,
                before=before,
                after=after,
                detector=detector,
                eips=_definers(producer, new_mixins),
            )
        )

    # 1. value-diff: scalar predicates
    sa, sb = _scalars(fork_a), _scalars(fork_b)
    for name in sorted(set(sa) | set(sb)):
        if sa.get(name) != sb.get(name):
            add(
                name,
                _classify_scalar(sa.get(name), sb.get(name), name),
                sa.get(name),
                sb.get(name),
                "value",
                name,
            )

    # 2. value-diff: GasCosts fields
    ga, gb = _gas_costs(fork_a), _gas_costs(fork_b)
    for name in sorted(set(ga) | set(gb)):
        if ga.get(name) != gb.get(name):
            add(
                f"gas_costs.{name}",
                ChangeKind.GAS_CONSTANT,
                ga.get(name),
                gb.get(name),
                "value",
                "gas_costs",
            )

    # 3. value-diff: opcode / system-contract / precompile sets
    oa, ob = _opcodes(fork_a), _opcodes(fork_b)
    for op in sorted(ob - oa):
        add(
            f"opcode:{op}",
            ChangeKind.OPCODE_ADDED,
            None,
            op,
            "value",
            "valid_opcodes",
        )
    for op in sorted(oa - ob):
        add(
            f"opcode:{op}",
            ChangeKind.OPCODE_REMOVED,
            op,
            None,
            "value",
            "valid_opcodes",
        )

    for method, added, removed in (
        ("system_contracts", ChangeKind.SYSTEM_CONTRACT_ADDED, None),
        (
            "precompiles",
            ChangeKind.PRECOMPILE_ADDED,
            ChangeKind.PRECOMPILE_REMOVED,
        ),
    ):
        a, b = _string_set(fork_a, method), _string_set(fork_b, method)
        for x in sorted(b - a):
            add(f"{method}:{x}", added, None, x, "value", method)
        if removed is not None:
            for x in sorted(a - b):
                add(f"{method}:{x}", removed, x, None, "value", method)

    # 4. override-diff: formula / calculator methods new mixins introduce
    seen = {c.name for c in changes}
    for mixin in new_mixins:
        for attr in mixin.__dict__:
            if attr.startswith("__") or attr in seen:
                continue
            if any(h in attr for h in _FORMULA_HINTS):
                changes.append(
                    Change(
                        name=attr,
                        kind=ChangeKind.FORMULA_CHANGED,
                        before="(previous formula)",
                        after="(overridden)",
                        detector="override",
                        eips=_definers(attr, new_mixins),
                    )
                )
                seen.add(attr)

    return changes


def changes_of_kind(
    fork_a: Fork, fork_b: Fork, kind: ChangeKind
) -> List[Change]:
    """
    Changes of a single kind from ``fork_a`` to ``fork_b``.

    This is the covariant source an archetype test parametrizes over: the
    fork diff supplies the cases, so one test body covers every fork.
    """
    return [c for c in diff_forks(fork_a, fork_b) if c.kind == kind]


def _non_transition_forks() -> List[Fork]:
    return [f for f in get_forks() if not f.is_transition_fork]


def fork_introducing_eip(eip: int) -> Optional[Fork]:
    """
    The fork whose mixins first include ``EIP<eip>``, or ``None``.

    An EIP mixin (class named ``EIP<n>``) enters the MRO in exactly one
    fork, so this is where its changes live.
    """
    tag = f"EIP{eip}"
    for fork in _non_transition_forks():
        if any(cls.__name__ == tag for cls in _eip_mixins(fork)):
            return fork
    return None


def changes_for_eip(eip: int) -> List[Change]:
    """
    Every manifest change attributed to a single EIP, by number.

    The manifest is fork-pair-keyed; this is the by-EIP-number view a skill
    starts from. It walks the adjacent non-transition fork pairs and keeps
    the changes attributed to ``EIP<eip>`` -- which, since the mixin is new
    in one fork, all come from that one transition.

    Attribution is manifest-granular, and coarse for shared methods: a
    change to ``gas_costs``/``valid_opcodes`` is attributed to *every* EIP
    in the fork that overrides that method, so for a fork that ships several
    EIPs at once (e.g. Cancun) this over-returns -- the result is a superset
    of what ``eip`` strictly owns. That is a property of the override-diff
    detector, not this query; a consumer should treat the changes as "the
    changed surface this EIP participated in," not "changes unique to it."
    """
    tag = f"EIP{eip}"
    forks = _non_transition_forks()
    result: List[Change] = []
    for parent, child in zip(forks, forks[1:], strict=False):
        result.extend(c for c in diff_forks(parent, child) if tag in c.eips)
    return result


def interaction_pairs(
    fork_a: Fork, fork_b: Fork
) -> Dict[Tuple[str, str], List[str]]:
    """
    EIP pairs that co-own a formula method, mapped to those methods.

    Two EIP mixins overriding the *same* calculator method is composition by
    construction: the composed behaviour is a distinct surface that neither
    EIP's prose necessarily determines — the prime hunting ground for both
    interaction properties and spec-ambiguity findings.

    Deliberately restricted to the override detector (``FORMULA_CHANGED``):
    value-level co-attribution (e.g. every gas-repricing EIP credited with
    every ``GasCosts`` field) mostly reflects attribution imprecision, not
    interaction, and would drown the signal. Widening this to value changes
    requires exact per-mixin attribution (incremental MRO diffing) first.
    """
    pairs: Dict[Tuple[str, str], List[str]] = {}
    for change in diff_forks(fork_a, fork_b):
        if change.kind is not ChangeKind.FORMULA_CHANGED:
            continue
        eips = sorted(set(change.eips))
        for i, first in enumerate(eips):
            for second in eips[i + 1 :]:
                pairs.setdefault((first, second), []).append(change.name)
    return pairs


def derived_checklist_sections(changes: List[Change]) -> Set[str]:
    """The set of checklist sections implied by a manifest."""
    sections: Set[str] = set()
    for change in changes:
        sections.update(change.checklist_sections)
    return sections
