"""
Build a frozen, drift-resilient held-out mutant set for reach gating.

A held-out mutant is anchored on its *construct* --
``(module, operator, original_text, mutated_text)`` -- never on a function
name or a line number, so it survives fork refactors and backported renames:
renaming a function does not change the ``a + b`` inside it. Drift (a construct
that genuinely changed) is a first-class check via ``check_held_out``, never a
silent empty set. This mirrors the loud-anchor rule the named shapes use.
"""

from __future__ import annotations

import ast
import json
import random
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import (
    Any,
    Collection,
    Dict,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from .mutations import Mutant, apply_mutant, enumerate_mutants
from .reach_log import summary_data
from .runner import DifferentialOptions, _run_differential
from .shapes import repo_root
from .source import restore_on_signal

_AMSTERDAM = "src/ethereum/forks/amsterdam"


@dataclass(frozen=True)
class Stratum:
    """A named spec module, or some of its functions, to draw from."""

    name: str
    module: str
    operators: Tuple[str, ...]
    functions: Optional[Tuple[str, ...]] = None
    """Draw only from constructs inside these top-level functions; the
    whole module when None. Used only when freezing: a frozen mutant is
    anchored on its construct, never on the function it was drawn from."""
    count: Optional[int] = None
    """Mutants to draw from this stratum; `per_stratum` when None."""


@dataclass(frozen=True)
class HeldOutMutant:
    """A frozen mutant anchored on its construct, not its position."""

    stratum: str
    module: str
    operator: str
    original: str
    mutated: str


DEFAULT_STRATA: Tuple[Stratum, ...] = (
    Stratum("gas-arithmetic", f"{_AMSTERDAM}/vm/gas.py", ("binop", "compare")),
    Stratum(
        "frame-handling",
        f"{_AMSTERDAM}/vm/interpreter.py",
        ("compare", "boolop", "unary-not"),
    ),
    Stratum(
        "call-paths",
        f"{_AMSTERDAM}/vm/instructions/system.py",
        ("binop", "compare"),
    ),
    Stratum(
        "state-tracker",
        f"{_AMSTERDAM}/state_tracker.py",
        ("compare", "boolop"),
    ),
)

_OPERATORS = ("binop", "compare", "boolop", "unary-not")

AMSTERDAM_STRATA: Tuple[Stratum, ...] = (
    # The fork's own surfaces.
    Stratum(
        "bal-builder",
        f"{_AMSTERDAM}/block_access_lists.py",
        _OPERATORS,
        count=14,
    ),
    Stratum(
        "bal-tracker", f"{_AMSTERDAM}/state_tracker.py", _OPERATORS, count=12
    ),
    Stratum(
        "state-gas",
        f"{_AMSTERDAM}/vm/gas.py",
        _OPERATORS,
        functions=(
            "charge_state_gas_from_meter",
            "charge_state_gas",
            "commit_state_gas",
            "restore_state_gas",
            "restore_state_gas_to_entry",
            "tx_state_gas_used",
            "credit_state_gas_refund",
            "repay_state_gas_spill",
            "forfeit_remaining_gas",
            "withhold_create_gas",
            "drain_state_gas_reservoir",
            "restore_child_gas",
            "allocate_evm_gas",
            "settle_transaction_gas",
            "check_block_gas_capacity",
        ),
        count=14,
    ),
    Stratum(
        "transaction",
        f"{_AMSTERDAM}/fork.py",
        _OPERATORS,
        functions=(
            "check_transaction",
            "process_transaction",
            "disburse_gas_fees",
            "update_sender_state",
            "make_receipt",
        ),
        count=8,
    ),
    Stratum(
        "system-calls",
        f"{_AMSTERDAM}/fork.py",
        _OPERATORS,
        functions=(
            "process_checked_system_transaction",
            "process_unchecked_system_transaction",
            "process_general_purpose_requests",
            "apply_body",
        ),
        count=8,
    ),
    Stratum("requests", f"{_AMSTERDAM}/requests.py", _OPERATORS, count=4),
    Stratum(
        "delegation",
        f"{_AMSTERDAM}/vm/eoa_delegation.py",
        _OPERATORS,
        count=10,
    ),
    Stratum(
        "blocks-withdrawals",
        f"{_AMSTERDAM}/fork.py",
        _OPERATORS,
        functions=(
            "state_transition",
            "validate_header",
            "calculate_base_fee_per_gas",
            "get_last_256_block_hashes",
            "execute_block",
            "process_withdrawals",
            "check_gas_limit",
        ),
        count=10,
    ),
    # Classic EVM, so regressions there still show.
    Stratum(
        "evm-system-ops",
        f"{_AMSTERDAM}/vm/instructions/system.py",
        _OPERATORS,
        count=6,
    ),
    Stratum(
        "evm-environment",
        f"{_AMSTERDAM}/vm/instructions/environment.py",
        _OPERATORS,
        count=4,
    ),
    Stratum(
        "evm-interpreter",
        f"{_AMSTERDAM}/vm/interpreter.py",
        _OPERATORS,
        count=4,
    ),
    Stratum(
        "evm-gas",
        f"{_AMSTERDAM}/vm/gas.py",
        _OPERATORS,
        functions=(
            "check_gas",
            "charge_gas_from_meter",
            "charge_gas",
            "calculate_memory_gas_cost",
            "calculate_gas_extend_memory",
            "calculate_message_call_gas",
            "max_message_call_gas",
            "init_code_cost",
        ),
        count=4,
    ),
    Stratum(
        "evm-arithmetic",
        f"{_AMSTERDAM}/vm/instructions/arithmetic.py",
        _OPERATORS,
        count=4,
    ),
)
"""The v26 held-out strata: weighted toward the Amsterdam surfaces, with a
slice of classic EVM modules so a regression there still shows."""


def _top_level_function(source: str, lineno: int) -> Optional[str]:
    """The name of the top-level function holding ``lineno``, if any."""
    for node in ast.parse(source).body:
        if isinstance(node, ast.FunctionDef) and node.lineno <= lineno <= (
            node.end_lineno or node.lineno
        ):
            return node.name
    return None


class HeldOutDriftError(Exception):
    """A frozen mutant no longer resolves against current spec source."""


def _identity(mutant: Mutant) -> Tuple[str, str, str]:
    return (mutant.operator, mutant.original, mutant.mutated)


def stratified_mutants(
    sources: Mapping[Stratum, str],
    *,
    per_stratum: int,
    seed: int,
) -> List[HeldOutMutant]:
    """Select up to ``per_stratum`` distinct-construct mutants per stratum."""
    picked: List[HeldOutMutant] = []
    for stratum, source in sources.items():
        seen: set[Tuple[str, str, str]] = set()
        candidates: List[Mutant] = []
        everywhere = enumerate_mutants(source)
        # `resolve` takes a construct's first occurrence; one that occurs
        # twice could resolve outside the function it was drawn from.
        ambiguous = {
            identity
            for identity, n in Counter(map(_identity, everywhere)).items()
            if n > 1
        }
        for mutant in everywhere:
            if (
                stratum.functions is not None
                and _identity(mutant) in ambiguous
            ):
                continue
            if mutant.operator not in stratum.operators:
                continue
            if (
                stratum.functions is not None
                and _top_level_function(source, mutant.lineno)
                not in stratum.functions
            ):
                continue
            identity = _identity(mutant)
            if identity in seen:
                continue
            seen.add(identity)
            candidates.append(mutant)
        random.Random(f"{seed}:{stratum.name}").shuffle(candidates)
        picked += [
            HeldOutMutant(
                stratum.name,
                stratum.module,
                mutant.operator,
                mutant.original,
                mutant.mutated,
            )
            for mutant in candidates[: stratum.count or per_stratum]
        ]
    return picked


def resolve(held: HeldOutMutant, source: str) -> Optional[Mutant]:
    """Find the current mutant matching this frozen construct, or None."""
    target = (held.operator, held.original, held.mutated)
    for mutant in enumerate_mutants(source):
        if _identity(mutant) == target:
            return mutant
    return None


def freeze_held_out(
    strata: Sequence[Stratum],
    path: Path,
    *,
    per_stratum: int,
    seed: int,
) -> None:
    """Freeze a stratified selection as construct-anchored mutants."""
    root = repo_root()
    sources = {s: (root / s.module).read_text() for s in strata}
    picked = stratified_mutants(sources, per_stratum=per_stratum, seed=seed)
    data = {
        "seed": seed,
        "per_stratum": per_stratum,
        "strata": [
            {
                "name": s.name,
                "module": s.module,
                "operators": list(s.operators),
                **({"functions": list(s.functions)} if s.functions else {}),
                **({"count": s.count} if s.count else {}),
            }
            for s in strata
        ],
        "mutants": [
            {
                "stratum": h.stratum,
                "module": h.module,
                "operator": h.operator,
                "original": h.original,
                "mutated": h.mutated,
            }
            for h in picked
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def split_held_out(
    held: Sequence[HeldOutMutant], *, seed: int
) -> Dict[str, List[int]]:
    """
    Split a frozen set into tuning and evaluation halves, stratum by
    stratum, by position.

    Motifs may be aimed only at the tuning half's survivors, so the
    evaluation half measures what a motif buys on mutants nobody tuned
    for. Each stratum's positions are shuffled by the seed and halved; a
    stratum with an odd count gives its extra one to the halves in turn.
    """
    by: Dict[str, List[int]] = {}
    for index, mutant in enumerate(held):
        by.setdefault(mutant.stratum, []).append(index)
    halves: Dict[str, List[int]] = {"tuning": [], "evaluation": []}
    odd = 0
    for stratum in sorted(by):
        indices = list(by[stratum])
        random.Random(f"split:{seed}:{stratum}").shuffle(indices)
        cut = len(indices) // 2
        if len(indices) % 2:
            cut += odd % 2 == 0
            odd += 1
        halves["tuning"] += indices[:cut]
        halves["evaluation"] += indices[cut:]
    return {half: sorted(indices) for half, indices in halves.items()}


def load_held_out(path: Path) -> List[HeldOutMutant]:
    """Load a frozen set (pure I/O; drift is a separate check)."""
    data = json.loads(path.read_text())
    return [
        HeldOutMutant(
            m["stratum"],
            m["module"],
            m["operator"],
            m["original"],
            m["mutated"],
        )
        for m in data["mutants"]
    ]


@dataclass(frozen=True)
class DriftReport:
    """Which frozen mutants still resolve, and which have drifted."""

    valid: Tuple[HeldOutMutant, ...]
    drifted: Tuple[HeldOutMutant, ...]


def check_held_out(path: Path) -> DriftReport:
    """Re-resolve every frozen mutant against current source."""
    root = repo_root()
    cache: Dict[str, Optional[str]] = {}
    valid: List[HeldOutMutant] = []
    drifted: List[HeldOutMutant] = []
    for held in load_held_out(path):
        if held.module not in cache:
            module_path = root / held.module
            cache[held.module] = (
                module_path.read_text() if module_path.exists() else None
            )
        source = cache[held.module]
        if source is not None and resolve(held, source) is not None:
            valid.append(held)
        else:
            drifted.append(held)
    return DriftReport(tuple(valid), tuple(drifted))


OUTCOMES = ("killed", "survived", "invalid", "not tested")
"""How a held-out mutant scores; only the first two were tested."""


def score(summary: Optional[Mapping[str, Any]]) -> str:
    """
    Score one mutant's run from its `fuzz diff` summary, seed by seed.

    A seed the mutated spec crashed on compared nothing there, so it is
    neither a kill nor a survival: a mutant is killed when some seed it
    did not crash on diverged, and survived when seeds were compared and
    none diverged. One that crashed on every seed is invalid: it measures
    nothing. A run that left no summary, or compared nothing for another
    reason (every seed refused or errored), was not tested.
    """
    if summary is None:
        return "not tested"
    if summary.get("crashed", 0) >= summary["seeds"]:
        return "invalid"
    if summary["diverged"]:
        return "killed"
    if summary.get("compared", 0):
        return "survived"
    return "not tested"


@dataclass
class HeldOutResult:
    """A held-out mutant paired with how the fuzzer scored it."""

    held: HeldOutMutant
    outcome: str
    first_kill_seed: Optional[int]
    seconds: float
    summary: Optional[Dict[str, Any]] = None
    index: int = 0
    """Position in the frozen set."""

    @property
    def killed(self) -> bool:
        """Whether some seed the spec ran diverged."""
        return self.outcome == "killed"


def run_held_out(
    path: Path,
    differential: DifferentialOptions,
    *,
    timeout: int,
    only: Optional[Collection[int]] = None,
) -> List[HeldOutResult]:
    """
    Apply each frozen mutant, run the differential oracle, score it.

    ``only`` runs the mutants at those positions in the frozen set, to
    re-measure part of it without reshaping it.
    """
    drift = check_held_out(path)
    if drift.drifted:
        modules = ", ".join(sorted({h.module for h in drift.drifted}))
        raise HeldOutDriftError(
            f"{len(drift.drifted)} held-out mutant(s) no longer resolve "
            f"(modules: {modules}); run `mutate --held-out-check` and "
            "re-freeze the set"
        )
    root = repo_root()
    cache: Dict[str, str] = {}
    results: List[HeldOutResult] = []
    with tempfile.TemporaryDirectory() as tmp:
        summary = Path(tmp) / "summary.json"
        for index, held in enumerate(load_held_out(path)):
            if only is not None and index not in only:
                continue
            if held.module not in cache:
                cache[held.module] = (root / held.module).read_text()
            source = cache[held.module]
            mutant = resolve(held, source)
            assert mutant is not None
            target = root / held.module
            original = target.read_text()
            target.write_text(apply_mutant(original, mutant))
            start = time.monotonic()
            # A run that dies before writing its summary must not inherit
            # the previous mutant's.
            summary.unlink(missing_ok=True)
            try:
                with restore_on_signal({target: original}):
                    _run_differential(differential, summary, timeout)
            finally:
                target.write_text(original)
            # The summary decides, never the exit code: `fuzz diff` exits
            # nonzero on a crash too, and a crash is not a kill.
            data = summary_data(summary)
            results.append(
                HeldOutResult(
                    held,
                    score(data),
                    (data or {}).get("first_divergent_seed"),
                    time.monotonic() - start,
                    data,
                    index,
                )
            )
    return results


CRASHING_FILE = "crashes_wherever_reached.json"
"""Beside a frozen set: the positions the survivor diagnostic found crash
wherever they are reached. A run cannot tell them from survivors, since
a seed that does not reach one agrees, so they are recorded once."""


def crashing_positions(path: Path) -> Set[int]:
    """The positions recorded as crashing wherever reached, if any."""
    listed = path.parent / CRASHING_FILE
    if not listed.exists():
        return set()
    return set(json.loads(listed.read_text())["positions"])


def held_out_report(
    results: Sequence[HeldOutResult], crashing: Collection[int] = ()
) -> str:
    """
    Render the stratified kill rate over the tested mutants, with the
    survived, crashing, invalid and untested counts beside it. A mutant in
    ``crashing`` that was not killed is scored apart: no case can kill it.
    """
    by: Dict[str, List[HeldOutResult]] = {}
    for result in results:
        by.setdefault(result.held.stratum, []).append(result)

    def line(name: str, group: Sequence[HeldOutResult]) -> str:
        apart = [
            r for r in group if r.index in crashing and r.outcome == "survived"
        ]
        counts = {o: sum(r.outcome == o for r in group) for o in OUTCOMES}
        counts["survived"] -= len(apart)
        tested = counts["killed"] + counts["survived"]
        return (
            f"{name}: kill-rate {counts['killed']}/{tested} tested "
            f"({counts['survived']} survived, {len(apart)} crash wherever "
            f"reached, {counts['invalid']} invalid, "
            f"{counts['not tested']} not tested)"
        )

    lines = [line(stratum, by[stratum]) for stratum in sorted(by)]
    lines.append(line("overall", results))
    return "\n".join(lines)
