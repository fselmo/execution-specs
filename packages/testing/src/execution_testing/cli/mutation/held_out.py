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

import json
import random
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from .mutations import Mutant, apply_mutant, enumerate_mutants
from .reach_log import summary_data
from .runner import DifferentialOptions, _run_differential
from .shapes import repo_root
from .source import restore_on_signal

_AMSTERDAM = "src/ethereum/forks/amsterdam"


@dataclass(frozen=True)
class Stratum:
    """A named spec module to draw held-out mutants from."""

    name: str
    module: str
    operators: Tuple[str, ...]


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
        for mutant in enumerate_mutants(source):
            if mutant.operator not in stratum.operators:
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
            for mutant in candidates[:per_stratum]
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


@dataclass
class HeldOutResult:
    """A held-out mutant paired with whether the fuzzer killed it."""

    held: HeldOutMutant
    killed: bool
    first_kill_seed: Optional[int]
    seconds: float


def run_held_out(
    path: Path,
    differential: DifferentialOptions,
    *,
    timeout: int,
) -> List[HeldOutResult]:
    """Apply each frozen mutant, run the differential oracle, score it."""
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
        for held in load_held_out(path):
            if held.module not in cache:
                cache[held.module] = (root / held.module).read_text()
            source = cache[held.module]
            mutant = resolve(held, source)
            assert mutant is not None
            target = root / held.module
            original = target.read_text()
            target.write_text(apply_mutant(original, mutant))
            start = time.monotonic()
            try:
                with restore_on_signal({target: original}):
                    process = _run_differential(differential, summary, timeout)
            finally:
                target.write_text(original)
            data = summary_data(summary) if summary.exists() else None
            killed = process is not None and process.returncode != 0
            results.append(
                HeldOutResult(
                    held,
                    killed,
                    (data or {}).get("first_divergent_seed"),
                    time.monotonic() - start,
                )
            )
    return results


def held_out_report(results: Sequence[HeldOutResult]) -> str:
    """Render stratified kill-rate over the held-out set."""
    by: Dict[str, List[HeldOutResult]] = {}
    for result in results:
        by.setdefault(result.held.stratum, []).append(result)
    lines: List[str] = []
    total_killed = 0
    for stratum in sorted(by):
        group = by[stratum]
        killed = sum(1 for r in group if r.killed)
        total_killed += killed
        lines.append(f"{stratum}: kill-rate {killed}/{len(group)}")
    lines.append(f"overall: {total_killed}/{len(results)}")
    return "\n".join(lines)
