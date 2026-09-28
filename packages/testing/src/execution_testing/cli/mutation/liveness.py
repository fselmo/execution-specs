"""
Weak-mutation liveness: whether generated cases ever make a mutant differ.

A mutant that survives the differential oracle either never ran
differently -- the mutated expression, evaluated where the original was,
always gave the same value -- or ran differently and nothing the
comparison sees changed. The first needs a case shape that reaches it (a
motif); the second needs the difference made visible (a witness, a field
compared), and no amount of new shapes would kill it.

Each mutant's site is rewritten to a probe that evaluates the original
and the mutated expression, counts where they differ, and returns the
original. The spec so instrumented behaves as the unmutated spec, so
every survivor is measured in one run of the reference over the seeds.

A differing value is not yet a differing execution: `2**64 - 1` differs
from `2**64 + 1` on every evaluation, and the nonce compared with it
never reaches either. So on the seeds where a mutant's value differs,
the real mutant then runs under a full trace, and its trace, results and
post-state are compared with the unmutated spec's. Only an execution
that differs there, and still was not killed, needs observability.
"""

from __future__ import annotations

import builtins
import hashlib
import json
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Sequence, Tuple

from .held_out import HeldOutMutant, resolve
from .mutations import Mutant, _line_start_offsets, apply_mutant
from .shapes import repo_root
from .source import restore_on_signal

PROBE = "__weak_mutation_probe__"
"""Name the instrumented source calls; installed in `builtins` by the
measuring process, so the spec imports nothing new."""

_MISSING = object()


@dataclass
class Tally:
    """How often a probed site ran, and how often the mutant differed."""

    evaluations: int = 0
    differing: int = 0
    """Evaluations where the mutated expression gave another value or
    raised where the original did not."""
    seeds_reached: int = 0
    seeds_differing: int = 0
    executions_differing: int = 0
    """Of the seeds where the value differed, those on which the real
    mutant's trace, results or post-state differ from the spec's."""
    crashed: int = 0
    """Of those seeds, the ones the real mutant crashed on."""

    @property
    def verdict(self) -> str:
        """Which remedy a survivor needs."""
        if self.executions_differing:
            return "reached, not killed: needs observability"
        if self.crashed and self.crashed == self.seeds_differing:
            return "reached, crashes wherever reached: not killable"
        if self.differing:
            return "value differs, execution never does: needs a motif"
        if self.evaluations:
            return "unreached (evaluated, never differs): needs a motif"
        return "unreached (never evaluated): needs a motif"


def instrument(source: str, mutants: Mapping[int, Mutant]) -> str:
    """Rewrite each mutant's site in ``source`` as a call to the probe."""
    starts = _line_start_offsets(source)
    spans: List[Tuple[int, int, int, Mutant]] = []
    for key, mutant in mutants.items():
        start = starts[mutant.lineno - 1] + mutant.col_offset
        end = starts[mutant.end_lineno - 1] + mutant.end_col_offset
        assert source[start:end] == mutant.original
        spans.append((start, end, key, mutant))
    spans.sort()
    for before, after in zip(spans, spans[1:], strict=False):
        if after[0] < before[1]:
            raise ValueError(
                f"probed sites overlap: {before[3].original!r} and "
                f"{after[3].original!r}"
            )
    for start, end, key, mutant in reversed(spans):
        call = (
            f"{PROBE}({key}, lambda: ({mutant.original}), "
            f"lambda: ({mutant.mutated}))"
        )
        source = source[:start] + call + source[end:]
    return source


class Probe:
    """Counts, per site, evaluations and those where the mutant differs."""

    def __init__(self) -> None:
        self.on = False
        self.evaluations: Counter[int] = Counter()
        self.differing: Counter[int] = Counter()

    def __call__(
        self, key: int, original: Callable[[], Any], mutated: Callable[[], Any]
    ) -> Any:
        """Return the original value, counting whether the mutant differs."""
        value = original()
        if not self.on:
            return value
        self.evaluations[key] += 1
        try:
            other = mutated()
        except Exception:  # noqa: BLE001 - a raise is a difference
            other = _MISSING
        try:
            differs = other is _MISSING or bool(other != value)
        except Exception:  # noqa: BLE001
            differs = True
        if differs:
            self.differing[key] += 1
        return value


def measure_seeds(fork_name: str, seeds: range) -> Dict[str, Any]:
    """
    Run each seed through the reference alone with the probe installed.

    The probe counts only the case's own transition: the measuring fill
    runs a variant of the case on ample gas, which the comparison never
    sees.
    """
    from execution_testing.client_clis.clis.execution_specs import (
        ExecutionSpecsTransitionTool,
    )

    from ..fuzzer_bridge.differential import (
        _fork_by_name,
        _prepare,
        _resolve,
        _transition,
    )
    from ..fuzzer_bridge.generator import generate_fuzzer_output

    probe = Probe()
    setattr(builtins, PROBE, probe)
    fork = _fork_by_name(fork_name)
    tool = ExecutionSpecsTransitionTool()
    per_seed: Dict[int, Dict[str, List[int]]] = {}
    failed = 0
    for seed in seeds:
        before = (Counter(probe.evaluations), Counter(probe.differing))
        try:
            case = _resolve(generate_fuzzer_output(fork, seed), fork, {})
            prepared = _prepare(case, fork)
            probe.on = True
            try:
                _transition(tool, prepared)
            finally:
                probe.on = False
        except Exception:  # noqa: BLE001 - counted, the probe kept its tally
            failed += 1
        per_seed[seed] = {
            str(key): [
                probe.evaluations[key] - before[0][key],
                probe.differing[key] - before[1][key],
            ]
            for key in probe.evaluations
            if probe.evaluations[key] - before[0][key]
        }
    return {"seeds": len(seeds), "failed": failed, "per_seed": per_seed}


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, default=str).encode()
    ).hexdigest()


def execution_digests(fork_name: str, seeds: Sequence[int]) -> Dict[str, Any]:
    """
    Each seed's resolved case and full execution under the spec on disk,
    as digests: the EIP-3155 trace, every block's result, the post-state.

    A seed the spec raises on is recorded as crashed.
    """
    from execution_testing.client_clis.clis.execution_specs import (
        ExecutionSpecsTransitionTool,
    )

    from ..fuzzer_bridge.differential import (
        _fork_by_name,
        _prepare,
        _resolve,
        _transition,
    )
    from ..fuzzer_bridge.generator import generate_fuzzer_output

    fork = _fork_by_name(fork_name)
    tool = ExecutionSpecsTransitionTool(trace=True)
    digests: Dict[int, Any] = {}
    for seed in seeds:
        tool.reset_traces()
        try:
            case = _resolve(generate_fuzzer_output(fork, seed), fork, {})
            results, alloc = _transition(tool, _prepare(case, fork))
        except Exception as exc:  # noqa: BLE001 - recorded per seed
            digests[seed] = {"crashed": type(exc).__name__}
            continue
        digests[seed] = {
            "case": _digest(case.model_dump(mode="json")),
            "run": _digest(
                [
                    [
                        t.model_dump(mode="json")
                        for t in tool.get_traces() or []
                    ],
                    [r.model_dump(mode="json") for r in results],
                    alloc.model_dump(mode="json") if alloc else None,
                ]
            ),
        }
    return {"digests": digests}


def tally(data: Mapping[str, Any], keys: Sequence[int]) -> Dict[int, Tally]:
    """Sum a measurement's per-seed counts into one tally per site."""
    tallies = {key: Tally() for key in keys}
    for counts in data["per_seed"].values():
        for key, (evaluated, differing) in counts.items():
            entry = tallies[int(key)]
            entry.evaluations += evaluated
            entry.differing += differing
            entry.seeds_reached += 1
            entry.seeds_differing += 1 if differing else 0
    return tallies


def run_liveness(
    mutants: Mapping[int, HeldOutMutant],
    fork: str,
    seeds: range,
    *,
    timeout: int,
) -> Tuple[Dict[int, Tally], int]:
    """
    Probe every mutant's site at once and run the seeds through EELS.

    Returns each mutant's tally and how many seeds the reference could not
    run. The instrumented sources are restored however the run ends.
    """
    root = repo_root()
    by_module: Dict[str, Dict[int, Mutant]] = {}
    originals: Dict[Path, str] = {}
    resolved: Dict[int, Mutant] = {}
    for key, held in mutants.items():
        path = root / held.module
        originals.setdefault(path, path.read_text())
        mutant = resolve(held, originals[path])
        if mutant is None:
            raise ValueError(f"held-out mutant {key} no longer resolves")
        by_module.setdefault(held.module, {})[key] = mutant
        resolved[key] = mutant

    def measure(mode: str, sources: Mapping[Path, str], seeds: str) -> Any:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"
            try:
                with restore_on_signal(originals):
                    for path, text in sources.items():
                        path.write_text(text)
                    subprocess.run(
                        [sys.executable, "-m", __name__, mode, fork, seeds]
                        + [str(out)],
                        check=True,
                        timeout=timeout,
                    )
            finally:
                for path, text in originals.items():
                    path.write_text(text)
            return json.loads(out.read_text())

    # A probe cannot sit inside another, so nested sites go to separate
    # runs: each run probes, per module, sites that do not overlap.
    rounds: List[Dict[str, Dict[int, Mutant]]] = []

    def span(starts: List[int], m: Mutant) -> Tuple[int, int]:
        return (
            starts[m.lineno - 1] + m.col_offset,
            starts[m.end_lineno - 1] + m.end_col_offset,
        )

    for module, sites in by_module.items():
        starts = _line_start_offsets(originals[root / module])

        for key, mutant in sorted(sites.items()):
            a, b = span(starts, mutant)
            for placed in rounds:
                others = placed.get(module, {})
                if all(
                    b <= span(starts, o)[0] or span(starts, o)[1] <= a
                    for o in others.values()
                ):
                    placed.setdefault(module, {})[key] = mutant
                    break
            else:
                rounds.append({module: {key: mutant}})
    data: Dict[str, Any] = {"failed": 0, "per_seed": {}}
    for placed in rounds:
        probed = {
            root / module: instrument(originals[root / module], sites)
            for module, sites in placed.items()
        }
        part = measure("probe", probed, f"{seeds.start}:{seeds.stop}")
        data["failed"] = max(data["failed"], part["failed"])
        for seed, counts in part["per_seed"].items():
            data["per_seed"].setdefault(seed, {}).update(counts)
    tallies = tally(data, list(mutants))

    differing = {
        key: sorted(
            int(seed)
            for seed, counts in data["per_seed"].items()
            if counts.get(str(key), [0, 0])[1]
        )
        for key in mutants
    }
    wanted = sorted({seed for seeds_ in differing.values() for seed in seeds_})
    if wanted:
        listed = ",".join(map(str, wanted))
        clean = measure("digest", {}, listed)["digests"]
        for key, mutant in resolved.items():
            if not differing[key]:
                continue
            path = root / mutants[key].module
            runs = measure(
                "digest",
                {path: apply_mutant(originals[path], mutant)},
                ",".join(map(str, differing[key])),
            )["digests"]
            for seed in differing[key]:
                mine = runs[str(seed)]
                if "crashed" in mine:
                    tallies[key].crashed += 1
                elif mine != clean[str(seed)]:
                    tallies[key].executions_differing += 1
    return tallies, data["failed"]


def liveness_report(
    mutants: Mapping[int, HeldOutMutant],
    tallies: Mapping[int, Tally],
    seeds: int,
    failed: int,
) -> str:
    """One line per mutant: its counts and the remedy it needs."""
    lines = [
        f"weak-mutation liveness over {seeds} seeds "
        f"({failed} the reference could not run)"
    ]
    for key in sorted(mutants):
        entry = tallies[key]
        held = mutants[key]
        lines.append(
            f"{key:02d} {held.stratum:<15} {entry.differing}/"
            f"{entry.evaluations} evaluations differ, on "
            f"{entry.seeds_differing}/{entry.seeds_reached} seeds reaching "
            f"it; execution differs on {entry.executions_differing}, "
            f"crashes on {entry.crashed} -- {entry.verdict}\n"
            f"   {held.original!r} -> {held.mutated!r}"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    mode, fork_name, seed_arg, output = sys.argv[1:5]
    if mode == "probe":
        start, stop = seed_arg.split(":")
        result = measure_seeds(fork_name, range(int(start), int(stop)))
    elif mode == "digest":
        result = execution_digests(
            fork_name, [int(s) for s in seed_arg.split(",")]
        )
    else:
        raise ValueError(f"unknown mode {mode!r}")
    Path(output).write_text(json.dumps(result))
