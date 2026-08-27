"""
Run mutation testing against the reference spec.

Each mutant is written into the spec source, then a kill-oracle runs. A mutant
is *killed* if the oracle fails (nonzero exit), a new invariant violation
appears, or the run times out; otherwise it *survives* — a case the suite does
not distinguish from correct behaviour, and therefore a coverage gap.

Two oracles:

- ``fill`` — a targeted ``fill`` with chain-invariant checks; measures how well
  the frozen conformance suite pins the spec.
- ``properties`` — the pure Hypothesis property suite (``tests_property``);
  faster, and it measures how well the *property* suite pins the spec. This is
  the objective validity signal for agent-proposed properties: a property that
  raises the kill score is demonstrably valuable.

The original source is always restored, even on error or interrupt.
"""

import json
import random
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from .mutations import Mutant, apply_mutant, enumerate_mutants
from .shapes import Shape, applied
from .source import restore_on_signal


class Oracle(str, Enum):
    """Which test oracle decides whether a mutant is killed."""

    FILL = "fill"
    PROPERTIES = "properties"
    DIFFERENTIAL = "differential"


class Verdict(str, Enum):
    """Outcome of running one mutant through the oracle."""

    KILLED_TESTS = "killed (tests)"
    KILLED_INVARIANT = "killed (invariant only)"
    KILLED_TIMEOUT = "killed (timeout)"
    KILLED_DIFFERENTIAL = "killed (differential)"
    SURVIVED = "survived"


@dataclass
class DifferentialOptions:
    """How the differential oracle drives `fuzz diff`."""

    fork: str
    count: int = 300
    campaign: Optional[str] = None
    clients: Tuple[Path, ...] = ()
    workers: int = 1
    config: Optional[Path] = None


@dataclass
class MutantResult:
    """A mutant paired with its verdict."""

    mutant: Mutant
    verdict: Verdict


@dataclass
class ShapeResult:
    """A named shape mutant paired with its verdict and reach detail."""

    shape: Shape
    verdict: Verdict
    detail: str = ""


@dataclass
class MutationReport:
    """Aggregate outcome of a mutation-testing run."""

    module: str
    total: int
    results: List[MutantResult] = field(default_factory=list)

    def _count(self, verdict: Verdict) -> int:
        return sum(1 for r in self.results if r.verdict == verdict)

    @property
    def killed(self) -> int:
        """Number of mutants killed by any signal."""
        return sum(1 for r in self.results if r.verdict != Verdict.SURVIVED)

    @property
    def survivors(self) -> List[MutantResult]:
        """Mutants no signal distinguished from correct behavior."""
        return [r for r in self.results if r.verdict == Verdict.SURVIVED]

    @property
    def invariant_only(self) -> List[MutantResult]:
        """Mutants the test suite missed but an invariant caught."""
        return [
            r for r in self.results if r.verdict == Verdict.KILLED_INVARIANT
        ]

    @property
    def score(self) -> float:
        """Fraction of mutants killed (the mutation score)."""
        return self.killed / self.total if self.total else 0.0


_INVARIANT_MARKER = "InvariantViolationWarning"


def _run_fill(
    test_paths: List[str],
    fork: str,
    output_dir: Path,
    timeout: int,
) -> Optional[subprocess.CompletedProcess]:
    """Run a targeted fill; return None on timeout."""
    try:
        return subprocess.run(
            [
                "uv",
                "run",
                "fill",
                *test_paths,
                "--fork",
                fork,
                "-x",
                "-q",
                "--invariant-checks",
                "--output",
                str(output_dir),
                "--clean",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None


def _run_properties(
    test_paths: List[str],
    timeout: int,
) -> Optional[subprocess.CompletedProcess]:
    """Run the property suite as the kill oracle; return None on timeout."""
    try:
        return subprocess.run(
            [
                "uv",
                "run",
                "pytest",
                *test_paths,
                "-x",
                "-q",
                "-p",
                "no:cacheprovider",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None


def _run_differential(
    options: DifferentialOptions, summary_path: Path, timeout: int
) -> Optional[subprocess.CompletedProcess]:
    """
    Run `fuzz diff` against the (mutated) spec on disk; None on timeout.

    `fuzz diff` exits nonzero when any seed diverges, so a divergence is a
    kill under the same classification as a failing test run.
    """
    command = [
        "uv",
        "run",
        "fuzz",
        "diff",
        "--fork",
        options.fork,
        "--count",
        str(options.count),
        "--no-minimize",
        "--no-baseline",
        "-j",
        str(options.workers),
        "--summary-json",
        str(summary_path),
    ]
    if options.campaign is not None:
        command += ["--campaign", options.campaign]
    for client in options.clients:
        command += ["--client", str(client)]
    if options.config is not None:
        command += ["--config", str(options.config)]
    try:
        return subprocess.run(
            command, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return None


def _run_oracle(
    oracle: Oracle,
    test_paths: List[str],
    fork: str,
    output_dir: Path,
    timeout: int,
    differential: Optional[DifferentialOptions] = None,
) -> Optional[subprocess.CompletedProcess]:
    if oracle is Oracle.PROPERTIES:
        return _run_properties(test_paths, timeout)
    if oracle is Oracle.DIFFERENTIAL:
        assert differential is not None
        return _run_differential(
            differential, output_dir / "summary.json", timeout
        )
    return _run_fill(test_paths, fork, output_dir, timeout)


def _invariant_count(process: subprocess.CompletedProcess) -> int:
    return (process.stdout + process.stderr).count(_INVARIANT_MARKER)


def summary_detail(summary_path: Path) -> str:
    """Render a `fuzz diff --summary-json` file as a one-line reach detail."""
    data = json.loads(summary_path.read_text())
    detail = f"{data['diverged']}/{data['seeds']} diverged"
    first = data.get("first_divergent_seed")
    if first is not None:
        detail += f", first at seed {first}"
    return detail


def run_mutation_testing(
    module_path: Path,
    test_paths: List[str],
    fork: str,
    *,
    max_mutants: Optional[int] = None,
    seed: int = 0,
    timeout: int = 600,
    include_constants: bool = False,
    oracle: Oracle = Oracle.FILL,
) -> MutationReport:
    """
    Mutate ``module_path`` and report which mutants the oracle kills.

    ``test_paths`` should exercise the mutated module; killed mutants exit
    fast under ``-x`` while survivors pay the full run. The original source
    is restored before returning.
    """
    original = module_path.read_text()
    mutants = enumerate_mutants(original, include_constants=include_constants)
    random.Random(seed).shuffle(mutants)
    if max_mutants is not None:
        mutants = mutants[:max_mutants]

    report = MutationReport(module=str(module_path), total=len(mutants))

    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp) / "fixtures"

        baseline = _run_oracle(oracle, test_paths, fork, output_dir, timeout)
        if baseline is None or baseline.returncode != 0:
            raise RuntimeError(
                "baseline oracle run did not pass cleanly; fix the "
                "target/tests before mutation testing"
            )
        baseline_invariants = _invariant_count(baseline)

        try:
            with restore_on_signal({module_path: original}):
                for mutant in mutants:
                    module_path.write_text(apply_mutant(original, mutant))
                    process = _run_oracle(
                        oracle, test_paths, fork, output_dir, timeout
                    )
                    verdict = _classify(process, baseline_invariants)
                    report.results.append(MutantResult(mutant, verdict))
        finally:
            module_path.write_text(original)

    return report


def run_shapes(
    shapes: Sequence[Shape],
    oracle: Oracle,
    test_paths: List[str],
    fork: str,
    *,
    differential: Optional[DifferentialOptions] = None,
    timeout: int = 3600,
) -> List[ShapeResult]:
    """
    Apply each named shape mutant to the spec and ask ``oracle`` whether it
    notices. Under the differential oracle the kill rate is the generator's
    *reach* for that bug class; under fill/properties it is whether the
    suite would have caught it.

    The clean spec must first pass the oracle, so a later kill is
    attributable to the shape alone.
    """
    results: List[ShapeResult] = []
    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp)
        baseline = _run_oracle(
            oracle, test_paths, fork, output_dir, timeout, differential
        )
        if baseline is None or baseline.returncode != 0:
            raise RuntimeError(
                "baseline oracle run did not pass on the clean spec; fix "
                "the target/tests/client set before measuring shapes"
            )
        baseline_invariants = _invariant_count(baseline)
        for shape in shapes:
            with applied(shape):
                process = _run_oracle(
                    oracle, test_paths, fork, output_dir, timeout, differential
                )
            verdict = _classify(process, baseline_invariants, oracle=oracle)
            summary = output_dir / "summary.json"
            detail = ""
            if oracle is Oracle.DIFFERENTIAL and process is not None:
                detail = summary_detail(summary) if summary.exists() else ""
            results.append(ShapeResult(shape, verdict, detail))
    return results


def _classify(
    process: Optional[subprocess.CompletedProcess],
    baseline_invariants: int,
    *,
    oracle: Oracle = Oracle.FILL,
) -> Verdict:
    if process is None:
        return Verdict.KILLED_TIMEOUT
    if process.returncode != 0:
        if oracle is Oracle.DIFFERENTIAL:
            return Verdict.KILLED_DIFFERENTIAL
        return Verdict.KILLED_TESTS
    if _invariant_count(process) > baseline_invariants:
        return Verdict.KILLED_INVARIANT
    return Verdict.SURVIVED
