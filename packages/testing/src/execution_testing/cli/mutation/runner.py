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

import os
import random
import signal
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator, List, Optional

from .mutations import Mutant, apply_mutant, enumerate_mutants


class Oracle(str, Enum):
    """Which test oracle decides whether a mutant is killed."""

    FILL = "fill"
    PROPERTIES = "properties"


class Verdict(str, Enum):
    """Outcome of running one mutant through the oracle."""

    KILLED_TESTS = "killed (tests)"
    KILLED_INVARIANT = "killed (invariant only)"
    KILLED_TIMEOUT = "killed (timeout)"
    SURVIVED = "survived"


@dataclass
class MutantResult:
    """A mutant paired with its verdict."""

    mutant: Mutant
    verdict: Verdict


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


def _run_oracle(
    oracle: Oracle,
    test_paths: List[str],
    fork: str,
    output_dir: Path,
    timeout: int,
) -> Optional[subprocess.CompletedProcess]:
    if oracle is Oracle.PROPERTIES:
        return _run_properties(test_paths, timeout)
    return _run_fill(test_paths, fork, output_dir, timeout)


def _invariant_count(process: subprocess.CompletedProcess) -> int:
    return (process.stdout + process.stderr).count(_INVARIANT_MARKER)


@contextmanager
def _restore_on_signal(module_path: Path, original: str) -> Iterator[None]:
    """
    Restore the module source if the process is signalled mid-run.

    A ``finally`` handles exceptions and SIGINT (which raises), but a plain
    SIGTERM (e.g. from ``timeout``) would kill the process before the source
    is restored, leaving a mutant on disk. Restore in a SIGTERM handler too.
    """

    def handler(signum: int, _frame: object) -> None:
        module_path.write_text(original)
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    previous = signal.signal(signal.SIGTERM, handler)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


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
            with _restore_on_signal(module_path, original):
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


def _classify(
    process: Optional[subprocess.CompletedProcess], baseline_invariants: int
) -> Verdict:
    if process is None:
        return Verdict.KILLED_TIMEOUT
    if process.returncode != 0:
        return Verdict.KILLED_TESTS
    if _invariant_count(process) > baseline_invariants:
        return Verdict.KILLED_INVARIANT
    return Verdict.SURVIVED
