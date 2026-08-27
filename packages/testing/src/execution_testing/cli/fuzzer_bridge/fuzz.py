"""
In-process fuzzing engine: generate → fill through EELS → check invariants.

Drives seeded ``FuzzerOutput`` cases through the reference spec (EELS) as the
oracle, checks each block against the chain invariants, and records any
interesting case (invariant violation or fill crash) into a corpus directory,
minimized via delta-debugging.

EELS is the oracle: the generator chooses inputs, the spec computes outputs.
Nothing here authors expected post-states.
"""

from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import List, Optional

from execution_testing.client_clis import LazyAlloc
from execution_testing.client_clis.clis.execution_specs import (
    ExecutionSpecsTransitionTool,
)
from execution_testing.forks import Fork
from execution_testing.specs import invariants
from execution_testing.specs.blockchain import (
    environment_from_parent_header,
)
from execution_testing.test_types import Alloc

from .converter import blockchain_test_from_fuzzer
from .corpus import minimize, save_case
from .generator import GENERATOR_VERSION, generate_fuzzer_output
from .models import FuzzerOutput


@dataclass
class CaseOutcome:
    """Result of fuzzing a single seed."""

    seed: int
    filled: bool
    violations: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def interesting(self) -> bool:
        """Whether this case is worth saving to the corpus."""
        return bool(self.violations) or self.error is not None


@dataclass
class FuzzReport:
    """Aggregate outcome of a fuzzing run."""

    fork: str
    generator_version: int
    seeds: int
    filled: int
    crashes: int
    violation_cases: int
    outcomes: List[CaseOutcome] = field(default_factory=list)


def _run_case(
    t8n: ExecutionSpecsTransitionTool, case: FuzzerOutput, fork: Fork
) -> List[str]:
    """
    Fill one case through EELS and return invariant-violation messages.

    Raises whatever the fill path raises; callers treat that as a crash.
    """
    test = blockchain_test_from_fuzzer(case, fork)
    pre, genesis = test.make_genesis(apply_pre_allocation_blockchain=True)
    env = environment_from_parent_header(genesis.header)
    alloc: Alloc | LazyAlloc = pre
    for block in test.blocks:
        built = test.generate_block_data(
            t8n=t8n, block=block, previous_env=env, previous_alloc=alloc
        )
        env = environment_from_parent_header(built.header)
        alloc = built.alloc
    # generate_block_data accumulates violations on the test instance.
    return [f"{v.invariant}: {v.message}" for v in test._invariant_violations]


def fuzz(
    fork: Fork,
    seeds: range,
    corpus_dir: Optional[Path] = None,
    *,
    minimize_cases: bool = True,
) -> FuzzReport:
    """
    Fuzz ``fork`` across ``seeds``, saving interesting cases to ``corpus_dir``.

    Returns a report tallying fills, crashes, and invariant-violation cases.
    """
    invariants.enable_invariant_checks()
    t8n = ExecutionSpecsTransitionTool()

    report = FuzzReport(
        fork=fork.name(),
        generator_version=GENERATOR_VERSION,
        seeds=len(seeds),
        filled=0,
        crashes=0,
        violation_cases=0,
    )

    for seed in seeds:
        case = generate_fuzzer_output(fork, seed)
        outcome = CaseOutcome(seed=seed, filled=False)
        try:
            outcome.violations = _run_case(t8n, case, fork)
            outcome.filled = True
            report.filled += 1
            if outcome.violations:
                report.violation_cases += 1
        except Exception as exc:  # noqa: BLE001 - any failure is a finding
            outcome.error = f"{type(exc).__name__}: {exc}"
            report.crashes += 1

        if outcome.interesting and corpus_dir is not None:
            saved = case
            if minimize_cases:
                predicate = partial(
                    _still_interesting, t8n, fork=fork, original=outcome
                )
                saved = minimize(case, predicate)
            label = "violation" if outcome.violations else "crash"
            save_case(
                saved,
                corpus_dir / f"{fork.name()}_{label}_seed{seed}.json",
            )

        report.outcomes.append(outcome)

    return report


def _still_interesting(
    t8n: ExecutionSpecsTransitionTool,
    case: FuzzerOutput,
    *,
    fork: Fork,
    original: CaseOutcome,
) -> bool:
    """
    Predicate for minimization: a reduced case stays interesting if it still
    crashes (when the original crashed) or still violates an invariant.
    """
    try:
        violations = _run_case(t8n, case, fork)
    except Exception:  # noqa: BLE001 - reduced case must reproduce the crash
        return original.error is not None
    if original.error is not None:
        return False
    return bool(violations)
