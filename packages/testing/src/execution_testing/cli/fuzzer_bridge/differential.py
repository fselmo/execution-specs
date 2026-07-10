"""
Cross-client differential fuzzing: EELS versus a client transition tool.

Runs each generated case through the reference spec (EELS, in-process) and a
client ``t8n`` (e.g. geth's ``evm``), then compares the transition results
field by field. A divergence in the state root, receipts root, gas used,
rejected-transaction set, or any other consensus-relevant output is a
finding: on adversarial input the two implementations disagree, which is the
class of bug that splits a live network.

Divergences are minimized (delta-debugging with a "still diverges"
predicate) and saved to a corpus as ``FuzzerOutput`` JSON.
"""

from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import List, Optional, Tuple

from execution_testing.client_clis import TransitionTool
from execution_testing.client_clis.cli_types import Result
from execution_testing.client_clis.clis.execution_specs import (
    ExecutionSpecsTransitionTool,
)
from execution_testing.forks import Fork
from execution_testing.specs.blockchain import (
    environment_from_parent_header,
)

from .converter import blockchain_test_from_fuzzer
from .corpus import minimize, save_case
from .generator import GENERATOR_VERSION, generate_fuzzer_output
from .models import FuzzerOutput

# Consensus-relevant scalar fields compared when both tools report them.
_COMPARED_FIELDS = (
    "state_root",
    "receipts_root",
    "logs_hash",
    "gas_used",
    "withdrawals_root",
    "blob_gas_used",
    "requests_hash",
    "block_access_list_hash",
)


@dataclass
class FieldDivergence:
    """A single field on which the two tools disagree."""

    field: str
    eels: str
    client: str


@dataclass
class CaseOutcome:
    """Result of comparing one seed across the two tools."""

    seed: int
    divergences: List[FieldDivergence] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def diverged(self) -> bool:
        """Whether the two tools disagreed (or one failed asymmetrically)."""
        return bool(self.divergences) or self.error is not None


@dataclass
class DifferentialReport:
    """Aggregate outcome of a differential run."""

    fork: str
    generator_version: int
    client: str
    seeds: int
    agreed: int
    diverged: int
    outcomes: List[CaseOutcome] = field(default_factory=list)


def _transition(t8n: TransitionTool, case: FuzzerOutput, fork: Fork) -> Result:
    """Run a single-block transition of ``case`` through ``t8n``."""
    test = blockchain_test_from_fuzzer(case, fork)
    pre, genesis = test.make_genesis(apply_pre_allocation_blockchain=True)
    env = environment_from_parent_header(genesis.header)
    built = test.generate_block_data(
        t8n=t8n, block=test.blocks[0], previous_env=env, previous_alloc=pre
    )
    return built.result


def _compare(eels: Result, client: Result) -> List[FieldDivergence]:
    """Compare two transition results, returning the fields that differ."""
    divergences: List[FieldDivergence] = []
    for name in _COMPARED_FIELDS:
        a = getattr(eels, name, None)
        b = getattr(client, name, None)
        if a is None or b is None:
            continue
        if str(a) != str(b):
            divergences.append(FieldDivergence(name, str(a), str(b)))

    eels_rejected = sorted(int(r.index) for r in eels.rejected_transactions)
    client_rejected = sorted(
        int(r.index) for r in client.rejected_transactions
    )
    if eels_rejected != client_rejected:
        divergences.append(
            FieldDivergence(
                "rejected_transactions",
                str(eels_rejected),
                str(client_rejected),
            )
        )
    return divergences


def _evaluate(
    eels: TransitionTool,
    client: TransitionTool,
    case: FuzzerOutput,
    fork: Fork,
) -> Tuple[List[FieldDivergence], Optional[str]]:
    """
    Run ``case`` through both tools and classify the outcome.

    A tool raising where the other succeeds is itself a divergence (one
    rejected the block, the other accepted it). Both raising is treated as
    agreement — both consider the input invalid.
    """
    eels_result: Optional[Result] = None
    client_result: Optional[Result] = None
    eels_error: Optional[str] = None
    client_error: Optional[str] = None

    try:
        eels_result = _transition(eels, case, fork)
    except Exception as exc:  # noqa: BLE001
        eels_error = f"{type(exc).__name__}: {exc}"

    try:
        client_result = _transition(client, case, fork)
    except Exception as exc:  # noqa: BLE001
        client_error = f"{type(exc).__name__}: {exc}"

    if eels_result is None and client_result is None:
        return [], None
    if eels_result is None or client_result is None:
        return [], (
            "asymmetric failure: "
            f"eels={eels_error or 'ok'} client={client_error or 'ok'}"
        )
    return _compare(eels_result, client_result), None


def differential_fuzz(
    fork: Fork,
    seeds: range,
    client: TransitionTool,
    corpus_dir: Optional[Path] = None,
    *,
    minimize_cases: bool = True,
) -> DifferentialReport:
    """
    Fuzz ``fork`` across ``seeds``, comparing EELS against ``client``.

    Divergent cases are saved to ``corpus_dir`` (minimized when requested).
    """
    eels = ExecutionSpecsTransitionTool()
    report = DifferentialReport(
        fork=fork.name(),
        generator_version=GENERATOR_VERSION,
        client=client.__class__.__name__,
        seeds=len(seeds),
        agreed=0,
        diverged=0,
    )

    for seed in seeds:
        case = generate_fuzzer_output(fork, seed)
        divergences, error = _evaluate(eels, client, case, fork)
        outcome = CaseOutcome(seed=seed, divergences=divergences, error=error)

        if outcome.diverged:
            report.diverged += 1
            if corpus_dir is not None:
                saved = case
                if minimize_cases:
                    predicate = partial(_diverges, eels, client, fork=fork)
                    saved = minimize(case, predicate)
                save_case(
                    saved,
                    corpus_dir / f"{fork.name()}_divergence_seed{seed}.json",
                )
        else:
            report.agreed += 1

        report.outcomes.append(outcome)

    return report


def _diverges(
    eels: TransitionTool,
    client: TransitionTool,
    case: FuzzerOutput,
    *,
    fork: Fork,
) -> bool:
    """Return whether this case still diverges (minimization predicate)."""
    divergences, error = _evaluate(eels, client, case, fork)
    return bool(divergences) or error is not None
