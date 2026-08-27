"""
Cross-client differential fuzzing: EELS versus client transition tools.

Runs each generated case through the reference spec (EELS, in-process) and
any number of client ``t8n`` tools, then compares the transition results
field by field. A divergence in the state root, receipts root, gas used,
rejected-transaction set, or any other consensus-relevant output is a
finding: on adversarial input the implementations disagree, which is the
class of bug that splits a live network. With several tools the report
names the minority on each field, so a run says *who* is wrong, not only
that someone is.

Divergences are minimized (delta-debugging with a "still diverges"
predicate) and saved to a corpus as ``FuzzerOutput`` JSON.
"""

from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from execution_testing.client_clis import LazyAlloc, TransitionTool
from execution_testing.client_clis.cli_types import Result
from execution_testing.client_clis.clis.execution_specs import (
    ExecutionSpecsTransitionTool,
)
from execution_testing.forks import Fork, get_forks
from execution_testing.specs.blockchain import (
    BlockchainTest,
    environment_from_parent_header,
)
from execution_testing.test_types import Alloc, Environment

from .converter import blockchain_test_from_fuzzer
from .corpus import minimize, save_case
from .generator import GENERATOR_VERSION, generate_fuzzer_output
from .models import FuzzerOutput

REFERENCE = "eels"


def _fork_by_name(name: str) -> Fork:
    for fork in get_forks():
        if fork.name() == name:
            return fork
    raise ValueError(f"unknown fork {name!r}")


# Consensus-relevant scalar fields compared when every tool reports them.
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
    """A field on which the tools disagree, with the odd ones out."""

    field: str
    values: Dict[str, str]
    minority: List[str]


@dataclass
class CaseOutcome:
    """Result of comparing one seed across the tools."""

    seed: int
    tool_count: int = 0
    divergences: List[FieldDivergence] = field(default_factory=list)
    errors: Dict[str, str] = field(default_factory=dict)
    eels_ran: bool = True
    post_state_diff: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    """Per minority tool, the accounts on which it differs from EELS."""

    @property
    def asymmetric_failure(self) -> bool:
        """Some tools failed while others produced a result."""
        return bool(self.errors) and len(self.errors) < self.tool_count

    @property
    def diverged(self) -> bool:
        """Whether any tool disagreed, or failed where another succeeded."""
        return bool(self.divergences) or self.asymmetric_failure


@dataclass
class DifferentialReport:
    """Aggregate outcome of a differential run."""

    fork: str
    generator_version: int
    clients: List[str]
    seeds: int
    agreed: int
    diverged: int
    outcomes: List[CaseOutcome] = field(default_factory=list)
    baseline: Dict[str, int] = field(default_factory=dict)
    manifest: Optional[Any] = None

    @property
    def eels_runs(self) -> int:
        """How many cases the reference had to adjudicate."""
        return sum(1 for outcome in self.outcomes if outcome.eels_ran)


Prepared = Tuple[BlockchainTest, Environment, Alloc]


def _prepare(case: FuzzerOutput, fork: Fork) -> Prepared:
    """
    Build the test and its genesis once per case.

    Genesis construction computes a state root, so it is done once and
    shared by every tool rather than repeated per transition.
    """
    test = blockchain_test_from_fuzzer(case, fork)
    pre, genesis = test.make_genesis(apply_pre_allocation_blockchain=True)
    env = environment_from_parent_header(genesis.header)
    return test, env, pre


def _transition(
    t8n: TransitionTool, prepared: Prepared
) -> Tuple[Result, Optional[Alloc]]:
    """Run the prepared single-block transition through ``t8n``."""
    test, env, pre = prepared
    built = test.generate_block_data(
        t8n=t8n, block=test.blocks[0], previous_env=env, previous_alloc=pre
    )
    alloc = (
        built.alloc.materialize()
        if isinstance(built.alloc, LazyAlloc)
        else built.alloc
    )
    return built.result, alloc


def _minority(values: Dict[str, str]) -> List[str]:
    """
    Name the tools holding a minority value.

    A tie is broken in favour of the reference implementation; a tie
    without it reports every tool, since nothing distinguishes the sides.
    """
    counts = Counter(values.values())
    top = max(counts.values())
    leaders = [value for value, n in counts.items() if n == top]
    if len(leaders) == 1:
        majority = leaders[0]
    elif values.get(REFERENCE) in leaders:
        majority = values[REFERENCE]
    else:
        return sorted(values)
    return sorted(name for name, value in values.items() if value != majority)


def compare_results(results: Dict[str, Result]) -> List[FieldDivergence]:
    """Return every field on which the given tool results disagree."""
    divergences: List[FieldDivergence] = []
    for name in _COMPARED_FIELDS:
        values = {
            tool: str(getattr(result, name))
            for tool, result in results.items()
            if getattr(result, name, None) is not None
        }
        if len(values) == len(results) and len(set(values.values())) > 1:
            divergences.append(
                FieldDivergence(name, values, _minority(values))
            )

    rejected = {
        tool: str(sorted(int(r.index) for r in result.rejected_transactions))
        for tool, result in results.items()
    }
    if len(set(rejected.values())) > 1:
        divergences.append(
            FieldDivergence(
                "rejected_transactions", rejected, _minority(rejected)
            )
        )
    return divergences


ToolRuns = Tuple[Dict[str, Result], Dict[str, str], Dict[str, Alloc]]


def run_tools(
    tools: Dict[str, Any], case: FuzzerOutput, fork: Fork
) -> ToolRuns:
    """
    Run ``case`` through each tool, collecting results, failures, and the
    post-state each tool produced.
    """
    prepared = _prepare(case, fork)
    results: Dict[str, Result] = {}
    errors: Dict[str, str] = {}
    allocs: Dict[str, Alloc] = {}
    for name, tool in tools.items():
        try:
            results[name], alloc = _transition(tool, prepared)
        except Exception as exc:  # noqa: BLE001
            errors[name] = f"{type(exc).__name__}: {exc}"
            continue
        if alloc is not None:
            allocs[name] = alloc
    return results, errors, allocs


def post_state_diff(
    divergences: List[FieldDivergence], allocs: Dict[str, Alloc]
) -> Dict[str, Dict[str, Any]]:
    """For each minority tool, the accounts on which it differs from EELS."""
    reference = allocs.get(REFERENCE)
    if reference is None:
        return {}
    diffs: Dict[str, Dict[str, Any]] = {}
    for divergence in divergences:
        for tool in divergence.minority:
            if tool == REFERENCE or tool in diffs or tool not in allocs:
                continue
            diffs[tool] = (
                allocs[tool].calculate_diff(reference).model_dump(mode="json")
            )
    return diffs


def _agree(results: Dict[str, Result], errors: Dict[str, str]) -> bool:
    """Whether a set of tool runs is unanimous (all fail, or none differ)."""
    if errors:
        return not results
    return not compare_results(results)


def evaluate_case(
    tools: Dict[str, Any],
    case: FuzzerOutput,
    fork: Fork,
    *,
    tiered: bool = False,
) -> CaseOutcome:
    """
    Run ``case`` through the tools and classify the outcome.

    A tool raising where another succeeds is a divergence in itself (one
    rejected the block, the other accepted it); every tool raising is
    agreement that the input is invalid.

    ``tiered`` runs the native clients first and consults the reference
    only when they disagree: EELS is the slowest tool by far, and unanimous
    clients need no adjudication. With fewer than two clients there is
    nothing to compare natively, so the reference always runs.
    """
    clients = {name: tool for name, tool in tools.items() if name != REFERENCE}
    if tiered and REFERENCE in tools and len(clients) > 1:
        results, errors, allocs = run_tools(clients, case, fork)
        if _agree(results, errors):
            return CaseOutcome(
                seed=-1,
                tool_count=len(clients),
                errors=errors,
                eels_ran=False,
            )
        reference, reference_error, reference_alloc = run_tools(
            {REFERENCE: tools[REFERENCE]}, case, fork
        )
        results.update(reference)
        errors.update(reference_error)
        allocs.update(reference_alloc)
    else:
        results, errors, allocs = run_tools(tools, case, fork)

    outcome = CaseOutcome(
        seed=-1,
        tool_count=len(tools),
        errors=errors,
        eels_ran=REFERENCE in tools,
    )
    if len(results) > 1:
        outcome.divergences = compare_results(results)
        outcome.post_state_diff = post_state_diff(outcome.divergences, allocs)
    return outcome


Signature = Set[Tuple[str, Tuple[str, ...]]]


def divergence_signature(outcome: CaseOutcome) -> Signature:
    """
    The (field, minority) pairs that identify *which* bug a case shows.

    Minimization must preserve this, not merely "still diverges": a
    reduction can otherwise drift onto an unrelated divergence.
    """
    signature: Signature = {
        (d.field, tuple(d.minority)) for d in outcome.divergences
    }
    if outcome.asymmetric_failure:
        signature.add(("failure", tuple(sorted(outcome.errors))))
    return signature


def still_diverges(
    tools: Dict[str, Any],
    case: FuzzerOutput,
    *,
    fork: Fork,
    signature: Signature,
    tiered: bool = False,
) -> bool:
    """Minimization predicate: the reduced case shows the same bug."""
    outcome = evaluate_case(tools, case, fork, tiered=tiered)
    return signature <= divergence_signature(outcome)


def build_client_tool(path: Path) -> TransitionTool:
    """Detect the client behind ``path`` and wrap its ``t8n``."""
    tool: TransitionTool = TransitionTool.from_binary_path(binary_path=path)
    return tool


def build_tools(clients: Dict[str, Path]) -> Dict[str, TransitionTool]:
    """Build the reference tool plus one tool per named client binary."""
    tools: Dict[str, TransitionTool] = {
        REFERENCE: ExecutionSpecsTransitionTool()
    }
    for name, path in clients.items():
        tools[name] = build_client_tool(path)
    return tools


# Per-worker tool state, built once by the pool initializer. Building the
# tools is not free, so workers reuse them across seeds.
_WORKER: Dict[str, Any] = {}


def _init_worker(
    fork_name: str, clients: Dict[str, str], tiered: bool
) -> None:
    """Build the per-process tools for the differential pool."""
    _WORKER["fork"] = _fork_by_name(fork_name)
    _WORKER["tools"] = build_tools(
        {name: Path(path) for name, path in clients.items()}
    )
    _WORKER["tiered"] = tiered


def _detect_in_worker(seed: int) -> CaseOutcome:
    """Evaluate one seed using the worker's tools (runs in a subprocess)."""
    fork = _WORKER["fork"]
    outcome = evaluate_case(
        _WORKER["tools"],
        generate_fuzzer_output(fork, seed),
        fork,
        tiered=_WORKER["tiered"],
    )
    outcome.seed = seed
    return outcome


def differential_fuzz(
    fork: Fork,
    seeds: range,
    *,
    clients: Dict[str, Path],
    corpus_dir: Optional[Path] = None,
    minimize_cases: bool = True,
    workers: int = 1,
    baseline_seeds: int = 0,
    manifest_path: Optional[Path] = None,
    tiered: bool = False,
) -> DifferentialReport:
    """
    Fuzz ``fork`` across ``seeds``, comparing EELS against every client.

    With ``baseline_seeds > 0`` every client must first agree with EELS on
    that many fixed seeds (see ``baseline``), which keeps a stale client
    from producing a run of false divergences. Each seed is independent,
    so ``workers > 1`` runs them across processes (each building its own
    tools once). Output order is deterministic regardless of worker count.
    Divergent cases are saved to ``corpus_dir``, minimized when requested
    (minimization runs in the main process). ``tiered`` lets unanimous
    clients skip the reference (see ``evaluate_case``).
    """
    from .baseline import BASELINE_SEED_START, check_baseline
    from .run_manifest import collect_manifest

    tools = build_tools(clients)
    report = DifferentialReport(
        fork=fork.name(),
        generator_version=GENERATOR_VERSION,
        clients=sorted(clients),
        seeds=len(seeds),
        agreed=0,
        diverged=0,
    )
    report.manifest = collect_manifest(fork, tools, seeds)
    if manifest_path is not None:
        report.manifest.write(manifest_path)
    if baseline_seeds > 0:
        report.baseline = check_baseline(
            fork,
            tools,
            range(BASELINE_SEED_START, BASELINE_SEED_START + baseline_seeds),
        )

    if workers > 1:
        with ProcessPoolExecutor(
            max_workers=workers,
            initializer=_init_worker,
            initargs=(
                fork.name(),
                {name: str(path) for name, path in clients.items()},
                tiered,
            ),
        ) as executor:
            outcomes = list(executor.map(_detect_in_worker, seeds))
    else:
        outcomes = []
        for seed in seeds:
            outcome = evaluate_case(
                tools, generate_fuzzer_output(fork, seed), fork, tiered=tiered
            )
            outcome.seed = seed
            outcomes.append(outcome)

    for outcome in outcomes:
        if outcome.diverged:
            report.diverged += 1
            if corpus_dir is not None:
                case = generate_fuzzer_output(fork, outcome.seed)
                signature = divergence_signature(outcome)
                if minimize_cases:
                    case = minimize(
                        case,
                        partial(
                            still_diverges,
                            tools,
                            fork=fork,
                            signature=signature,
                            tiered=tiered,
                        ),
                    )
                save_case(case, corpus_dir / corpus_name(fork, outcome))
        else:
            report.agreed += 1
        report.outcomes.append(outcome)

    return report


def corpus_name(fork: Fork, outcome: CaseOutcome) -> str:
    """File name carrying the seed and the first (field, minority) pair."""
    order = {name: i for i, name in enumerate(_COMPARED_FIELDS)}
    signature = sorted(
        divergence_signature(outcome),
        key=lambda pair: (order.get(pair[0], len(order)), pair),
    )
    tag = ""
    if signature:
        field_name, minority = signature[0]
        tag = f"_{field_name}_{'+'.join(minority)}"
    return f"{fork.name()}_divergence_seed{outcome.seed}{tag}.json"
