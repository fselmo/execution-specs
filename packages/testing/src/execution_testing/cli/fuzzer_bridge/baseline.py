"""
Baseline gate: refuse to fuzz against a client that is out of date.

A client built before the spec's latest change disagrees with EELS on
almost every case, and a run against it is a wall of false divergences.
Before a campaign, every client is compared with EELS on a fixed set of
seeds disjoint from any campaign; a client that disagrees on any of them
stops the run and is named, with the count.
"""

from typing import Any, Dict

from execution_testing.forks import Fork

from .differential import REFERENCE, CaseOutcome, evaluate_case
from .generator import generate_fuzzer_output

BASELINE_SEED_START = 1_000_000_000
"""Baseline seeds live far above any campaign's, so they never overlap."""


class StaleClientError(Exception):
    """One or more clients disagree with EELS on the baseline seeds."""

    def __init__(self, stale: Dict[str, int], seeds: int) -> None:
        self.stale = stale
        self.seeds = seeds
        detail = ", ".join(
            f"{name}: {count}/{seeds}" for name, count in sorted(stale.items())
        )
        super().__init__(
            f"stale clients (disagree with EELS on baseline seeds): {detail}"
        )


def _disagrees_with_reference(outcome: CaseOutcome, client: str) -> bool:
    if client in outcome.errors:
        return REFERENCE not in outcome.errors
    return any(
        d.values.get(client) != d.values.get(REFERENCE)
        for d in outcome.divergences
        if client in d.values and REFERENCE in d.values
    )


def check_baseline(
    fork: Fork, tools: Dict[str, Any], seeds: range
) -> Dict[str, int]:
    """
    Compare every client with EELS on ``seeds``; raise if any disagrees.

    Returns the per-client disagreement counts (all zero) on success.
    """
    counts = {name: 0 for name in tools if name != REFERENCE}
    for seed in seeds:
        outcome = evaluate_case(
            tools, generate_fuzzer_output(fork, seed), fork
        )
        for name in counts:
            if _disagrees_with_reference(outcome, name):
                counts[name] += 1
    stale = {name: count for name, count in counts.items() if count}
    if stale:
        raise StaleClientError(stale, len(seeds))
    return counts
