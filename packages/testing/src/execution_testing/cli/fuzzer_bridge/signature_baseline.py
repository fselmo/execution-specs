"""
Measure execution-signature novelty on the current generator.

This is the baseline the future corpus-growth scheduler is judged against:
before a corpus lane exists, fill a seed range serially, fold each case's
signature into a running set-union, and report how many cases were novel. A
signal only earns its keep if novelty-guided growth later beats this
fresh-seed-only curve at equal budget.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Set, Tuple

if TYPE_CHECKING:
    from execution_testing.evm_tools.t8n.evm_trace.signature import Signature
    from execution_testing.forks import Fork


class NoveltyTracker:
    """Promote a case as novel when it extends any signature layer."""

    def __init__(self) -> None:
        self._frames: Set[Tuple[int, str, str]] = set()
        self._events: Set[str] = set()
        self._bigrams: Set[Tuple[str, str]] = set()

    def observe(self, signature: "Signature") -> bool:
        """Fold a signature in; return whether any layer grew (set-union)."""
        before = len(self._frames) + len(self._events) + len(self._bigrams)
        self._frames |= signature.frames
        self._events |= signature.events
        self._bigrams |= signature.bigrams
        after = len(self._frames) + len(self._events) + len(self._bigrams)
        return after > before

    def counts(self) -> Tuple[int, int, int]:
        """Return the distinct (frames, events, bigrams) totals seen."""
        return len(self._frames), len(self._events), len(self._bigrams)


@dataclass
class BaselineReport:
    """Novelty statistics for a seed range on the current generator."""

    seeds: int
    novel: int
    frames: int
    events: int
    bigrams: int
    max_depth: int

    def summary(self) -> str:
        """Render the report as one line."""
        return (
            f"novel {self.novel}/{self.seeds}; "
            f"distinct frames={self.frames} events={self.events} "
            f"bigrams={self.bigrams}; max depth {self.max_depth}"
        )


def signature_baseline(fork: "Fork", seeds: range) -> BaselineReport:
    """Fill each seed serially and measure signature novelty (set-union)."""
    from execution_testing.cli.fuzzer_bridge.campaign import fill_case
    from execution_testing.cli.fuzzer_bridge.generator import (
        generate_fuzzer_output,
    )
    from execution_testing.client_clis.clis.execution_specs import (
        ExecutionSpecsTransitionTool,
    )

    eels = ExecutionSpecsTransitionTool()
    eels.compute_signature = True
    tracker = NoveltyTracker()
    novel = 0
    max_depth = 0
    for seed in seeds:
        eels.last_signature = None
        fill_case(generate_fuzzer_output(fork, seed), fork, eels)
        signature = eels.last_signature
        if signature is not None:
            max_depth = max(max_depth, signature.max_depth)
            if tracker.observe(signature):
                novel += 1
    frames, events, bigrams = tracker.counts()
    return BaselineReport(
        len(seeds), novel, frames, events, bigrams, max_depth
    )
