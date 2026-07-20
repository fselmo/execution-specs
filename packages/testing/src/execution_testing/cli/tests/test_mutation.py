"""Tests for spec mutation operators and verdict classification."""

import ast
import subprocess
from pathlib import Path
from typing import Any

from ..mutation import runner as runner_mod
from ..mutation.mutations import apply_mutant, enumerate_mutants
from ..mutation.runner import Oracle, Verdict, _classify, _run_oracle

SNIPPET = """\
def f(x, y):
    if x < y and y > 0:
        return x + y
    return not x
"""


def _completed(
    returncode: int, stdout: str = ""
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["fill"], returncode=returncode, stdout=stdout, stderr=""
    )


def test_enumerate_is_deterministic() -> None:
    """Enumeration yields the same mutants in the same order each call."""
    a = enumerate_mutants(SNIPPET)
    b = enumerate_mutants(SNIPPET)
    assert [m.description for m in a] == [m.description for m in b]


def test_enumerate_finds_expected_operators() -> None:
    """Comparison, arithmetic, boolean, and negation mutants are found."""
    ops = {m.operator for m in enumerate_mutants(SNIPPET)}
    assert {"compare", "binop", "boolop", "unary-not"} <= ops


def test_apply_produces_valid_python() -> None:
    """Every applied mutant re-parses as valid Python and differs."""
    for mutant in enumerate_mutants(SNIPPET):
        mutated = apply_mutant(SNIPPET, mutant)
        assert mutated != SNIPPET
        ast.parse(mutated)


def test_apply_is_localized() -> None:
    """Applying a mutant changes only the intended segment."""
    mutant = next(
        m for m in enumerate_mutants(SNIPPET) if m.original == "x < y"
    )
    mutated = apply_mutant(SNIPPET, mutant)
    assert mutant.mutated in mutated
    # The negation and addition elsewhere are untouched.
    assert "not x" in mutated
    assert "x + y" in mutated


def test_constants_are_opt_in() -> None:
    """Constant mutations only appear when requested."""
    without = enumerate_mutants(SNIPPET)
    with_consts = enumerate_mutants(SNIPPET, include_constants=True)
    assert len(with_consts) > len(without)
    assert any(m.operator.startswith("const") for m in with_consts)
    assert not any(m.operator.startswith("const") for m in without)


def test_classify_killed_by_tests() -> None:
    """A nonzero fill exit is a test kill."""
    assert _classify(_completed(1), 0) == Verdict.KILLED_TESTS


def test_classify_killed_by_timeout() -> None:
    """A timed-out fill (None) is a timeout kill."""
    assert _classify(None, 0) == Verdict.KILLED_TIMEOUT


def test_classify_killed_by_invariant_only() -> None:
    """A clean exit with new invariant warnings is an invariant-only kill."""
    process = _completed(0, "InvariantViolationWarning: ether_conservation")
    assert _classify(process, 0) == Verdict.KILLED_INVARIANT


def test_run_oracle_dispatches_by_oracle(monkeypatch: Any) -> None:
    """_run_oracle routes to the property runner or the fill runner."""
    monkeypatch.setattr(
        runner_mod, "_run_properties", lambda *_a, **_k: "PROPERTIES"
    )
    monkeypatch.setattr(runner_mod, "_run_fill", lambda *_a, **_k: "FILL")
    assert _run_oracle(Oracle.PROPERTIES, [], "", Path("."), 1) == "PROPERTIES"
    assert _run_oracle(Oracle.FILL, [], "Osaka", Path("."), 1) == "FILL"


def test_classify_survived() -> None:
    """A clean exit with no new invariant warnings is a survivor."""
    assert _classify(_completed(0, "273 passed"), 0) == Verdict.SURVIVED


def test_classify_ignores_baseline_invariants() -> None:
    """Warnings already present in the baseline do not count as a kill."""
    process = _completed(0, "InvariantViolationWarning: x")
    assert _classify(process, 1) == Verdict.SURVIVED
