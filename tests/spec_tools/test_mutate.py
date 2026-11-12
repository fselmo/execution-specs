"""Tests for `ethereum-spec-mutate`'s operators, sampling and areas."""

import ast
from pathlib import Path
from typing import List

import pytest
from execution_testing.forks import Fork, get_forks

from ethereum_spec_tools.mutate.areas import AREAS
from ethereum_spec_tools.mutate.driver import (
    Baseline,
    Planned,
    fork_by_name,
    package_of,
    packages_before,
    plan,
    sample,
)
from ethereum_spec_tools.mutate.operators import (
    Mutant,
    apply,
    function_mutants,
    previous_fork_mutants,
    same_function,
)

ROOT = Path(__file__).parents[2]


def newest_fork() -> Fork:
    """The newest framework fork whose spec package is in `src/`."""
    for fork in reversed(get_forks()):
        try:
            package = package_of(fork)
        except Exception:  # noqa: BLE001 - a fork without its own package
            continue
        if (ROOT / "src/ethereum/forks" / package).is_dir():
            return fork
    raise AssertionError("no fork has a spec package")


SOURCE = '''
class GasCosts:
    WARM: int = 100
    COLD: int = 2600


def charge(evm: "Evm", amount: int) -> None:
    """Charge `amount`, or fail."""
    ensure(evm.gas_left >= amount, OutOfGasError)
    if not evm.running and amount > 0:
        raise OutOfGasError(f"short by {amount - evm.gas_left}")
    evm.gas_left -= amount
    charge_state(evm, GasCosts.COLD)
    evm.total = U256(evm.total).wrapping_add(U256(amount))
'''


def mutants_of(operator: str) -> List[Mutant]:
    """The mutants ``operator`` makes of `charge`."""
    return [
        m
        for m in function_mutants(
            "gas.py", SOURCE, ["charge"], {"GasCosts": ["WARM", "COLD"]}
        )
        if m.operator == operator
    ]


@pytest.mark.parametrize(
    "operator,original,mutated",
    [
        pytest.param(
            "compare",
            "evm.gas_left >= amount",
            "evm.gas_left > amount",
            id="compare",
        ),
        pytest.param(
            "drop-call",
            "ensure(evm.gas_left >= amount, OutOfGasError)",
            "pass",
            id="ensure",
        ),
        pytest.param(
            "drop-update",
            "evm.gas_left -= amount",
            "pass",
            id="drop-update",
        ),
        pytest.param(
            "drop-guard",
            "not evm.running and amount > 0",
            "False",
            id="if-raise",
        ),
        pytest.param(
            "drop-operand",
            "not evm.running and amount > 0",
            "amount > 0",
            id="drop-operand",
        ),
        pytest.param(
            "drop-call",
            "charge_state(evm, GasCosts.COLD)",
            "pass",
            id="state-call",
        ),
        pytest.param(
            "gas-constant",
            "GasCosts.COLD",
            "GasCosts.WARM",
            id="gas-constant",
        ),
        pytest.param(
            "wrapping",
            "U256(evm.total).wrapping_add(U256(amount))",
            "U256(evm.total) + U256(amount)",
            id="checked",
        ),
    ],
)
def test_operator_makes_the_edit(
    operator: str, original: str, mutated: str
) -> None:
    """Each EELS operator makes the edit it names, and it applies cleanly."""
    found = [
        m
        for m in mutants_of(operator)
        if m.original == original and m.mutated == mutated
    ]
    assert len(found) == 1
    edited = apply(SOURCE, found[0])
    assert mutated in edited and edited != SOURCE
    ast.parse(edited)


def test_a_nested_edit_keeps_its_meaning() -> None:
    """
    An operator expression spliced into a tighter-binding parent gets
    parentheses, so `a - b * c` becomes `a - (b + c)`, not `a - b + c`.
    """
    source = "def f(a, b, c):\n    return a - b * c\n"
    (mutant,) = [
        m
        for m in function_mutants("f.py", source, ["f"])
        if m.original == "b * c" and "+" in m.mutated
    ]
    assert "a - (b + c)" in apply(source, mutant)
    assert mutant.construct == "f: b * c -> b + c"


def test_a_loop_is_skipped() -> None:
    """A `for` loop over nothing and a `while` that never runs."""
    source = (
        "def f(xs):\n    for x in xs:\n        g(x)\n"
        "    while xs:\n        xs.pop()\n"
    )
    skipped = {
        (m.original, m.mutated)
        for m in function_mutants("f.py", source, ["f"])
        if m.operator == "skip-loop"
    }
    assert skipped == {("xs", "()"), ("xs", "False")}


def test_a_mutant_on_an_unexecuted_line_is_not_reached() -> None:
    """The baseline's coverage decides which mutants are worth running."""
    (first, *_) = mutants_of("compare")
    reached = Baseline(1.0, {"gas.py": {first.lineno}})
    assert reached.reaches(first)
    assert not Baseline(1.0, {"gas.py": {first.lineno + 50}}).reaches(first)
    assert not Baseline(1.0, {}).reaches(first)


@pytest.mark.parametrize("area", sorted(AREAS))
def test_every_note_names_a_mutant_the_area_still_has(area: str) -> None:
    """A note on an edit the spec no longer has is stale."""
    constructs = {
        p.mutant.construct for p in plan(ROOT, newest_fork(), [area])
    }
    assert set(AREAS[area].notes) <= constructs


def test_no_mutant_in_docstrings_annotations_or_fstrings() -> None:
    """Edits that cannot change behavior are never made."""
    for mutant in function_mutants("gas.py", SOURCE, ["charge"]):
        assert "short by" not in mutant.original
        assert "Charge" not in mutant.original
        assert mutant.original not in ('"Evm"', "int", "None")


def test_only_matched_functions_are_mutated() -> None:
    """A mutant outside the area's functions measures nothing."""
    assert function_mutants("gas.py", SOURCE, ["other"]) == []
    assert {
        m.function for m in function_mutants("gas.py", SOURCE, ["ch*"])
    } == {"charge"}


def test_previous_fork_body_replaces_a_changed_function() -> None:
    """A function a fork changed is replaced whole by its old body."""
    before = SOURCE.replace("evm.gas_left -= amount", "evm.gas_left -= 2")
    (mutant,) = previous_fork_mutants("gas.py", SOURCE, before, ["charge"])
    assert "evm.gas_left -= 2" in apply(SOURCE, mutant)
    assert previous_fork_mutants("gas.py", SOURCE, SOURCE, ["charge"]) == []


def test_same_function_ignores_docstrings() -> None:
    """Identical code with another docstring is the same function."""
    a = ast.parse("def f():\n    '''a'''\n    return 1\n").body[0]
    b = ast.parse("def f():\n    '''b'''\n    return 1\n").body[0]
    c = ast.parse("def f():\n    return 2\n").body[0]
    assert same_function(a, b)
    assert not same_function(a, c)


def test_a_sample_does_not_depend_on_other_areas() -> None:
    """An area's sample is the same whatever else the run includes."""
    fork = newest_fork()
    alone = sample(plan(ROOT, fork, ["signatures"]), 5, 0)
    together: List[Planned] = [
        p
        for p in sample(plan(ROOT, fork, ["gas-meter", "signatures"]), 5, 0)
        if p.area == "signatures"
    ]
    assert [p.mutant.ident for p in alone] == [
        p.mutant.ident for p in together
    ]


@pytest.mark.parametrize("area", sorted(AREAS))
def test_every_area_names_functions_the_fork_has(area: str) -> None:
    """Each area plans mutants at the newest fork with a spec package."""
    assert plan(ROOT, newest_fork(), [area])


def test_previous_fork_skips_shared_packages() -> None:
    """The fork before is the newest earlier fork with its own package."""
    before = packages_before(fork_by_name("Osaka"))
    assert before[0] == "prague"
