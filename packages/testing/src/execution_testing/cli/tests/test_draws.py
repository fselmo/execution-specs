"""
Recorded draws: a case replays from its tree, and a focused run moves
only what it varies.
"""

from pathlib import Path
from typing import Any, Dict, List

import pytest

from execution_testing.forks import Amsterdam
from execution_testing.fuzzing.draws import (
    PARAM,
    STRUCTURAL,
    DrawError,
    DrawTree,
    Plan,
    compare,
    focus_plan,
)

from ..fuzzer_bridge.campaign import signature_id
from ..fuzzer_bridge.focus import focus, triage
from ..fuzzer_bridge.generator import record_case
from ..fuzzer_bridge.runners import Verdict


def _seed_with(**wanted: Any) -> int:
    """The first seed whose tree holds every label at the value given."""
    for seed in range(500):
        values = record_case(Amsterdam, seed)[1].values()
        if all(values.get(k) == v for k, v in wanted.items()):
            return seed
    raise AssertionError(f"no seed below 500 draws {wanted}")


def test_a_recorded_tree_replays_byte_identically() -> None:
    """Replaying a tree's values, through its file, gives the same case."""
    for seed in range(200):
        case, tree = record_case(Amsterdam, seed)
        back = DrawTree.from_json(tree.to_json())
        replayed, again = record_case(
            Amsterdam, seed, plan=Plan(values=back.values())
        )
        assert replayed.model_dump_json() == case.model_dump_json(), seed
        assert again.values() == tree.values()


def test_varying_one_param_moves_only_that_label() -> None:
    """
    Each draw is seeded by its label alone, so resampling one param
    leaves every other label's value where it was.
    """
    for seed in range(100):
        _, tree = record_case(Amsterdam, seed)
        params = [d.label for d in tree.draws if d.kind == PARAM]
        label = params[seed % len(params)]
        plan = focus_plan(tree, vary=[label], salt=1)
        _, varied = record_case(Amsterdam, seed, plan=plan)
        changed, _, _ = compare(tree, varied)
        assert set(changed) <= {label}, (seed, label, changed)


def test_a_sender_varied_keeps_every_pick_of_it() -> None:
    """
    A pick among senders is recorded by position, so varying a sender's
    key changes its address and every transaction still names it.
    """
    case, tree = record_case(Amsterdam, 0)
    plan = focus_plan(tree, vary=["sender:0/key"], salt=1)
    varied_case, varied = record_case(Amsterdam, 0, plan=plan)
    assert compare(tree, varied)[0] == ["sender:0/key"]
    before = [str(tx.from_) for tx in case.transactions]
    after = [str(tx.from_) for tx in varied_case.transactions]
    # Senders are the first accounts in the pre-state.
    old, new = str(list(case.accounts)[0]), str(list(varied_case.accounts)[0])
    assert old != new and old in before
    assert after == [new if s == old else s for s in before]


def test_varying_a_structural_label_redraws_what_it_decides() -> None:
    """
    The near-full block's fill decides which labels exist beneath it:
    varying it draws those again, and pinning one of them is refused.
    """
    seed = _seed_with(**{"near_full": True, "near_full/fill": "execution"})
    _, tree = record_case(Amsterdam, seed)
    assert tree.kinds()["near_full/fill"] == STRUCTURAL
    plan = focus_plan(tree, vary=["near_full/fill"])
    assert "near_full/fill:execution/left" not in plan.values
    with pytest.raises(DrawError, match="pinned beneath near_full/fill"):
        focus_plan(
            tree,
            vary=["near_full/fill"],
            pin=["near_full/fill:execution/left"],
        )


def test_vary_alone_pins_everything_else() -> None:
    """Every recorded label but the varied one is held to its value."""
    _, tree = record_case(Amsterdam, 3)
    plan = focus_plan(tree, vary=["tx:0/value"])
    assert set(plan.values) == set(tree.values()) - {"tx:0/value"}


def test_a_set_is_checked_against_the_type_not_the_sampling_range() -> None:
    """
    The margin is sampled from 0 and 1, but any non-negative gas is a
    valid margin; a negative one is refused before anything fills.
    """
    seed = _seed_with(**{"near_full": True})
    _, tree = record_case(Amsterdam, seed)
    report = focus(
        Amsterdam,
        tree,
        sets={"near_full/margin": 7},
        fill_cases=False,
    )
    (run,) = report.variants
    assert run.error == "" and run.varied == {"near_full/margin": 7}
    with pytest.raises(DrawError, match="outside its domain"):
        focus(Amsterdam, tree, sets={"near_full/margin": -5}, fill_cases=False)
    with pytest.raises(DrawError, match="no label"):
        focus_plan(tree, vary=["tx:99/gas"])


def test_an_unfillable_run_is_reported_not_dropped() -> None:
    """
    A block gas limit below the transactions' gas cannot fill: the run is
    reported with its error, next to what was set.
    """
    _, tree = record_case(Amsterdam, 3)
    report = focus(Amsterdam, tree, sets={"env/block_gas_limit": 30_000})
    (run,) = report.variants
    assert run.error
    assert "set: env/block_gas_limit=30000" in report.render()


def test_triage_narrows_a_finding_to_the_label_it_needs(
    tmp_path: Path,
) -> None:
    """
    A client that fails every block expected rejected: varying the
    near-full margin away from one loses the finding, and varying a
    transaction's value keeps it every time.
    """
    seed = _seed_with(**{"near_full": True, "near_full/margin": 1})
    target = signature_id(("geth", "boom"))

    def judge(path: Path, names: List[str]) -> Dict[str, Any]:
        import json

        fixtures = json.loads(path.read_text())
        verdicts: Dict[str, Dict[str, Verdict]] = {"geth": {}, "erigon": {}}
        for name in names:
            rejects = any(
                "expectException" in b for b in fixtures[name]["blocks"]
            )
            verdicts["geth"][name] = Verdict(not rejects, "boom")
            verdicts["erigon"][name] = Verdict(True)
        return verdicts

    outcomes = {
        o.label: o
        for o in triage(
            Amsterdam,
            seed,
            target,
            judge,
            runs=4,
            labels=["near_full/margin", "tx:0/value"],
            workdir=tmp_path,
        )
    }
    assert outcomes["near_full/margin"].lost >= 1
    assert outcomes["near_full/margin"].kept == 0
    assert outcomes["tx:0/value"].kept == 4
    assert outcomes["tx:0/value"].lost == 0


def test_a_call_in_contract_code_has_its_own_labels() -> None:
    """
    A message call in a contract body records its kind, value, target and
    gas; varying the kind leaves the value where it was, so triage can
    tell them apart.
    """
    for seed in range(50):
        _, tree = record_case(Amsterdam, seed)
        kinds = [
            d.label
            for d in tree.draws
            if d.label.startswith("contract:")
            and d.label.endswith("/motif:message_call/kind")
        ]
        if kinds:
            break
    (kind, *_) = kinds
    call = kind.rsplit("/", 1)[0]
    values = tree.values()
    for name in ("value", "target", "gas", "size", "data"):
        assert f"{call}/{name}" in values
    _, varied = record_case(
        Amsterdam, seed, plan=focus_plan(tree, vary=[kind], salt=2)
    )
    changed = compare(tree, varied)[0]
    assert set(changed) <= {kind}
