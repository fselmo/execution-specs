"""
The block access list against an independent observation of execution.

The list is built from the state tracker's own read and write sets, so
checking it against those sets tests the encoder, not the tracker. These
check it against accesses observed on the trace stream instead -- a
different code path -- which is the only way an access the tracker forgot
shows up as a disagreement rather than as a matching absence on both
sides.

That failure is invisible to every cross-client comparison in the
framework: a client faithful to the reference reproduces the omission,
and the campaign records agreement.
"""

from typing import Any, Dict, List, Tuple

import pytest
from execution_testing.cli.fuzzer_bridge.campaign import fill_case
from execution_testing.cli.fuzzer_bridge.generator import (
    generate_fuzzer_output,
)
from execution_testing.client_clis.clis.execution_specs import (
    ExecutionSpecsTransitionTool,
)
from execution_testing.evm_tools.t8n.evm_trace.bal_witness import (
    BalWitness,
    bal_slots,
    check_bal_against_witness,
)
from execution_testing.forks import Amsterdam

SEEDS = range(9000, 9010)


@pytest.fixture(scope="module")
def runs() -> List[Tuple[int, BalWitness, List[Dict[str, Any]]]]:
    """Fill a few generated cases, keeping each one's witness and blocks."""
    collected: List[Tuple[int, BalWitness, List[Dict[str, Any]]]] = []
    for seed in SEEDS:
        eels = ExecutionSpecsTransitionTool()
        eels.compute_bal_witness = True
        eels.last_bal_witness = None
        try:
            fixture = fill_case(
                generate_fuzzer_output(Amsterdam, seed), Amsterdam, eels
            )
        except Exception:  # noqa: BLE001 - an unfillable case is not the subject
            continue
        assert eels.last_bal_witness is not None
        collected.append((seed, eels.last_bal_witness, fixture["blocks"]))
    assert collected, "no case filled; the rest of this module proves nothing"
    return collected


def test_the_witness_observes_something(
    runs: List[Tuple[int, BalWitness, List[Dict[str, Any]]]],
) -> None:
    """
    An empty witness would satisfy every relation below vacuously, so the
    observations are asserted non-empty before anything is concluded from
    them, and `ended` must sit inside `started` by construction.
    """
    assert any(witness.started for _, witness, _ in runs)
    assert any(witness.ended for _, witness, _ in runs)
    for seed, witness, _ in runs:
        assert witness.ended <= witness.started, seed


def test_the_bal_sits_inside_the_observed_bracket(
    runs: List[Tuple[int, BalWitness, List[Dict[str, Any]]]],
) -> None:
    """
    `ended <= BAL <= started` on real executions.

    The stream carries no event at the access itself, so an op that dies
    on its gas gate is observed and never accesses, while one that dies on
    its state charge accesses and is not observed as completing. The two
    rules bracket the truth rather than hitting it.
    """
    for seed, witness, blocks in runs:
        assert not check_bal_against_witness(witness, blocks), seed


def test_a_dropped_access_is_caught(
    runs: List[Tuple[int, BalWitness, List[Dict[str, Any]]]],
) -> None:
    """
    Kill check, lower bound: a list that omits a completed access must be
    reported. This is the tracker-forgot-an-access failure.
    """
    seed, witness, blocks = next(
        (s, w, b) for s, w, b in runs if w.ended & bal_slots(b)
    )
    victim = sorted(witness.ended & bal_slots(blocks))[0]
    pruned = _without_slot(blocks, victim)
    assert bal_slots(pruned) == bal_slots(blocks) - {victim}, seed

    found = check_bal_against_witness(witness, pruned)
    assert any("absent" in d.kind for d in found)
    assert victim in next(d for d in found if "absent" in d.kind).slots


def test_an_invented_access_is_caught(
    runs: List[Tuple[int, BalWitness, List[Dict[str, Any]]]],
) -> None:
    """
    Kill check, upper bound: a list naming a slot execution never touched
    must be reported.
    """
    _, witness, blocks = runs[0]
    invented = (0xDEAD, 0xBEEF)
    assert invented not in witness.started
    fabricated = [dict(block) for block in blocks]
    fabricated[0] = dict(fabricated[0])
    fabricated[0]["blockAccessList"] = [
        *(fabricated[0].get("blockAccessList") or []),
        {
            "address": f"{invented[0]:#042x}",
            "nonceChanges": [],
            "balanceChanges": [],
            "codeChanges": [],
            "storageChanges": [],
            "storageReads": [f"{invented[1]:#x}"],
        },
    ]
    found = check_bal_against_witness(witness, fabricated)
    assert any("never accessed" in d.kind for d in found)


def test_an_entry_with_empty_lists_hides_nothing() -> None:
    """
    Emptiness is not absence.

    An account can appear in the list with every change list empty, so the
    collection walks entries rather than non-empty lists -- otherwise a
    slot recorded beside an empty sibling list would be skipped and a
    dropped access would read as agreement.
    """
    blocks = [
        {
            "blockAccessList": [
                {
                    "address": f"{0x1234:#042x}",
                    "nonceChanges": [],
                    "balanceChanges": [],
                    "codeChanges": [],
                    "storageChanges": [],
                    "storageReads": [],
                },
                {
                    "address": f"{0x5678:#042x}",
                    "storageChanges": [{"slot": "0x1", "postValue": "0x2"}],
                    "storageReads": [],
                },
                {
                    "address": f"{0x9ABC:#042x}",
                    "storageChanges": [],
                    "storageReads": ["0x3"],
                },
            ]
        }
    ]
    assert bal_slots(blocks) == {(0x5678, 0x1), (0x9ABC, 0x3)}


def _without_slot(
    blocks: List[Dict[str, Any]], victim: Tuple[int, int]
) -> List[Dict[str, Any]]:
    """Copy `blocks` with one slot removed from the access list."""
    address, slot = victim
    out = []
    for block in blocks:
        entries = []
        for entry in block.get("blockAccessList", []) or []:
            if int(entry["address"], 16) != address:
                entries.append(entry)
                continue
            entry = dict(entry)
            entry["storageChanges"] = [
                change
                for change in entry.get("storageChanges", []) or []
                if int(change["slot"], 16) != slot
            ]
            entry["storageReads"] = [
                read
                for read in entry.get("storageReads", []) or []
                if int(read, 16) != slot
            ]
            entries.append(entry)
        block = dict(block)
        block["blockAccessList"] = entries
        out.append(block)
    return out


def test_the_invariant_is_silent_without_a_witness() -> None:
    """
    Every transition tool but the reference one traces nothing, so the
    check must stand down rather than infer a violation from absence.
    """
    from execution_testing.specs.invariants import check_bal_access_witness

    assert check_bal_access_witness(None, None) == []
    assert check_bal_access_witness(BalWitness(), None) == []


def test_the_invariant_reports_both_directions() -> None:
    """The invariant layer surfaces each side of the relation."""
    from execution_testing.evm_tools.t8n.evm_trace.bal_witness import (
        check_bal_relation,
    )

    witness = BalWitness(
        started=frozenset({(1, 2), (3, 4)}), ended=frozenset({(1, 2)})
    )
    dropped = check_bal_relation(witness, frozenset())
    assert [d.kind for d in dropped] == ["accessed but absent from the BAL"]
    invented = check_bal_relation(witness, frozenset({(1, 2), (9, 9)}))
    assert [d.kind for d in invented] == ["in the BAL but never accessed"]


def test_the_check_is_wired_into_the_block_invariants() -> None:
    """
    An invariant that runs only when called is not a guard.

    The point of the witness is that it catches a spec-side access-list
    error on an ordinary fill, unprompted, so this pins that
    `check_block_invariants` actually runs it.
    """
    import inspect

    from execution_testing.specs import invariants

    source = inspect.getsource(invariants.check_block_invariants)
    assert "check_bal_access_witness" in source


def test_the_bracket_width_is_reported(
    runs: List[Tuple[int, BalWitness, List[Dict[str, Any]]]],
) -> None:
    """
    The gap between the two observations is the accesses that began and
    did not complete. Recorded per case rather than only passing or
    failing: a gap widening across generator versions means more accesses
    are dying on the state charge, which is reach on the EIP-8037 surface.
    """
    from execution_testing.evm_tools.t8n.evm_trace.bal_witness import (
        bracket_width,
    )

    for _, witness, _ in runs:
        assert bracket_width(witness) == len(witness.started - witness.ended)
    assert any(bracket_width(witness) for _, witness, _ in runs), (
        "no case had an incomplete access; the diagnostic is untested"
    )
