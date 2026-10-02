"""
The block access list checked against an independent witness of execution.

The list is built from the state tracker's own read and write sets, so
checking it against those sets tests the encoder, not the tracker. The
witness is collected from the trace stream instead -- a different code
path -- which is the only way an access the tracker forgot shows up as a
disagreement rather than as a matching absence on both sides. These pin
the relation and its wiring into the fill-time invariants; the fuzzer
checks it on generated cases.
"""

from execution_testing.evm_tools.t8n.evm_trace.bal_witness import (
    BalWitness,
    bal_slots,
)


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
