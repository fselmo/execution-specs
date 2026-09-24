"""
Transactions that fail on purpose, witnessed by their effect.

A failed transaction rolls its writes back, but what it read and wrote
still merges into the block access list as reads. Each test sends a real
generated case's transaction to the failer and reads the outcome from the
fixture -- the receipt, the gas it used, its entry in the list, the
post-state -- rather than from the generator's declaration.
"""

import contextlib
import io
import random
import warnings
from dataclasses import replace
from typing import Any, Dict, List, Tuple

from execution_testing.base_types import Address, Bytes, HexNumber
from execution_testing.forks import Amsterdam
from execution_testing.fuzzing import fork_domains
from execution_testing.vm import Opcodes as Op

from ..fuzzer_bridge import campaign as mod
from ..fuzzer_bridge.density import axis_collapse_warnings, axis_coverage
from ..fuzzer_bridge.generator import (
    FAILER_ADDRESS,
    STATE_EXHAUSTER_ADDRESS,
    TOUCHER_ADDRESS,
    failer_code,
    generate_fuzzer_output,
)
from ..fuzzer_bridge.models import FuzzerAccountInput, FuzzerOutput

FAILER = Address(FAILER_ADDRESS)
SMALLEST_GAS = (
    Amsterdam.transaction_gas_limit_cap()
    or fork_domains(Amsterdam).block_gas_limit
) // 128
"""The smallest gas limit the generator draws, derived as it derives it.
The failer is built to reach its failure on it, so the tests use nothing
larger."""


def _failer(outcome: str) -> Tuple[bytes, Dict[HexNumber, HexNumber]]:
    """The generator's failer, drawn to end the given way."""
    domains = replace(
        fork_domains(Amsterdam), failing_tx_outcome_shares=((outcome, 1.0),)
    )
    return failer_code(random.Random(0), domains)


def _send_to_failer(code: bytes, storage: Dict) -> FuzzerOutput:
    """A generated case whose first transaction calls the given failer."""
    case = generate_fuzzer_output(Amsterdam, 0)
    accounts = dict(case.accounts)
    accounts[FAILER] = FuzzerAccountInput(
        balance=HexNumber(0),
        nonce=HexNumber(1),
        code=Bytes(code),
        storage=storage,
    )
    transactions = list(case.transactions)
    transactions[0] = transactions[0].model_copy(
        update={"to": FAILER, "gas": HexNumber(SMALLEST_GAS)}
    )
    return case.model_copy(
        update={"accounts": accounts, "transactions": transactions}
    )


def _fill(case: FuzzerOutput) -> Dict[str, Any]:
    mod._init_fill_worker("Amsterdam")
    fork, eels = mod._FILL["fork"], mod._FILL["eels"]
    eels.compute_signature = True
    eels.last_signature = None
    with contextlib.redirect_stdout(io.StringIO()):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return mod.fill_case(case, fork, eels)


def _failer_tx(fixture: Dict[str, Any]) -> Tuple[int, Dict, int]:
    """The failer transaction's block index, receipt and gas used."""
    (block, *_) = fixture["blocks"]
    previous = 0
    for position, (tx, receipt) in enumerate(
        zip(block["transactions"], block["receipts"], strict=True)
    ):
        cumulative = int(receipt["cumulativeGasUsed"], 16)
        if (tx.get("to") or "").lower() == str(FAILER).lower():
            return position + 1, receipt, cumulative - previous
        previous = cumulative
    raise AssertionError("the failer transaction is not in the first block")


def _failer_entry(fixture: Dict[str, Any]) -> Dict[str, Any]:
    (block, *_) = fixture["blocks"]
    return next(
        entry
        for entry in block["blockAccessList"]
        if entry["address"].lower() == str(FAILER).lower()
    )


def _slots(values: List[str]) -> set:
    return {int(value, 16) for value in values}


def _check_failed(outcome: str) -> None:
    code, storage = _failer(outcome)
    fixture = _fill(_send_to_failer(code, storage))
    _, receipt, gas_used = _failer_tx(fixture)
    assert not receipt["status"]
    # An exceptional halt forfeits all the gas; a REVERT returns the rest.
    # No failer write pays state gas, so nothing comes back on a halt.
    if outcome == "revert":
        assert gas_used < SMALLEST_GAS
    elif outcome == "exceptional_halt":
        assert gas_used == SMALLEST_GAS
    else:
        raise ValueError(f"unknown outcome {outcome!r}")

    entry = _failer_entry(fixture)
    assert _slots(entry["storageReads"]) == {int(k) for k in storage}
    assert entry["storageChanges"] == []
    assert entry["balanceChanges"] == []
    post = fixture["postState"][str(FAILER).lower()]
    assert {int(k, 16): int(v, 16) for k, v in post["storage"].items()} == {
        int(k): int(v) for k, v in storage.items()
    }


def test_a_reverted_transaction_leaves_its_accesses_as_reads() -> None:
    """
    The failer reverts: the receipt fails with gas returned, and every
    slot it read or wrote is in the list as a read, none as a change.
    """
    _check_failed("revert")


def test_a_halted_transaction_leaves_its_accesses_as_reads() -> None:
    """The same on an exceptional halt, which forfeits all its gas."""
    _check_failed("exceptional_halt")


def test_the_same_transaction_succeeding_keeps_its_writes() -> None:
    """
    The near-miss: the failer's code with its failure replaced by STOP.
    The written slots are changes at the transaction's own index and not
    reads, and the slots only read stay reads.
    """
    code, storage = _failer("revert")
    ending = bytes(Op.REVERT(0, 0))
    assert code.endswith(ending)
    fixture = _fill(_send_to_failer(code[: -len(ending)], storage))
    index, receipt, _ = _failer_tx(fixture)
    assert receipt["status"]

    pairs = len(storage) // 2
    reads, writes = set(range(pairs)), set(range(pairs, 2 * pairs))
    entry = _failer_entry(fixture)
    assert _slots(entry["storageReads"]) == reads
    changed = {int(change["slot"], 16) for change in entry["storageChanges"]}
    assert changed == writes
    for change in entry["storageChanges"]:
        (at,) = change["slotChanges"]
        assert int(at["blockAccessIndex"], 16) == index
        slot = int(change["slot"], 16)
        read_value = int(storage[HexNumber(slot - pairs)])
        assert int(at["postValue"], 16) == read_value + 1


def test_the_outcome_tally_matches_the_receipts() -> None:
    """
    The per-transaction outcome axis is read off the trace; the receipts
    are a different reader. Their success counts must agree, and the
    reverting failer must be counted as a revert.
    """
    code, storage = _failer("revert")
    fixture = _fill(_send_to_failer(code, storage))
    outcomes = dict(mod._FILL["eels"].last_signature.tx_outcomes)
    succeeded = sum(
        bool(receipt["status"])
        for block in fixture["blocks"]
        for receipt in block["receipts"]
    )
    assert outcomes.get("success", 0) == succeeded
    assert outcomes.get("revert", 0) >= 1


def test_every_failer_axis_keeps_all_its_values() -> None:
    """Presence and both failures stay above the collapse floor."""
    coverage = axis_coverage(Amsterdam, range(0, 400))
    warnings_ = [
        w
        for w in axis_collapse_warnings(coverage)
        if w.startswith(("failing_tx", "failer_outcome"))
    ]
    assert warnings_ == []


def test_only_the_succeeding_failer_commits_a_storage_write() -> None:
    """
    The committed-write count reads the fixture's list at each
    transaction's own index. The failer's index must carry no storage
    change when it fails and one when the same code succeeds.
    """
    from ..fuzzer_bridge.signature_baseline import (
        _indices_with_storage_changes,
    )

    code, storage = _failer("revert")
    failed = _fill(_send_to_failer(code, storage))
    index, _, _ = _failer_tx(failed)
    assert index not in _indices_with_storage_changes(failed["blocks"][0])

    ending = bytes(Op.REVERT(0, 0))
    succeeded = _fill(_send_to_failer(code[: -len(ending)], storage))
    index, _, _ = _failer_tx(succeeded)
    assert index in _indices_with_storage_changes(succeeded["blocks"][0])


TOUCHER = Address(TOUCHER_ADDRESS)
SHARED = Address(0x3F200)
"""A contract both transactions reach: the first pays it and bumps its
slot 0, the toucher reads its balance and calls it."""


def _shared_block(ending: bytes) -> FuzzerOutput:
    """
    A two-transaction block: the first pays `SHARED`, whose code adds one
    to its slot 0; the second runs a toucher that reads `SHARED`'s
    balance, calls it with one wei, reads and writes its own slot 0, and
    ends with `ending`.
    """
    case = generate_fuzzer_output(Amsterdam, 0)
    accounts = dict(case.accounts)
    accounts[SHARED] = FuzzerAccountInput(
        balance=HexNumber(0),
        nonce=HexNumber(1),
        code=Bytes(bytes(Op.SSTORE(0, Op.ADD(Op.SLOAD(0), 1)))),
        storage={HexNumber(0): HexNumber(5)},
    )
    toucher = (
        Op.POP(Op.BALANCE(Op.PUSH20(SHARED)))
        + Op.POP(Op.CALL(50_000, Op.PUSH20(SHARED), 1, 0, 0, 0, 0))
        + Op.POP(Op.SLOAD(0))
        + Op.SSTORE(1, 9)
    )
    accounts[TOUCHER] = FuzzerAccountInput(
        balance=HexNumber(1),
        nonce=HexNumber(1),
        code=Bytes(bytes(toucher) + ending),
        storage={HexNumber(0): HexNumber(3), HexNumber(1): HexNumber(4)},
    )
    first, second = case.transactions[:2]
    plain = {"authorization_list": None, "gas_need_fraction": None}
    transactions = [
        first.model_copy(
            update={
                **plain,
                "to": SHARED,
                "value": HexNumber(7),
                "data": b"",
                "gas": HexNumber(SMALLEST_GAS),
                "block": 0,
            }
        ),
        second.model_copy(
            update={
                **plain,
                "to": TOUCHER,
                "value": HexNumber(0),
                "data": b"",
                "gas": HexNumber(SMALLEST_GAS),
                "block": 0,
            }
        ),
    ]
    return case.model_copy(
        update={
            "accounts": accounts,
            "transactions": transactions,
            "block_count": 1,
            "withdrawals": [],
        }
    )


def _entry(fixture: Dict[str, Any], address: Address) -> Dict[str, Any]:
    (block,) = fixture["blocks"]
    return next(
        entry
        for entry in block["blockAccessList"]
        if entry["address"].lower() == str(address).lower()
    )


def _indices(changes: List[Dict[str, Any]]) -> List[int]:
    return [int(change["blockAccessIndex"], 16) for change in changes]


def test_a_failed_toucher_leaves_the_shared_entries_intact() -> None:
    """
    The toucher reverts after reading and calling an account the first
    transaction changed. That account keeps exactly the first
    transaction's changes, at index 1; nothing changes at the toucher's
    index 2; the toucher's own slots are reads.
    """
    fixture = _fill(_shared_block(bytes(Op.REVERT(0, 0))))
    (block,) = fixture["blocks"]
    assert [bool(r["status"]) for r in block["receipts"]] == [True, False]

    shared = _entry(fixture, SHARED)
    assert _indices(shared["balanceChanges"]) == [1]
    (slot,) = shared["storageChanges"]
    assert int(slot["slot"], 16) == 0
    assert _indices(slot["slotChanges"]) == [1]
    assert int(slot["slotChanges"][0]["postValue"], 16) == 6

    toucher = _entry(fixture, TOUCHER)
    assert _slots(toucher["storageReads"]) == {0, 1}
    assert toucher["storageChanges"] == []
    assert toucher["balanceChanges"] == []


def test_a_succeeding_toucher_adds_its_own_changes_at_its_index() -> None:
    """
    The near-miss: the same toucher ending in STOP. The shared account
    now changes at both indices, the call's wei and the second bump at 2.
    """
    fixture = _fill(_shared_block(bytes(Op.STOP)))
    shared = _entry(fixture, SHARED)
    assert _indices(shared["balanceChanges"]) == [1, 2]
    (slot,) = shared["storageChanges"]
    assert _indices(slot["slotChanges"]) == [1, 2]
    assert int(slot["slotChanges"][1]["postValue"], 16) == 7
    toucher = _entry(fixture, TOUCHER)
    assert _indices(toucher["balanceChanges"]) == [2]


def test_every_toucher_axis_keeps_all_its_values() -> None:
    """Presence, every touch kind and every target class stay drawn."""
    coverage = axis_coverage(Amsterdam, range(0, 400))
    warnings_ = [
        w for w in axis_collapse_warnings(coverage) if w.startswith("toucher")
    ]
    assert warnings_ == []


EXHAUSTER = Address(STATE_EXHAUSTER_ADDRESS)
STORE = Op.SSTORE(key_warm=False, original_value=0, new_value=1)
FINAL_SLOT = 2**255


def _exhaust(reservoir: int, stores: int) -> FuzzerOutput:
    """
    One transaction to the exhauster, funded `reservoir` above the cap,
    told to fill `stores` slots before it burns execution gas.
    """
    case = generate_fuzzer_output(Amsterdam, 0)
    cap = Amsterdam.transaction_gas_limit_cap()
    assert cap is not None
    (first, *_) = case.transactions
    tx = first.model_copy(
        update={
            "to": EXHAUSTER,
            "gas": HexNumber(cap + reservoir),
            "data": Bytes(stores.to_bytes(32, "big")),
            "value": HexNumber(0),
            "authorization_list": None,
            "gas_need_fraction": None,
            "block": 0,
        }
    )
    return case.model_copy(
        update={"transactions": [tx], "block_count": 1, "withdrawals": []}
    )


def _oog_kinds() -> Dict[str, int]:
    return dict(mod._FILL["eels"].last_signature.tx_oog)


def test_an_emptied_reservoir_runs_out_on_a_state_charge() -> None:
    """
    A reservoir of one store is emptied by the first write; the final
    write's state charge then exceeds what execution gas is left. The
    transaction fails, both slots are reads, and the tally blames a state
    charge in a reservoir-funded transaction.
    """
    fixture = _fill(_exhaust(STORE.state_cost(Amsterdam), 1))
    (block,) = fixture["blocks"]
    (receipt,) = block["receipts"]
    assert not receipt["status"]
    entry = _entry(fixture, EXHAUSTER)
    assert _slots(entry["storageReads"]) == {1, FINAL_SLOT}
    assert entry["storageChanges"] == []
    assert _oog_kinds() == {"state-reservoir": 1}


def test_one_more_store_of_reservoir_pays_for_the_final_write() -> None:
    """
    The near-miss by one input: a reservoir one store larger covers the
    final write's state charge, so the transaction succeeds and both
    writes are changes at its index.
    """
    fixture = _fill(_exhaust(2 * STORE.state_cost(Amsterdam), 1))
    (block,) = fixture["blocks"]
    (receipt,) = block["receipts"]
    assert receipt["status"]
    entry = _entry(fixture, EXHAUSTER)
    changed = {int(c["slot"], 16) for c in entry["storageChanges"]}
    assert changed == {1, FINAL_SLOT}
    assert _oog_kinds() == {}


def test_without_a_reservoir_it_is_a_state_charge_but_not_this_cell() -> None:
    """
    At the cap exactly there is no reservoir: the final write still runs
    out on its state charge, and the tally says so without the reservoir.
    """
    _fill(_exhaust(0, 0))
    assert _oog_kinds() == {"state": 1}


def test_every_state_exhaust_axis_keeps_all_its_values() -> None:
    """Presence and every reservoir size stay drawn."""
    coverage = axis_coverage(Amsterdam, range(0, 400))
    warnings_ = [
        w
        for w in axis_collapse_warnings(coverage)
        if w.startswith("state_exhaust")
    ]
    assert warnings_ == []
