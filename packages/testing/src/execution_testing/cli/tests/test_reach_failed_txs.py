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
