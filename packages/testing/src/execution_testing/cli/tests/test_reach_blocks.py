"""
Cases that span several blocks, witnessed by their effect.

A case now carries its block count and which block each transaction was
drawn for. The tests read what the chain did from the fixture itself --
each block's header hash, each block's own access list, the post-state --
rather than from anything the generator or the observer claims.
"""

import contextlib
import io
import warnings
from typing import Any, Dict, List

from execution_testing.base_types import Address, HexNumber
from execution_testing.forks import Amsterdam
from execution_testing.fuzzing.strategies import blockhash_read

from ..fuzzer_bridge import campaign as mod
from ..fuzzer_bridge.density import axis_collapse_warnings, axis_coverage
from ..fuzzer_bridge.differential import FieldDivergence, compare_results
from ..fuzzer_bridge.generator import generate_fuzzer_output
from ..fuzzer_bridge.models import FuzzerAccountInput, FuzzerOutput

READER = Address(0x3F000)
"""Where the witness contract lives: outside every generated range."""


def _fill(case: FuzzerOutput) -> Dict[str, Any]:
    mod._init_fill_worker("Amsterdam")
    fork, eels = mod._FILL["fork"], mod._FILL["eels"]
    with contextlib.redirect_stdout(io.StringIO()):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return mod.fill_case(case, fork, eels)


def _multi_block_case() -> FuzzerOutput:
    """A generated case with a transaction in its second block."""
    for seed in range(200):
        case = generate_fuzzer_output(Amsterdam, seed)
        if case.block_count >= 2 and any(
            tx.block == 1 and tx.to is not None for tx in case.transactions
        ):
            return case
    raise AssertionError("no two-block case in range; widen the seeds")


def _hashes(fixture: Dict[str, Any]) -> List[str]:
    """Genesis then every block's hash, as the fixture records them."""
    return [fixture["genesisBlockHeader"]["hash"]] + [
        block["blockHeader"]["hash"] for block in fixture["blocks"]
    ]


def test_every_block_writes_its_parent_s_hash_into_history() -> None:
    """
    Each block's own access list carries, at index 0, a system contract
    storing the hash of that block's parent -- the case's own previous
    block from the second block on. One list per block, each recording
    its own write, is the per-block claim.
    """
    fixture = _fill(_multi_block_case())
    hashes = _hashes(fixture)
    system = {str(a).lower() for a in Amsterdam.system_contracts()}
    assert len(fixture["blocks"]) >= 2
    for number, block in enumerate(fixture["blocks"], start=1):
        parent = int(hashes[number - 1], 16)
        written = [
            int(change["postValue"], 16)
            for entry in block["blockAccessList"]
            if entry["address"].lower() in system
            for slot in entry["storageChanges"]
            for change in slot["slotChanges"]
            if int(change["blockAccessIndex"], 16) == 0
        ]
        assert parent in written, f"block {number} wrote no parent hash"


def test_blockhash_reads_a_block_the_case_produced() -> None:
    """
    The motif's positive and its near-misses on one real chain: from the
    second block, one back is the case's first block and two back is
    genesis, while the current block and one past the window read zero.
    The witness is the stored value against the hash the fixture records.
    """
    case = _multi_block_case()
    code = (
        blockhash_read(1, 0)
        + blockhash_read(2, 1)
        + blockhash_read(0, 2)
        + blockhash_read(257, 3)
    )
    accounts = dict(case.accounts)
    accounts[READER] = FuzzerAccountInput(balance=HexNumber(0), code=code)
    transactions = list(case.transactions)
    index = next(
        i
        for i, tx in enumerate(transactions)
        if tx.block == 1 and tx.to is not None
    )
    # Four stores into fresh slots pay state gas under EIP-8037; the gas
    # drawn for the transaction's original target does not cover them.
    transactions[index] = transactions[index].model_copy(
        update={"to": READER, "data": b"", "gas": HexNumber(2_000_000)}
    )
    fixture = _fill(
        case.model_copy(
            update={"accounts": accounts, "transactions": transactions}
        )
    )
    hashes = _hashes(fixture)
    post = {k.lower(): v for k, v in fixture["postState"].items()}
    storage = {
        int(slot, 16): int(value, 16)
        for slot, value in post[str(READER).lower()]["storage"].items()
    }
    assert storage[0] == int(hashes[1], 16)  # the case's first block
    assert storage[1] == int(hashes[0], 16)  # genesis
    assert storage.get(2, 0) == 0  # the current block reads zero
    assert storage.get(3, 0) == 0  # one past the window reads zero


def test_a_divergence_in_a_later_block_is_named_by_its_block() -> None:
    """
    The diff lane compares every block, and a later block's field carries
    its number, so a divergence the first block does not show is neither
    lost nor mistaken for one in the first block.
    """
    from types import SimpleNamespace

    def result(bal: str) -> Any:
        return SimpleNamespace(
            block_access_list_hash=bal, rejected_transactions=[]
        )

    divergences = compare_results(
        {
            "eels": [result("0xa"), result("0xb")],
            "geth": [result("0xa"), result("0xc")],
        }
    )
    assert [d.field for d in divergences] == ["block2.block_access_list_hash"]
    assert isinstance(divergences[0], FieldDivergence)


def test_every_block_axis_keeps_all_its_values() -> None:
    """Block count and BLOCKHASH reads stay above the collapse floor."""
    coverage = axis_coverage(Amsterdam, range(0, 400))
    warnings_ = [
        w
        for w in axis_collapse_warnings(coverage)
        if w.startswith(("block_count", "blockhash"))
    ]
    assert warnings_ == []


def _signature_of(case: FuzzerOutput) -> Any:
    """Fill ``case`` and return its execution signature."""
    # `_fill` builds a fresh tool, so read the signature off that one.
    _fill(case)
    return mod._FILL["eels"].last_signature


def _second_block_calls(case: FuzzerOutput, target: Address, code: Any) -> Any:
    """``case`` with its first block-2 transaction calling ``target``."""
    accounts = dict(case.accounts)
    if code is not None:
        accounts[target] = FuzzerAccountInput(balance=HexNumber(0), code=code)
    transactions = list(case.transactions)
    index = next(
        i
        for i, tx in enumerate(transactions)
        if tx.block == 1 and tx.to is not None
    )
    for i, tx in enumerate(transactions):
        if tx.block >= 1 and i != index:
            # Only the chosen transaction runs code after block 1, so the
            # event can only come from it.
            transactions[i] = tx.model_copy(
                update={"to": Address(0x3F001), "gas_need_fraction": None}
            )
    transactions[index] = transactions[index].model_copy(
        update={"to": target, "data": b"", "gas": HexNumber(2_000_000)}
    )
    return case.model_copy(
        update={"accounts": accounts, "transactions": transactions}
    )


def test_code_run_by_a_later_block_s_transaction_fires_the_event() -> None:
    """
    The positive, witnessed behaviourally: a block-2 transaction calls a
    contract, the event fires, and the post-state carries the store that
    contract made in block 2.
    """
    case = _second_block_calls(
        _multi_block_case(), READER, blockhash_read(1, 0)
    )
    signature = _signature_of(case)
    assert "later-block-code" in signature.events
    post = {k.lower(): v for k, v in _fill(case)["postState"].items()}
    assert post[str(READER).lower()]["storage"]


def test_system_code_in_a_later_block_is_not_user_code() -> None:
    """
    The near-miss that matters: every block runs system-call code at index
    0, so counting any code would fire on every multi-block case. A block-2
    transaction that only moves value must leave the event dark.
    """
    case = _second_block_calls(_multi_block_case(), Address(0x3F002), None)
    assert "later-block-code" not in _signature_of(case).events


def test_a_single_block_case_never_fires_it() -> None:
    """Code in the first block is not code in a later one."""
    single = next(
        generate_fuzzer_output(Amsterdam, seed)
        for seed in range(200)
        if generate_fuzzer_output(Amsterdam, seed).block_count == 1
    )
    assert "later-block-code" not in _signature_of(single).events
