"""
Claims about current Amsterdam behavior that planned work depends on.

Each of these is an assertion the fuzzing-surface analysis makes about
what the spec does today, and each is a premise for a generation target.
A target built on a wrong premise is wrong too, and the cost of finding
that out later is a campaign: the nethermind halt-chain detour began
from a mechanism description that was one level off the mechanism.

They are pinned here so that a repricing or a refactor that invalidates
one fails loudly, rather than quietly invalidating whatever was built on
top of it.
"""

from typing import Any, Dict, Set

from ethereum_types.bytes import Bytes20, Bytes32
from ethereum_types.numeric import U256, Uint
from execution_testing.base_types import (
    AccessList,
    Address,
    Bytes,
    Hash,
    HexNumber,
)
from execution_testing.cli.fuzzer_bridge.campaign import fill_case
from execution_testing.cli.fuzzer_bridge.models import (
    FuzzerAccountInput,
    FuzzerOutput,
    FuzzerTransactionInput,
)
from execution_testing.client_clis.clis.execution_specs import (
    ExecutionSpecsTransitionTool,
)
from execution_testing.forks import Amsterdam
from execution_testing.test_types import Environment
from execution_testing.test_types.account_types import EOA
from execution_testing.vm import Opcodes as Op

from ethereum.forks.amsterdam.state_tracker import (
    BlockState,
    TransactionState,
    restore_tx_state,
)
from ethereum.forks.amsterdam.vm.gas import GasCosts
from ethereum.state_mpt import State


def test_the_sstore_gas_gate_is_the_stipend_for_warm_and_cold_alike() -> None:
    """
    SSTORE's pre-access gas check is `max(access cost, CALL_STIPEND + 1)`,
    and today the `max` is inert: both access costs sit below the stipend,
    so the gate is the stipend whichever side it takes.

    The `max` exists against a future repricing -- its own comment says
    the access cost "can exceed the stipend" -- so this is the assertion
    that goes stale first. A repricing that lifts `COLD_STORAGE_ACCESS`
    past the stipend moves the cold gate without moving the warm one, and
    any boundary case generated around the stipend stops testing the edge
    it was written for. Asserted against the constants rather than the
    value they currently produce, so a repricing fails here.
    """
    gate = Uint(GasCosts.CALL_STIPEND) + Uint(1)
    assert Uint(GasCosts.WARM_ACCESS) < gate
    assert Uint(GasCosts.COLD_STORAGE_ACCESS) < gate
    assert max(Uint(GasCosts.WARM_ACCESS), gate) == gate
    assert max(Uint(GasCosts.COLD_STORAGE_ACCESS), gate) == gate


def _as_int(address: Address) -> int:
    """`Address` is bytes; comparisons go through its integer value."""
    return int.from_bytes(bytes(address), "big")


def _bal_addresses(fixture: Dict[str, Any]) -> Set[int]:
    """Every address the block access list names, as ints."""
    found: Set[int] = set()
    for block in fixture.get("blocks", []):
        for entry in block.get("blockAccessList", []):
            found.add(int(entry["address"], 16))
    return found


def test_a_declared_but_untouched_access_list_entry_is_not_in_the_bal() -> (
    None
):
    """
    An access list entry is paid for and warms its target, but warming is
    not access: an address the transaction never touches must not appear
    in the block access list.

    The two live in different places -- the declaration reaches the
    interpreter's `accessed_addresses`, while the BAL is built from the
    state tracker's reads and writes -- and nothing carries one into the
    other. An address can appear in the BAL with every change list empty,
    so the assertion is absence from the address set, not emptiness.
    """
    key = Hash((11).to_bytes(32, "big"))
    sender = Address(EOA(key=key))
    target = Address(0x50000)
    declared = Address(0xDEAD0000BEEF)

    case = FuzzerOutput(
        version="2.0",
        fork=Amsterdam,
        accounts={
            sender: FuzzerAccountInput(
                balance=HexNumber(10**18), private_key=key
            ),
            target: FuzzerAccountInput(
                balance=HexNumber(0), code=Bytes(bytes(Op.STOP))
            ),
        },
        transactions=[
            FuzzerTransactionInput(
                **{"from": sender},
                to=target,
                gas=HexNumber(200_000),
                gas_price=HexNumber(10),
                nonce=HexNumber(0),
                access_list=[
                    AccessList(address=declared, storage_keys=[0x01])
                ],
            )
        ],
        env=Environment(
            fee_recipient=Address(0xC0FFEE),
            gas_limit=30_000_000,
            number=1,
            timestamp=1000,
            prev_randao=Hash(0),
            base_fee_per_gas=7,
        ),
    )
    eels = ExecutionSpecsTransitionTool()
    fixture = fill_case(case, Amsterdam, eels)

    # The claim has two halves, and the second is vacuous without the
    # first: were the declaration silently dropped, the address would be
    # absent from the BAL for the wrong reason.
    intrinsic = Amsterdam.transaction_intrinsic_cost_calculator()
    declaration = AccessList(address=declared, storage_keys=[0x01])
    assert intrinsic(access_list=[declaration]) > intrinsic()

    seen = _bal_addresses(fixture)
    assert _as_int(target) in seen, (
        "the called account must appear, or the case proves nothing"
    )
    assert _as_int(declared) not in seen


def test_reads_and_creations_survive_rollback_but_writes_do_not() -> None:
    """
    Rollback restores the write sets and leaves the read sets alone, so a
    failed frame's accesses still reach the block access list while its
    changes do not.

    This is what makes the BAL an access record rather than a state diff,
    and it is the rule the erigon self-destruct finding turned on.
    """
    tx_state = TransactionState(parent=BlockState(pre_state=State()))
    address = Bytes20((0x1234).to_bytes(20, "big"))
    slot = Bytes32((0).to_bytes(32, "big"))

    snapshot = TransactionState(
        parent=tx_state.parent,
        account_reads=tx_state.account_reads,
        account_writes=dict(tx_state.account_writes),
        storage_reads=tx_state.storage_reads,
        storage_writes=dict(tx_state.storage_writes),
        code_writes=dict(tx_state.code_writes),
        created_accounts=tx_state.created_accounts,
        transient_storage=dict(tx_state.transient_storage),
    )

    tx_state.account_reads.add(address)
    tx_state.storage_reads.add((address, slot))
    tx_state.created_accounts.add(address)
    tx_state.account_writes[address] = None
    tx_state.storage_writes[address] = {}
    tx_state.transient_storage[(address, slot)] = U256(0)

    restore_tx_state(tx_state, snapshot)

    assert address in tx_state.account_reads
    assert (address, slot) in tx_state.storage_reads
    assert address in tx_state.created_accounts
    assert address not in tx_state.account_writes
    assert address not in tx_state.storage_writes
    assert (address, slot) not in tx_state.transient_storage


def test_the_restore_touches_exactly_the_write_collections() -> None:
    """
    The survival rule above is a property of which fields `restore_tx_state`
    names. Enumerated here so that adding a collection to `TransactionState`
    forces a decision about which side it falls on, rather than defaulting
    to surviving rollback because nobody listed it.
    """
    import inspect

    source = inspect.getsource(restore_tx_state)
    restored = {
        line.split("=")[0].strip().split(".")[-1]
        for line in source.splitlines()
        if line.strip().startswith("tx_state.")
    }
    assert restored == {
        "account_writes",
        "storage_writes",
        "code_writes",
        "transient_storage",
    }
