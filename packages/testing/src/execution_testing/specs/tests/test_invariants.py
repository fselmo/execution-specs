"""Tests for the chain invariants checked on filled blocks."""

from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from execution_testing.base_types import Account, Address
from execution_testing.evm_tools.t8n.evm_trace.bal_witness import (
    BalWitness,
    bal_slots,
    check_bal_relation,
)
from execution_testing.forks import Amsterdam, Osaka
from execution_testing.test_types import Alloc
from execution_testing.test_types.block_access_list import (
    BalAccountChange,
    BalBalanceChange,
    BalStorageChange,
    BalStorageSlot,
    BlockAccessList,
)
from execution_testing.vm import Op

from ..invariants import (
    check_bal_against_state_diff,
    check_ether_conservation,
    check_gas_accounting,
    check_nonce_monotonicity,
)

ACCOUNT = Address(0x1234)


def result(
    gas_used: int = 0,
    cumulative: List[int] | None = None,
    opcodes: Dict[Op, int] | None = None,
) -> Any:
    """Return the fields of a transition tool result the checks read."""
    return SimpleNamespace(
        gas_used=gas_used,
        receipts=[
            SimpleNamespace(cumulative_gas_used=gas)
            for gas in cumulative or []
        ],
        rejected_transactions=[],
        opcode_count=None
        if opcodes is None
        else SimpleNamespace(root=opcodes),
        base_fee_per_gas=None,
        blob_gas_used=0,
        excess_blob_gas=0,
    )


def env() -> Any:
    """Return the fields of an environment the checks read."""
    return SimpleNamespace(
        gas_limit=30_000_000,
        withdrawals=None,
        base_fee_per_gas=None,
        excess_blob_gas=0,
    )


def alloc(**account: Any) -> Alloc:
    """Return an allocation holding one account."""
    return Alloc({ACCOUNT: Account(**account)})


def invariants(violations: List[Any]) -> List[str]:
    """Return the names of the violated invariants."""
    return [violation.invariant for violation in violations]


@pytest.mark.parametrize(
    "gas_used,expected",
    [
        pytest.param(700, [], id="equal"),
        pytest.param(699, ["receipt_gas_totals"], id="below"),
        pytest.param(701, ["receipt_gas_totals"], id="above"),
    ],
)
def test_receipts_equal_header_gas_before_eip7778(
    gas_used: int, expected: List[str]
) -> None:
    """Before EIP-7778 the last receipt equals the header's gas used."""
    violations = check_gas_accounting(
        Osaka, result(gas_used, [200, 700]), env()
    )
    assert invariants(violations) == expected


@pytest.mark.parametrize(
    "gas_used,expected",
    [
        pytest.param(500, [], id="lowest"),
        pytest.param(499, ["receipt_gas_totals"], id="below_lowest"),
        pytest.param(1250, [], id="highest"),
        pytest.param(1251, ["receipt_gas_totals"], id="above_highest"),
    ],
)
def test_header_gas_bounds_with_two_dimensions(
    gas_used: int, expected: List[str]
) -> None:
    """
    With EIP-7778 and EIP-8037 the header lies between half and five
    quarters of the receipts.
    """
    violations = check_gas_accounting(
        Amsterdam, result(gas_used, [400, 1000]), env()
    )
    assert invariants(violations) == expected


@pytest.mark.parametrize(
    "fork,opcodes,post_balance,expected",
    [
        pytest.param(
            Osaka, {Op.SELFDESTRUCT: 1}, 95, [], id="burn_before_eip8246"
        ),
        pytest.param(Osaka, None, 95, [], id="burn_without_opcode_counts"),
        pytest.param(
            Osaka,
            {},
            95,
            ["ether_conservation"],
            id="burn_without_selfdestruct",
        ),
        pytest.param(
            Osaka,
            {Op.SELFDESTRUCT: 1},
            105,
            ["ether_conservation"],
            id="mint_before_eip8246",
        ),
        pytest.param(
            Amsterdam,
            {Op.SELFDESTRUCT: 1},
            95,
            ["ether_conservation"],
            id="burn_with_eip8246",
        ),
    ],
)
def test_selfdestruct_may_only_burn_before_eip8246(
    fork: Any,
    opcodes: Dict[Op, int] | None,
    post_balance: int,
    expected: List[str],
) -> None:
    """A block that ran SELFDESTRUCT may lose ether only before EIP-8246."""
    violations = check_ether_conservation(
        fork,
        alloc(balance=100),
        alloc(balance=post_balance),
        result(opcodes=opcodes),
        env(),
        txs=[],
        reward=0,
    )
    assert invariants(violations) == expected


@pytest.mark.parametrize(
    "opcodes,expected",
    [
        pytest.param({}, ["nonce_never_decreases"], id="without_selfdestruct"),
        pytest.param({Op.SELFDESTRUCT: 1}, [], id="with_selfdestruct"),
    ],
)
def test_nonce_decreases_only_with_selfdestruct(
    opcodes: Dict[Op, int], expected: List[str]
) -> None:
    """Only account deletion, which needs SELFDESTRUCT, lowers a nonce."""
    violations = check_nonce_monotonicity(
        alloc(nonce=2), alloc(nonce=0), [], result(opcodes=opcodes)
    )
    assert invariants(violations) == expected


def bal(**changes: Any) -> BlockAccessList:
    """Return a BAL with one account entry."""
    return BlockAccessList([BalAccountChange(address=ACCOUNT, **changes)])


def balances(*values: int) -> List[BalBalanceChange]:
    """Return balance changes at consecutive indices."""
    return [
        BalBalanceChange(block_access_index=index + 1, post_balance=value)
        for index, value in enumerate(values)
    ]


@pytest.mark.parametrize(
    "recorded,expected",
    [
        pytest.param(balances(7), [], id="recorded"),
        pytest.param(balances(9, 7), [], id="recorded_twice"),
        pytest.param([], ["bal_state_diff"], id="missing"),
        pytest.param(balances(6), ["bal_state_diff"], id="last_value_differs"),
        pytest.param(balances(5, 7), ["bal_state_diff"], id="no_op_change"),
    ],
)
def test_bal_balance_against_state_diff(
    recorded: List[BalBalanceChange], expected: List[str]
) -> None:
    """A balance going from 5 to 7 must end at 7 with no repeated value."""
    violations = check_bal_against_state_diff(
        alloc(balance=5), alloc(balance=7), bal(balance_changes=recorded)
    )
    assert invariants(violations) == expected


@pytest.mark.parametrize(
    "post_storage,expected",
    [
        pytest.param({1: 0}, ["bal_state_diff"], id="netted_to_zero"),
        pytest.param({}, ["bal_state_diff"], id="absent_means_zero"),
        pytest.param({1: 1}, [], id="kept"),
    ],
)
def test_bal_storage_no_op_change(
    post_storage: Dict[int, int], expected: List[str]
) -> None:
    """A slot recorded as written back to its pre-state value is a no-op."""
    recorded = [
        BalStorageSlot(
            slot=1,
            slot_changes=[
                BalStorageChange(
                    block_access_index=1, post_value=post_storage.get(1, 0)
                )
            ],
        )
    ]
    violations = check_bal_against_state_diff(
        alloc(storage={}),
        alloc(storage=post_storage),
        bal(storage_changes=recorded),
    )
    assert invariants(violations) == expected


@pytest.mark.parametrize(
    "pre_nonce,expected",
    [
        pytest.param(0, [], id="storage_only_account_wiped"),
        pytest.param(
            1, ["bal_state_diff"] * 2, id="account_with_nonce_cleared"
        ),
    ],
)
def test_bal_storage_wipe_of_storage_only_account(
    pre_nonce: int, expected: List[str]
) -> None:
    """
    Creating over a storage-only account wipes its storage, which the BAL
    cannot record, so only that account's storage is exempt.
    """
    violations = check_bal_against_state_diff(
        alloc(nonce=pre_nonce, storage={1: 1, 2: 2}),
        alloc(nonce=pre_nonce, storage={}),
        bal(),
    )
    assert invariants(violations) == expected


def test_bal_entry_for_an_account_absent_from_the_state() -> None:
    """A change recorded for an account in neither state is reported."""
    violations = check_bal_against_state_diff(
        Alloc({}), Alloc({}), bal(balance_changes=balances(7))
    )
    assert invariants(violations) == ["bal_state_diff"]


def test_witness_bounds_report_each_side() -> None:
    """A slot dropped from the BAL and one it invented are both reported."""
    witness = BalWitness(
        started=frozenset({(1, 2), (3, 4)}), ended=frozenset({(1, 2)})
    )
    assert check_bal_relation(witness, frozenset({(1, 2), (3, 4)})) == []
    dropped = check_bal_relation(witness, frozenset())
    assert [d.kind for d in dropped] == ["accessed but absent from the BAL"]
    invented = check_bal_relation(witness, frozenset({(1, 2), (9, 9)}))
    assert [d.kind for d in invented] == ["in the BAL but never accessed"]


def test_bal_slots_include_reads_and_changes() -> None:
    """Both a read slot and a changed slot count as accessed."""
    listed = bal(
        storage_changes=[BalStorageSlot(slot=1, slot_changes=[])],
        storage_reads=[3],
    )
    assert bal_slots(listed) == {(0x1234, 1), (0x1234, 3)}
