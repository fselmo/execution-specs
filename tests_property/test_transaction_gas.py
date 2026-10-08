"""
The gas limits the spec accepts for a transaction, against the framework.

The framework computes the least gas a transaction needs and the caps on
its gas, so each limit is pinned on both sides: the last valid value and the
first invalid one.
"""

from dataclasses import replace
from types import ModuleType
from typing import Callable

import pytest
from ethereum_types.numeric import Uint
from execution_testing import RecipientType, Transaction, TransactionType
from execution_testing.base_types import AccessList
from execution_testing.forks import Fork
from hypothesis import given
from hypothesis import strategies as st

from ethereum.exceptions import InsufficientTransactionGasError
from ethereum_spec_tools.forks import Hardfork

from .forks import requires
from .spec_api import spec_transaction, validate_tx
from .strategies import framework_tx, framework_txs

BOUNDARY_SIDES = ["at_cap", "above_cap"]

# From EIP-8037 a separate cap bounds the gas limit, and the EIP-7825 cap
# bounds the intrinsic execution gas and the calldata floor instead.
with_intrinsic_gas_cap = requires(
    lambda fork: fork.transaction_total_gas_limit_cap() is not None
)


def validate(transactions: ModuleType, framework: Transaction) -> None:
    """Validate the spec's copy of a framework transaction."""
    assert framework.sender is not None
    tx = spec_transaction(transactions, framework)
    validate_tx(transactions, tx, framework.sender)


@given(data=st.data())
def test_minimum_gas_limit_boundary(
    fork: Fork, transactions: ModuleType, data: st.DataObject
) -> None:
    """
    Validation accepts a gas limit of exactly the framework's intrinsic
    cost, for any transaction type, recipient, value, calldata, access list
    and authorization count, and rejects one gas less.
    """
    framework = data.draw(framework_txs(fork))
    minimum = fork.transaction_intrinsic_cost_calculator()(
        calldata=framework.data,
        contract_creation=framework.to is None,
        access_list=framework.access_list,
        authorization_list_or_count=framework.authorization_list,
        sends_value=framework.value > 0,
        recipient_type=(
            RecipientType.SELF
            if framework.to == framework.sender
            else RecipientType.CONTRACT
        ),
    )
    assert framework.sender is not None
    tx = spec_transaction(transactions, framework)

    validate_tx(transactions, replace(tx, gas=Uint(minimum)), framework.sender)
    below = replace(tx, gas=Uint(minimum - 1))
    with pytest.raises(InsufficientTransactionGasError):
        validate_tx(transactions, below, framework.sender)


@requires(lambda fork: fork.transaction_gas_limit_cap() is not None)
@pytest.mark.parametrize("side", BOUNDARY_SIDES)
def test_gas_limit_cap_boundary(
    fork: Fork, spec: Hardfork, transactions: ModuleType, side: str
) -> None:
    """
    A gas limit of exactly the cap is valid for every transaction type and
    one more is not.
    """
    cap = (
        fork.transaction_total_gas_limit_cap()
        or fork.transaction_gas_limit_cap()
    )
    assert cap is not None
    exceptions = spec.module("exceptions")
    for ty in fork.tx_types():
        if side == "at_cap":
            validate(transactions, framework_tx(ty, gas_limit=cap))
        elif side == "above_cap":
            above = framework_tx(ty, gas_limit=cap + 1)
            with pytest.raises(exceptions.TransactionGasLimitExceededError):
                validate(transactions, above)
        else:
            raise ValueError(f"unknown boundary side: {side}")


def largest_size_within(cap: int, cost_of: Callable[[int], int]) -> int:
    """
    Return the largest size whose cost fits `cap`, for a cost that grows by
    a fixed step per unit of size.
    """
    step = cost_of(1) - cost_of(0)
    assert step > 0
    return (cap - cost_of(0)) // step


@with_intrinsic_gas_cap
@pytest.mark.parametrize("side", BOUNDARY_SIDES)
def test_intrinsic_execution_gas_cap_boundary(
    fork: Fork, transactions: ModuleType, side: str
) -> None:
    """
    Intrinsic execution gas of exactly the cap is valid and one zero byte
    more is not.

    Access list slots bring the cost near the cap and zero calldata bytes
    close the gap, keeping the calldata floor well below the cap.
    """
    cap = fork.transaction_gas_limit_cap()
    gas_limit = fork.transaction_total_gas_limit_cap()
    assert cap is not None and gas_limit is not None
    intrinsic_cost = fork.transaction_intrinsic_cost_calculator()
    floor_cost = fork.transaction_data_floor_cost_calculator()

    def tx_with(slots: int, zero_bytes: int) -> Transaction:
        access = AccessList(address=0xCC, storage_keys=[0] * slots)
        return framework_tx(
            TransactionType.BASE_FEE,
            gas_limit=gas_limit,
            access_list=[access],
            data=b"\x00" * zero_bytes,
        )

    def execution_gas(tx: Transaction) -> int:
        return intrinsic_cost(
            calldata=tx.data,
            access_list=tx.access_list,
            return_cost_deducted_prior_execution=True,
        )

    slots = largest_size_within(cap, lambda n: execution_gas(tx_with(n, 0)))
    zero_bytes = largest_size_within(
        cap, lambda n: execution_gas(tx_with(slots, n))
    )
    at_cap = tx_with(slots, zero_bytes)
    above_cap = tx_with(slots, zero_bytes + 1)
    assert execution_gas(at_cap) == cap
    assert (
        floor_cost(data=above_cap.data, access_list=above_cap.access_list)
        < cap
    )

    if side == "at_cap":
        validate(transactions, at_cap)
    elif side == "above_cap":
        with pytest.raises(InsufficientTransactionGasError):
            validate(transactions, above_cap)
    else:
        raise ValueError(f"unknown boundary side: {side}")


@with_intrinsic_gas_cap
@pytest.mark.parametrize("side", BOUNDARY_SIDES)
def test_calldata_floor_cap_boundary(
    fork: Fork, transactions: ModuleType, side: str
) -> None:
    """
    The longest calldata whose floor fits the cap is valid and one more
    byte is not.

    The floor grows in steps of many gas per byte and cannot land on the
    cap exactly, so the two sides are one byte apart.
    """
    cap = fork.transaction_gas_limit_cap()
    gas_limit = fork.transaction_total_gas_limit_cap()
    assert cap is not None and gas_limit is not None
    floor_cost = fork.transaction_data_floor_cost_calculator()
    intrinsic_cost = fork.transaction_intrinsic_cost_calculator()

    def floor(data_bytes: int) -> int:
        return floor_cost(data=b"\xff" * data_bytes)

    data_bytes = largest_size_within(cap, floor)
    assert floor(data_bytes) <= cap < floor(data_bytes + 1)
    execution = intrinsic_cost(
        calldata=b"\xff" * (data_bytes + 1),
        return_cost_deducted_prior_execution=True,
    )
    assert execution < cap

    def tx_with(data_bytes: int) -> Transaction:
        return framework_tx(
            TransactionType.LEGACY,
            gas_limit=gas_limit,
            data=b"\xff" * data_bytes,
        )

    if side == "at_cap":
        validate(transactions, tx_with(data_bytes))
    elif side == "above_cap":
        with pytest.raises(InsufficientTransactionGasError):
            validate(transactions, tx_with(data_bytes + 1))
    else:
        raise ValueError(f"unknown boundary side: {side}")
