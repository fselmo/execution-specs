"""
Properties of the [EIP-7825] transaction gas cap.

Before [EIP-8037] the cap bounds a transaction's gas limit. From EIP-8037 the
gas limit has its own, higher cap, and the EIP-7825 cap bounds the intrinsic
execution gas and the calldata floor instead.

[EIP-7825]: https://eips.ethereum.org/EIPS/eip-7825
[EIP-8037]: https://eips.ethereum.org/EIPS/eip-8037
"""

import importlib
from types import ModuleType
from typing import Any, Callable

import pytest
from ethereum_types.bytes import Bytes, Bytes32
from ethereum_types.numeric import Uint

from ethereum.exceptions import InsufficientTransactionGasError

from .forks import forks_from, past_fork
from .strategies.builders import (
    build_tx,
    intrinsic_cost,
    transaction_types,
    validate_tx,
)

# EIP-7825: "a protocol-level cap ... to 16,777,216 (2^24) gas".
TX_MAX_GAS_LIMIT = 2**24
# EIP-8037: "TX_MAX_TOTAL_GAS_LIMIT | 4,294,967,295 (2^32 - 1)".
TX_MAX_TOTAL_GAS_LIMIT = 2**32 - 1

BOUNDARY_SIDES = [
    pytest.param("at_cap", id="at_cap"),
    pytest.param("above_cap", id="above_cap"),
]

with_total_gas_cap = pytest.mark.parametrize(
    "fork_name", forks_from("amsterdam"), indirect=True
)


@pytest.fixture(scope="session")
def exceptions(fork_name: str) -> ModuleType:
    """Return the exceptions module of the fork under test."""
    return importlib.import_module(f"ethereum.forks.{fork_name}.exceptions")


def check_gas_limit_boundary(
    transactions: ModuleType, exceptions: ModuleType, cap: int, side: str
) -> None:
    """Validate every transaction type with a gas limit at or above `cap`."""
    for tx_type in transaction_types(transactions):
        if side == "at_cap":
            validate_tx(
                transactions, build_tx(transactions, tx_type, gas=Uint(cap))
            )
        elif side == "above_cap":
            tx = build_tx(transactions, tx_type, gas=Uint(cap + 1))
            with pytest.raises(exceptions.TransactionGasLimitExceededError):
                validate_tx(transactions, tx)
        else:
            raise ValueError(f"unknown boundary side: {side}")


# EIP-8037 replaced this rule in Amsterdam, so Osaka is the last fork with it.
@pytest.mark.parametrize("fork_name", past_fork("osaka"), indirect=True)
@pytest.mark.parametrize("side", BOUNDARY_SIDES)
def test_gas_limit_cap_boundary(
    transactions: ModuleType, exceptions: ModuleType, side: str
) -> None:
    """A gas limit of exactly the EIP-7825 cap is valid and one more is not."""
    check_gas_limit_boundary(transactions, exceptions, TX_MAX_GAS_LIMIT, side)


@with_total_gas_cap
@pytest.mark.parametrize("side", BOUNDARY_SIDES)
def test_total_gas_limit_cap_boundary(
    transactions: ModuleType, exceptions: ModuleType, side: str
) -> None:
    """A gas limit of exactly the EIP-8037 cap is valid and one more is not."""
    check_gas_limit_boundary(
        transactions, exceptions, TX_MAX_TOTAL_GAS_LIMIT, side
    )


def largest_size_within_cap(cost_of: Callable[[int], int]) -> int:
    """
    Return the largest size whose cost fits the EIP-7825 cap, for a cost
    that grows by a fixed step per unit of size.
    """
    step = cost_of(1) - cost_of(0)
    assert step > 0
    return (TX_MAX_GAS_LIMIT - cost_of(0)) // step


@with_total_gas_cap
@pytest.mark.parametrize("side", BOUNDARY_SIDES)
def test_intrinsic_execution_gas_cap_boundary(
    transactions: ModuleType, side: str
) -> None:
    """
    Intrinsic execution gas of exactly the EIP-7825 cap is valid and the
    next step above it is not.

    Access list slots bring the cost near the cap and zero calldata bytes
    close the gap, keeping the calldata floor well below the cap.
    """

    def tx_with(slots: int, zero_bytes: int) -> Any:
        access = transactions.Access(
            account=transactions.Address(b"\xcc" * 20),
            slots=(Bytes32(b"\x00" * 32),) * slots,
        )
        return build_tx(
            transactions,
            transactions.FeeMarketTransaction,
            gas=Uint(TX_MAX_TOTAL_GAS_LIMIT),
            access_list=(access,),
            data=Bytes(b"\x00" * zero_bytes),
        )

    slots = largest_size_within_cap(
        lambda n: int(intrinsic_cost(transactions, tx_with(n, 0)).execution)
    )
    zero_bytes = largest_size_within_cap(
        lambda n: int(
            intrinsic_cost(transactions, tx_with(slots, n)).execution
        )
    )
    at_cap = intrinsic_cost(transactions, tx_with(slots, zero_bytes))
    assert int(at_cap.execution) == TX_MAX_GAS_LIMIT
    assert int(at_cap.calldata_floor) < TX_MAX_GAS_LIMIT

    if side == "at_cap":
        validate_tx(transactions, tx_with(slots, zero_bytes))
    elif side == "above_cap":
        above = tx_with(slots, zero_bytes + 1)
        above_floor = intrinsic_cost(transactions, above).calldata_floor
        assert int(above_floor) < TX_MAX_GAS_LIMIT
        with pytest.raises(
            InsufficientTransactionGasError,
            match="Intrinsic execution gas exceeds TX_MAX_GAS_LIMIT",
        ):
            validate_tx(transactions, above)
    else:
        raise ValueError(f"unknown boundary side: {side}")


@with_total_gas_cap
@pytest.mark.parametrize("side", BOUNDARY_SIDES)
def test_calldata_floor_cap_boundary(
    transactions: ModuleType, side: str
) -> None:
    """
    The longest calldata whose floor fits the EIP-7825 cap is valid and one
    more byte is not.

    The floor grows in steps of many gas per byte and cannot land on the
    cap exactly, so the two sides are one byte apart.
    """

    def tx_with(data_bytes: int) -> Any:
        return build_tx(
            transactions,
            transactions.LegacyTransaction,
            gas=Uint(TX_MAX_TOTAL_GAS_LIMIT),
            data=Bytes(b"\xff" * data_bytes),
        )

    data_bytes = largest_size_within_cap(
        lambda n: int(intrinsic_cost(transactions, tx_with(n)).calldata_floor)
    )
    at_cap = intrinsic_cost(transactions, tx_with(data_bytes))
    above = intrinsic_cost(transactions, tx_with(data_bytes + 1))
    assert (
        int(at_cap.calldata_floor)
        <= TX_MAX_GAS_LIMIT
        < int(above.calldata_floor)
    )
    assert int(above.execution) < TX_MAX_GAS_LIMIT

    if side == "at_cap":
        validate_tx(transactions, tx_with(data_bytes))
    elif side == "above_cap":
        with pytest.raises(
            InsufficientTransactionGasError,
            match="Intrinsic calldata floor exceeds TX_MAX_GAS_LIMIT",
        ):
            validate_tx(transactions, tx_with(data_bytes + 1))
    else:
        raise ValueError(f"unknown boundary side: {side}")
