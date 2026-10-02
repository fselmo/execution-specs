"""Properties of the intrinsic gas charged before a transaction runs."""

from types import ModuleType

import pytest
from ethereum_types.bytes import Bytes
from ethereum_types.numeric import Uint
from hypothesis import assume, given
from hypothesis import strategies as st

from ethereum.exceptions import InsufficientTransactionGasError
from ethereum.state import Address

from .strategies import addresses, bytes_data
from .strategies.builders import (
    build_tx,
    intrinsic_cost,
    legacy_tx,
    transaction_types,
    validate_tx,
)


@given(data=bytes_data(), to=addresses())
def test_intrinsic_cost_at_least_base(
    gas: ModuleType, transactions: ModuleType, data: Bytes, to: Address
) -> None:
    """No transaction costs less than the base transaction cost."""
    intrinsic = intrinsic_cost(transactions, legacy_tx(transactions, data, to))
    base = gas.GasCosts.TX_BASE
    assert intrinsic.execution >= base
    assert intrinsic.calldata_floor >= base


@given(data=bytes_data(), extra=st.integers(0, 255), to=addresses())
def test_intrinsic_cost_monotonic_in_data(
    transactions: ModuleType, data: Bytes, extra: int, to: Address
) -> None:
    """Appending a calldata byte never lowers the intrinsic cost."""
    shorter = intrinsic_cost(transactions, legacy_tx(transactions, data, to))
    longer_data = Bytes(bytes(data) + bytes([extra]))
    longer = intrinsic_cost(
        transactions, legacy_tx(transactions, longer_data, to)
    )
    assert longer.execution >= shorter.execution
    assert longer.calldata_floor >= shorter.calldata_floor


@given(
    data=bytes_data(max_size=128),
    index=st.integers(0, 127),
    to=addresses(),
)
def test_zero_bytes_never_cost_more(
    transactions: ModuleType, data: Bytes, index: int, to: Address
) -> None:
    """Zeroing a calldata byte never raises the intrinsic cost."""
    assume(len(data) > 0)
    zeroed_data = bytearray(data)
    zeroed_data[index % len(data)] = 0
    original = intrinsic_cost(transactions, legacy_tx(transactions, data, to))
    with_zero = intrinsic_cost(
        transactions, legacy_tx(transactions, Bytes(zeroed_data), to)
    )
    assert with_zero.execution <= original.execution
    assert with_zero.calldata_floor <= original.calldata_floor


@given(data=bytes_data(), to=addresses(), draw=st.data())
def test_validation_boundary_is_exact(
    transactions: ModuleType, data: Bytes, to: Address, draw: st.DataObject
) -> None:
    """
    Validation accepts a transaction whose gas limit is exactly its
    intrinsic cost or calldata floor, whichever is larger, and rejects one
    with a single unit less.
    """
    tx_type = draw.draw(st.sampled_from(transaction_types(transactions)))
    unpriced = build_tx(transactions, tx_type, data=data, to=to)
    intrinsic = intrinsic_cost(transactions, unpriced)
    threshold = max(intrinsic.execution, intrinsic.calldata_floor)

    exact = build_tx(transactions, tx_type, data=data, to=to, gas=threshold)
    validate_tx(transactions, exact)

    below = build_tx(
        transactions, tx_type, data=data, to=to, gas=threshold - Uint(1)
    )
    with pytest.raises(InsufficientTransactionGasError):
        validate_tx(transactions, below)
