"""Properties of transaction intrinsic gas cost calculation."""

import importlib
from types import ModuleType
from typing import Any, NamedTuple

import pytest
from ethereum_types.bytes import Bytes, Bytes0, Bytes20
from ethereum_types.numeric import U256, Uint
from hypothesis import assume, given
from hypothesis import strategies as st

from ethereum.exceptions import InsufficientTransactionGasError
from ethereum.state import Address

from .strategies import addresses, bytes_data

SENDER = Address(Bytes20(b"\xaa" * 20))
DEFAULT_TX_GAS = Uint(30_000_000)


@pytest.fixture(scope="session")
def transactions(fork_name: str) -> ModuleType:
    """Transactions module of the fork under test."""
    return importlib.import_module(f"ethereum.forks.{fork_name}.transactions")


@pytest.fixture(scope="session")
def gas_costs(fork_name: str) -> Any:
    """Gas cost constants of the fork under test."""
    gas = importlib.import_module(f"ethereum.forks.{fork_name}.vm.gas")
    return gas.GasCosts


def legacy_tx(
    transactions: ModuleType,
    data: Bytes,
    to: Bytes0 | Address,
    gas: Uint = DEFAULT_TX_GAS,
) -> Any:
    """Build a legacy transaction with the given data and target."""
    return transactions.LegacyTransaction(
        nonce=U256(0),
        gas_price=Uint(10),
        gas=gas,
        to=to,
        value=U256(0),
        data=data,
        v=U256(27),
        r=U256(1),
        s=U256(1),
    )


class Intrinsic(NamedTuple):
    """Fork-independent view of an intrinsic gas cost."""

    execution: Uint
    calldata_floor: Uint


def intrinsic_cost(
    fork_name: str, transactions: ModuleType, tx: Any
) -> Intrinsic:
    """
    Adapt to the per-fork calling convention and field names: Amsterdam's
    intrinsic cost depends on the sender (self-transfer and
    recipient-access charges) and calls the non-floor component
    `execution` where Osaka calls it `regular`.
    """
    if fork_name == "osaka":
        cost = transactions.calculate_intrinsic_cost(tx)
        return Intrinsic(cost.regular, cost.calldata_floor)
    elif fork_name == "amsterdam":
        cost = transactions.calculate_intrinsic_cost(tx, SENDER)
        return Intrinsic(cost.execution, cost.calldata_floor)
    else:
        raise ValueError(f"unhandled fork: {fork_name}")


@given(data=bytes_data(), to=addresses())
def test_intrinsic_cost_at_least_base(
    fork_name: str,
    transactions: ModuleType,
    gas_costs: Any,
    data: Bytes,
    to: Address,
) -> None:
    """No transaction is cheaper than the base cost."""
    intrinsic = intrinsic_cost(
        fork_name, transactions, legacy_tx(transactions, data, to)
    )
    base = gas_costs.TX_BASE
    assert intrinsic.execution >= base
    assert intrinsic.calldata_floor >= base


@given(data=bytes_data(), extra=st.integers(0, 255), to=addresses())
def test_intrinsic_cost_monotonic_in_data(
    fork_name: str,
    transactions: ModuleType,
    data: Bytes,
    extra: int,
    to: Address,
) -> None:
    """Appending calldata never lowers the intrinsic cost."""
    shorter = intrinsic_cost(
        fork_name, transactions, legacy_tx(transactions, data, to)
    )
    longer = intrinsic_cost(
        fork_name,
        transactions,
        legacy_tx(transactions, Bytes(bytes(data) + bytes([extra])), to),
    )
    assert longer.execution >= shorter.execution
    assert longer.calldata_floor >= shorter.calldata_floor


@given(
    data=bytes_data(max_size=128),
    index=st.integers(0, 127),
    to=addresses(),
)
def test_zero_bytes_never_cost_more(
    fork_name: str,
    transactions: ModuleType,
    data: Bytes,
    index: int,
    to: Address,
) -> None:
    """Zeroing a calldata byte never raises the intrinsic cost."""
    assume(len(data) > 0)
    index = index % len(data)
    zeroed = bytearray(data)
    zeroed[index] = 0
    original = intrinsic_cost(
        fork_name, transactions, legacy_tx(transactions, data, to)
    )
    with_zero = intrinsic_cost(
        fork_name,
        transactions,
        legacy_tx(transactions, Bytes(bytes(zeroed)), to),
    )
    assert with_zero.execution <= original.execution
    assert with_zero.calldata_floor <= original.calldata_floor


@given(data=bytes_data(), to=addresses())
def test_create_costs_exactly_create_plus_init_code(
    fork_name: str, transactions: ModuleType, data: Bytes, to: Address
) -> None:
    """
    Cost decomposition of Osaka's create transactions; Amsterdam
    reprices creation entirely (state gas, `CREATE_ACCESS`), so its
    decomposition needs its own property once that model settles.
    """
    if fork_name != "osaka":
        pytest.skip("cost decomposition is fork-specific")
    gas = importlib.import_module(
        transactions.__name__.rsplit(".", 1)[0] + ".vm.gas"
    )
    call = transactions.calculate_intrinsic_cost(
        legacy_tx(transactions, data, to)
    )
    create = transactions.calculate_intrinsic_cost(
        legacy_tx(transactions, data, Bytes0(b""))
    )
    expected_extra = gas.GasCosts.TX_CREATE + gas.init_code_cost(
        Uint(len(data))
    )
    assert create.regular - call.regular == expected_extra
    assert create.calldata_floor == call.calldata_floor


@given(data=bytes_data(), to=addresses())
def test_validation_boundary_is_exact(
    fork_name: str, transactions: ModuleType, data: Bytes, to: Address
) -> None:
    """
    `validate_transaction` must accept a transaction with exactly
    `max(regular, calldata_floor)` gas and reject one with a single
    unit less.
    """
    if fork_name != "osaka":
        pytest.skip("validation gas semantics are fork-specific")
    intrinsic = transactions.calculate_intrinsic_cost(
        legacy_tx(transactions, data, to)
    )
    threshold = max(intrinsic.regular, intrinsic.calldata_floor)

    exact = legacy_tx(transactions, data, to, gas=threshold)
    transactions.validate_transaction(exact)

    below = legacy_tx(transactions, data, to, gas=threshold - Uint(1))
    with pytest.raises(InsufficientTransactionGasError):
        transactions.validate_transaction(below)
