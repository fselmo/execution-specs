"""
Properties of the gas a parent frame grants a child and gets back.

Covers how a call or create forms the child's two gas grants ([EIP-150],
[EIP-8037]), how a child that never runs hands them back, and how a returning
child's leftovers merge into the parent.

[EIP-150]: https://eips.ethereum.org/EIPS/eip-150
[EIP-8037]: https://eips.ethereum.org/EIPS/eip-8037
"""

from types import ModuleType
from typing import Any, List, Tuple

import pytest
from ethereum_types.numeric import U256, Uint
from execution_testing import Op
from execution_testing.forks import Fork
from hypothesis import given
from hypothesis import strategies as st

from ethereum.state import EMPTY_CODE_HASH, Account, Address
from ethereum.state_mpt import State
from ethereum_spec_tools.forks import Hardfork

from .forks import requires
from .gas_meter import (
    AMOUNT_BOUND,
    CHARGES_AND_REFUNDS,
    MeterOp,
    amounts,
    apply_ops,
    fresh_frame,
    meter_fields,
    op_lists,
    pools,
)
from .spec_api import zeroed

pytestmark = requires(lambda fork: fork.state_gas_reservoir_enabled())


# Yellow Paper: a call at this depth fails without entering its child.
CALL_DEPTH_LIMIT = 1024

# EIP-150: a parent keeps one 64th of its gas when it makes a call.
RETAINED_FRACTION = 64


@pytest.fixture(scope="session")
def vm(spec: Hardfork) -> ModuleType:
    """Return the VM package of the fork under test."""
    return spec.module("vm")


@pytest.fixture(scope="session")
def system(spec: Hardfork) -> ModuleType:
    """Return the system instructions, such as `CALL`, of the fork."""
    return spec.module("vm.instructions.system")


@given(
    gas_left=pools(),
    reservoir=pools(),
    prefix=op_lists(CHARGES_AND_REFUNDS),
)
def test_restore_child_gas_undoes_withhold_and_drain(
    gas: ModuleType,
    gas_left: int,
    reservoir: int,
    prefix: List[MeterOp],
) -> None:
    """Handing back a child's unused grants restores the parent exactly."""
    frame = fresh_frame(gas, gas_left, reservoir)
    apply_ops(gas, frame, prefix)
    meter = frame.gas_meter
    before = meter_fields(meter)

    child_gas = gas.withhold_create_gas(meter)
    child_reservoir = gas.drain_state_gas_reservoir(meter)
    gas.restore_child_gas(meter, child_gas, child_reservoir)

    assert meter_fields(meter) == before


@given(
    request=amounts(),
    gas_left=pools(),
    memory_cost=amounts(),
    extra_gas=amounts(),
    big_value=st.integers(min_value=2, max_value=1 << 63),
)
def test_value_adds_only_the_stipend_to_the_child_grant(
    gas: ModuleType,
    fork: Fork,
    request: int,
    gas_left: int,
    memory_cost: int,
    extra_gas: int,
    big_value: int,
) -> None:
    """
    A value-bearing call gives the child exactly the call stipend more
    than the same call without value, costs the caller the same, and does
    not depend on how much value is sent.
    """
    without_value, with_one, with_big = (
        gas.calculate_message_call_gas(
            U256(value),
            Uint(request),
            Uint(gas_left),
            Uint(memory_cost),
            Uint(extra_gas),
        )
        for value in (0, 1, big_value)
    )
    assert with_one.cost == without_value.cost
    assert int(with_one.sub_call) - int(without_value.sub_call) == (
        fork.call_value_stipend()
    )
    assert with_big == with_one


@given(
    reservoir=pools(),
    request=amounts(),
    memory_cost=amounts(),
    extra_gas=amounts(),
    value=st.sampled_from([0, 1]),
    delta=st.one_of(
        st.sampled_from([-2, -1, 0, 1, 2]),
        st.integers(min_value=-AMOUNT_BOUND, max_value=AMOUNT_BOUND),
    ),
)
def test_call_runs_out_of_gas_only_on_its_own_costs(
    gas: ModuleType,
    reservoir: int,
    request: int,
    memory_cost: int,
    extra_gas: int,
    value: int,
    delta: int,
) -> None:
    """
    Charging a call runs out of gas exactly when `gas_left` cannot cover
    the call's own costs; a large gas request never does, and a
    successful charge leaves the parent at least a 64th of the rest.
    """
    gas_left = max(extra_gas + memory_cost + delta, 0)
    frame = fresh_frame(gas, gas_left, reservoir)
    before = meter_fields(frame.gas_meter)

    result = gas.calculate_message_call_gas(
        U256(value),
        Uint(request),
        Uint(gas_left),
        Uint(memory_cost),
        Uint(extra_gas),
    )

    if gas_left < extra_gas + memory_cost:
        with pytest.raises(gas.OutOfGasError):
            gas.charge_gas(frame, result.cost + Uint(memory_cost))
        assert meter_fields(frame.gas_meter) == before
    else:
        gas.charge_gas(frame, result.cost + Uint(memory_cost))
        remaining = gas_left - memory_cost - extra_gas
        assert int(frame.gas_meter.gas_left) >= (
            remaining // RETAINED_FRACTION
        )


CALLER = Address(b"\xaa" * 20)
CALLEE = Address(b"\xbb" * 20)


def calling_frame(
    vm: ModuleType,
    tracker: ModuleType,
    bal: ModuleType,
    gas_meter: Any,
    depth: int,
    caller_balance: int,
    callee_exists: bool,
) -> Any:
    """Return a real `Evm` for `CALLER`, holding just enough state to call."""
    block_state = tracker.BlockState(pre_state=State())
    tx_state = tracker.TransactionState(parent=block_state)
    tracker.set_account(
        tx_state,
        CALLER,
        Account(
            nonce=Uint(1),
            balance=U256(caller_balance),
            code_hash=EMPTY_CODE_HASH,
        ),
    )
    if callee_exists:
        tracker.set_account(
            tx_state,
            CALLEE,
            Account(nonce=Uint(1), balance=U256(0), code_hash=EMPTY_CODE_HASH),
        )
    block_env = zeroed(
        vm.BlockEnvironment,
        state=block_state,
        block_access_list_builder=bal.BlockAccessListBuilder(),
    )
    tx_env = zeroed(vm.TransactionEnvironment, state=tx_state)
    return zeroed(
        vm.Evm,
        gas_meter=gas_meter,
        block_env=block_env,
        tx_env=tx_env,
        caller=CALLER,
        current_target=CALLER,
        code_address=CALLER,
        depth=Uint(depth),
        running=True,
        parent_evm=None,
        error=None,
    )


@pytest.mark.parametrize("opcode", ["call", "callcode"])
@pytest.mark.parametrize("never_enters_because", ["depth", "balance"])
@given(
    reservoir=pools(),
    headroom=amounts(),
    request=amounts(),
    warm=st.booleans(),
    value=st.sampled_from([0, 1]),
    callee_exists=st.booleans(),
    input_size=st.integers(min_value=0, max_value=1 << 15),
)
def test_call_that_never_enters_its_child_refunds_both_grants(
    fork: Fork,
    gas: ModuleType,
    vm: ModuleType,
    system: ModuleType,
    tracker: ModuleType,
    bal: ModuleType,
    opcode: str,
    never_enters_because: str,
    reservoir: int,
    headroom: int,
    request: int,
    warm: bool,
    value: int,
    callee_exists: bool,
    input_size: int,
) -> None:
    """
    A `CALL` or `CALLCODE` that fails before entering its child leaves the
    reservoir as it was, refunds any new-account state charge, and costs
    the caller only the call's own costs, less the stipend it carried.
    """
    if never_enters_because == "depth":
        depth = CALL_DEPTH_LIMIT
        caller_balance = value
    elif never_enters_because == "balance":
        value = 1
        depth = 0
        caller_balance = 0
    else:
        raise ValueError(f"unknown reason: {never_enters_because}")

    own_costs = getattr(Op, opcode.upper())(
        address_warm=warm,
        value_transfer=value > 0,
        new_memory_size=input_size,
    ).gas_cost(fork)
    new_account = Op.CALL.with_metadata(
        value_transfer=True, account_new=True
    ).state_cost(fork)
    gas_left = own_costs + new_account + headroom

    frame = calling_frame(
        vm,
        tracker,
        bal,
        fresh_frame(gas, gas_left, reservoir).gas_meter,
        depth,
        caller_balance,
        callee_exists,
    )
    if warm:
        frame.accessed_addresses.add(CALLEE)
    # Pushed in reverse, so `gas` is popped first.
    frame.stack = [
        U256(0),
        U256(0),
        U256(input_size),
        U256(0),
        U256(value),
        U256.from_be_bytes(CALLEE),
        U256(request),
    ]

    getattr(system, opcode)(frame)

    stipend = fork.call_value_stipend() if value else 0
    assert frame.stack == [U256(0)]
    assert meter_fields(frame.gas_meter) == meter_fields(
        fresh_frame(gas, gas_left - own_costs + stipend, reservoir).gas_meter
    )


ChildFrame = Tuple[str, int, int, List[MeterOp], int, str]


@given(
    gas_left=pools(),
    reservoir=pools(),
    parent_ops=op_lists(CHARGES_AND_REFUNDS, max_size=4),
    children=st.lists(
        st.tuples(
            st.sampled_from(["create", "call"]),
            amounts(),
            st.sampled_from([0, 1]),
            op_lists(CHARGES_AND_REFUNDS, max_size=6),
            st.integers(min_value=0, max_value=1 << 16),
            st.sampled_from(["success", "revert", "halt"]),
        ),
        max_size=3,
    ),
)
def test_child_round_trips_conserve_both_gas_dimensions(
    gas: ModuleType,
    vm: ModuleType,
    spec: Hardfork,
    gas_left: int,
    reservoir: int,
    parent_ops: List[MeterOp],
    children: List[ChildFrame],
) -> None:
    """
    Granting a child gas, running it, and merging it back creates or loses
    no gas in either pool beyond what the child itself spent.
    """
    parent = fresh_frame(gas, gas_left, reservoir)
    apply_ops(gas, parent, parent_ops)
    meter = parent.gas_meter

    for mode, request, value, child_ops, counter, outcome in children:
        before = meter_fields(meter)

        if mode == "create":
            grant = int(gas.withhold_create_gas(meter))
            assert grant == (
                before.gas_left - before.gas_left // RETAINED_FRACTION
            )
            paid = grant
        elif mode == "call":
            result = gas.calculate_message_call_gas(
                U256(value),
                Uint(request),
                Uint(before.gas_left),
                Uint(0),
                Uint(0),
            )
            gas.charge_gas(parent, result.cost)
            paid = int(result.cost)
            grant = int(result.sub_call)
        else:
            raise ValueError(f"unknown child mode: {mode}")
        # The child gets the whole reservoir, with no 64th kept back.
        child_reservoir = int(gas.drain_state_gas_reservoir(meter))
        assert child_reservoir == before.state_gas_left

        child = fresh_frame(gas, grant, child_reservoir)
        child_regular, child_state, child_refunded = apply_ops(
            gas, child, child_ops
        )
        net_state = child_state - child_refunded
        child.gas_meter.refund_counter = counter
        spill_out = int(child.gas_meter.state_gas_spilled)

        if outcome == "success":
            pass
        elif outcome == "revert":
            gas.restore_state_gas(child.gas_meter)
            child.error = spec.module("vm.exceptions").Revert()
        elif outcome == "halt":
            gas.restore_state_gas(child.gas_meter)
            gas.forfeit_remaining_gas(child.gas_meter)
            child.error = gas.OutOfGasError()
        else:
            raise ValueError(f"unknown child outcome: {outcome}")

        vm.incorporate_child(parent, child)

        if outcome == "success":
            reservoir_pooled = before.state_gas_left - net_state + spill_out
            spill_pooled = before.state_gas_spilled + spill_out
            repaid = min(reservoir_pooled, spill_pooled)
            expected = before._replace(
                gas_left=before.gas_left
                - paid
                + grant
                - child_regular
                - spill_out
                + repaid,
                state_gas_left=reservoir_pooled - repaid,
                state_gas_spilled=spill_pooled - repaid,
                refund_counter=before.refund_counter + counter,
            )
        elif outcome == "revert":
            expected = before._replace(
                gas_left=before.gas_left - paid + grant - child_regular
            )
        elif outcome == "halt":
            expected = before._replace(gas_left=before.gas_left - paid)
        else:
            raise ValueError(f"unknown child outcome: {outcome}")
        assert meter_fields(meter) == expected
