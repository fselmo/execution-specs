"""
Properties of the gas a parent frame grants a child and gets back.

Covers how a call or create forms the child's two gas grants ([EIP-150],
[EIP-8037]), how a child that never runs hands them back, and how a returning
child's leftovers merge into the parent.

[EIP-150]: https://eips.ethereum.org/EIPS/eip-150
[EIP-8037]: https://eips.ethereum.org/EIPS/eip-8037
"""

import importlib
from types import ModuleType
from typing import List, Tuple

import pytest
from ethereum_types.numeric import U256, Uint
from hypothesis import given
from hypothesis import strategies as st

from .forks import forks_from
from .strategies.gas_meter import (
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

pytestmark = pytest.mark.parametrize(
    "fork_name", forks_from("amsterdam"), indirect=True
)

# Yellow Paper G_callstipend: gas added to a value-bearing call's grant.
CALL_STIPEND = 2300


@pytest.fixture(scope="session")
def vm(fork_name: str) -> ModuleType:
    """Return the VM package of the fork under test."""
    return importlib.import_module(f"ethereum.forks.{fork_name}.vm")


@pytest.fixture(scope="session")
def vm_exceptions(fork_name: str) -> ModuleType:
    """Return the VM exceptions module of the fork under test."""
    return importlib.import_module(f"ethereum.forks.{fork_name}.vm.exceptions")


@given(
    gas_left=pools(),
    reservoir=pools(),
    prefix=op_lists(CHARGES_AND_REFUNDS),
)
def test_withhold_create_gas_moves_regular_gas_only(
    gas: ModuleType,
    gas_left: int,
    reservoir: int,
    prefix: List[MeterOp],
) -> None:
    """
    Withholding a create's grant splits `gas_left` between parent and
    child without losing any, and moves no other meter field.
    """
    frame = fresh_frame(gas, gas_left, reservoir)
    apply_ops(gas, frame, prefix)
    meter = frame.gas_meter
    before = meter_fields(meter)

    child_gas = int(gas.withhold_create_gas(meter))

    assert meter_fields(meter) == before._replace(
        gas_left=before.gas_left - child_gas
    )


@given(
    gas_left=pools(),
    reservoir=pools(),
    prefix=op_lists(CHARGES_AND_REFUNDS),
)
def test_drain_grants_the_entire_reservoir(
    gas: ModuleType,
    gas_left: int,
    reservoir: int,
    prefix: List[MeterOp],
) -> None:
    """
    A child receives the parent's whole reservoir, with no 63/64 share
    withheld, and nothing else in the parent's meter moves.
    """
    frame = fresh_frame(gas, gas_left, reservoir)
    apply_ops(gas, frame, prefix)
    meter = frame.gas_meter
    before = meter_fields(meter)

    granted = int(gas.drain_state_gas_reservoir(meter))

    assert granted == before.state_gas_left
    assert meter_fields(meter) == before._replace(state_gas_left=0)


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
        CALL_STIPEND
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
        assert int(frame.gas_meter.gas_left) >= remaining // 64


@given(
    reservoir=pools(),
    headroom=amounts(),
    request=amounts(),
    warm=st.booleans(),
    value=st.sampled_from([0, 1]),
    folded=st.booleans(),
    creates_account=st.booleans(),
    memory_cost=amounts(),
)
def test_call_that_never_enters_its_child_refunds_both_grants(
    gas: ModuleType,
    reservoir: int,
    headroom: int,
    request: int,
    warm: bool,
    value: int,
    folded: bool,
    creates_account: bool,
    memory_cost: int,
) -> None:
    """
    A call that fails before entering its child leaves the reservoir as
    it was, refunds any new-account state charge, and costs the caller
    only the call's own costs, less the stipend on a value-bearing call.

    The steps follow `call()` and `generic_call()` in that order.
    """
    costs = gas.GasCosts
    access = int(costs.WARM_ACCESS if warm else costs.COLD_ACCOUNT_ACCESS)
    extra_gas = access + (int(costs.CALL_VALUE) if value else 0)
    charges_new_account = creates_account and value == 1 and not folded
    state_charge = (
        int(gas.StateGasCosts.NEW_ACCOUNT) if charges_new_account else 0
    )
    gas_left = extra_gas + memory_cost + state_charge + headroom

    frame = fresh_frame(gas, gas_left, reservoir)
    meter = frame.gas_meter
    if folded:
        result = gas.calculate_message_call_gas(
            U256(value),
            Uint(request),
            Uint(int(meter.gas_left)),
            Uint(memory_cost),
            Uint(extra_gas),
        )
        gas.charge_gas(frame, result.cost + Uint(memory_cost))
    else:
        gas.charge_gas(frame, Uint(extra_gas + memory_cost))
        if charges_new_account:
            gas.charge_state_gas(frame, Uint(state_charge))
        result = gas.calculate_message_call_gas(
            U256(value),
            Uint(request),
            Uint(int(meter.gas_left)),
            Uint(0),
            Uint(0),
        )
        gas.charge_gas(frame, result.cost)
    child_reservoir = gas.drain_state_gas_reservoir(meter)

    gas.restore_child_gas(meter, result.sub_call, child_reservoir)
    if charges_new_account:
        gas.credit_state_gas_refund(meter, Uint(state_charge))

    stipend = CALL_STIPEND if value else 0
    assert meter_fields(meter) == meter_fields(
        fresh_frame(
            gas, gas_left - extra_gas - memory_cost + stipend, reservoir
        ).gas_meter
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
    vm_exceptions: ModuleType,
    gas_left: int,
    reservoir: int,
    parent_ops: List[MeterOp],
    children: List[ChildFrame],
) -> None:
    """
    Granting a child gas, running it, and merging it back creates or loses
    no gas in either pool beyond what the child itself spent.

    A successful child returns its leftovers and spill, after which the
    reservoir repays the spill; a reverted child loses only its regular
    charges; a halted child burns its regular grant. Either failure hands
    the reservoir back whole.
    """
    parent = fresh_frame(gas, gas_left, reservoir)
    apply_ops(gas, parent, parent_ops)
    meter = parent.gas_meter

    for mode, request, value, child_ops, counter, outcome in children:
        before = meter_fields(meter)

        if mode == "create":
            grant = int(gas.withhold_create_gas(meter))
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
        child_reservoir = int(gas.drain_state_gas_reservoir(meter))

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
            child.error = vm_exceptions.Revert()
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
