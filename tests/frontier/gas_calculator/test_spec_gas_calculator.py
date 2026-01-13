"""
Tests verifying spec-based gas calculation accuracy.

These tests verify that the `Fork.execution_gas_calculator()` method correctly
calculates EXACT gas costs by running bytecode through the actual spec EVM.

The tests use `expected_receipt` to verify that the calculated gas matches
actual execution - no buffers allowed.
"""

import pytest
from execution_testing import (
    Account,
    Alloc,
    Environment,
    Op,
    StateTestFiller,
    Transaction,
    TransactionReceipt,
)
from execution_testing.forks.helpers import Fork


@pytest.mark.valid_from("Byzantium")
def test_simple_arithmetic_exact_gas(
    state_test: StateTestFiller,
    pre: Alloc,
    fork: Fork,
) -> None:
    """
    Test EXACT gas calculation for simple arithmetic operations.

    Verifies that execution_gas_calculator returns the precise gas cost.
    No buffer - uses expected_receipt to verify exact match.
    """
    slot_result = 1

    code = (
        Op.PUSH1(5)
        + Op.PUSH1(3)
        + Op.ADD
        + Op.PUSH1(slot_result)
        + Op.SSTORE
        + Op.STOP
    )

    contract_address = pre.deploy_contract(code=code)
    sender = pre.fund_eoa()

    # Calculate EXACT execution gas
    gas_calc = fork.execution_gas_calculator()
    gas_result = gas_calc(code=code, pre=pre, target=contract_address)

    # Calculate EXACT intrinsic gas (no calldata, not contract creation)
    intrinsic_calc = fork.transaction_intrinsic_cost_calculator()
    intrinsic_gas = intrinsic_calc(calldata=b"", contract_creation=False)

    # Total gas should be EXACT - no buffer
    total_gas = gas_result.total_gas + intrinsic_gas

    tx = Transaction(
        sender=sender,
        to=contract_address,
        gas_limit=total_gas,
        value=0,
        # Verify exact gas usage
        expected_receipt=TransactionReceipt(gas_used=total_gas),
    )

    post = {
        contract_address: Account(
            storage={
                slot_result: 8,  # 5 + 3 = 8
            }
        )
    }

    state_test(env=Environment(), pre=pre, post=post, tx=tx)


@pytest.mark.valid_from("Berlin")
def test_sload_cold_warm_exact_gas(
    state_test: StateTestFiller,
    pre: Alloc,
    fork: Fork,
) -> None:
    """
    Test EXACT gas calculation for SLOAD with cold and warm access.

    First SLOAD is cold (2100 gas), second SLOAD of same slot is warm
    (100 gas). Verifies the gas calculator correctly tracks access
    warming.
    """
    slot_to_load = 0x42
    slot_result_1 = 1
    slot_result_2 = 2

    code = (
        Op.PUSH1(slot_to_load)
        + Op.SLOAD  # Cold: 2100 gas
        + Op.PUSH1(slot_result_1)
        + Op.SSTORE
        + Op.PUSH1(slot_to_load)
        + Op.SLOAD  # Warm: 100 gas
        + Op.PUSH1(slot_result_2)
        + Op.SSTORE
        + Op.STOP
    )

    contract_address = pre.deploy_contract(
        code=code,
        storage={slot_to_load: 0xBEEF},
    )
    sender = pre.fund_eoa()

    gas_calc = fork.execution_gas_calculator()
    gas_result = gas_calc(code=code, pre=pre, target=contract_address)

    intrinsic_calc = fork.transaction_intrinsic_cost_calculator()
    intrinsic_gas = intrinsic_calc(calldata=b"", contract_creation=False)

    total_gas = gas_result.total_gas + intrinsic_gas

    tx = Transaction(
        sender=sender,
        to=contract_address,
        gas_limit=total_gas,
        value=0,
        expected_receipt=TransactionReceipt(gas_used=total_gas),
    )

    post = {
        contract_address: Account(
            storage={
                slot_to_load: 0xBEEF,
                slot_result_1: 0xBEEF,
                slot_result_2: 0xBEEF,
            }
        )
    }

    state_test(env=Environment(), pre=pre, post=post, tx=tx)


@pytest.mark.valid_from("Berlin")
def test_sstore_clear_refund_exact_gas(
    state_test: StateTestFiller,
    pre: Alloc,
    fork: Fork,
) -> None:
    """
    Test EXACT gas calculation for SSTORE clearing a slot (non-zero to zero).

    Verifies both execution gas and refund are calculated correctly.
    The refund is subtracted from gas_used at transaction end:
    - Pre-London: max refund = gas_used / 2
    - London+: max refund = gas_used / 5 (EIP-3529)
    """
    slot_to_clear = 0x01
    slot_result = 0x02

    code = (
        Op.PUSH1(0)  # value = 0
        + Op.PUSH1(slot_to_clear)
        + Op.SSTORE  # Clear the slot
        + Op.PUSH1(1)
        + Op.PUSH1(slot_result)
        + Op.SSTORE  # Mark success
        + Op.STOP
    )

    contract_address = pre.deploy_contract(
        code=code,
        storage={slot_to_clear: 100},
    )
    sender = pre.fund_eoa()

    gas_calc = fork.execution_gas_calculator()
    gas_result = gas_calc(code=code, pre=pre, target=contract_address)

    # Verify we got a refund for clearing storage
    assert gas_result.refund > 0, "Should have refund for clearing storage"

    intrinsic_calc = fork.transaction_intrinsic_cost_calculator()
    intrinsic_gas = intrinsic_calc(calldata=b"", contract_creation=False)

    gas_limit = gas_result.total_gas + intrinsic_gas

    # Use convenience method to calculate expected gas_used after refund cap
    expected_gas_used = gas_result.gas_used_after_refund(
        intrinsic_gas=intrinsic_gas,
        max_refund_quotient=fork.max_refund_quotient(),
    )

    tx = Transaction(
        sender=sender,
        to=contract_address,
        gas_limit=gas_limit,
        value=0,
        expected_receipt=TransactionReceipt(gas_used=expected_gas_used),
    )

    post = {
        contract_address: Account(
            storage={
                slot_to_clear: 0,  # Cleared
                slot_result: 1,  # Success marker
            }
        )
    }

    state_test(env=Environment(), pre=pre, post=post, tx=tx)


@pytest.mark.valid_from("Istanbul")
def test_selfbalance_exact_gas(
    state_test: StateTestFiller,
    pre: Alloc,
    fork: Fork,
) -> None:
    """
    Test EXACT gas calculation for SELFBALANCE opcode.

    SELFBALANCE costs 5 gas (GAS_LOW) - always warm since it's self-access.
    """
    slot_result_1 = 1
    slot_result_2 = 2
    contract_balance = 5000

    code = (
        Op.SELFBALANCE  # 5 gas
        + Op.PUSH1(slot_result_1)
        + Op.SSTORE
        + Op.SELFBALANCE  # 5 gas
        + Op.PUSH1(slot_result_2)
        + Op.SSTORE
        + Op.STOP
    )

    contract_address = pre.deploy_contract(code=code, balance=contract_balance)
    sender = pre.fund_eoa()

    gas_calc = fork.execution_gas_calculator()
    gas_result = gas_calc(code=code, pre=pre, target=contract_address)

    intrinsic_calc = fork.transaction_intrinsic_cost_calculator()
    intrinsic_gas = intrinsic_calc(calldata=b"", contract_creation=False)

    total_gas = gas_result.total_gas + intrinsic_gas

    tx = Transaction(
        sender=sender,
        to=contract_address,
        gas_limit=total_gas,
        value=0,
        expected_receipt=TransactionReceipt(gas_used=total_gas),
    )

    post = {
        contract_address: Account(
            balance=contract_balance,
            storage={
                slot_result_1: contract_balance,
                slot_result_2: contract_balance,
            },
        )
    }

    state_test(env=Environment(), pre=pre, post=post, tx=tx)


@pytest.mark.valid_from("Byzantium")
def test_memory_expansion_exact_gas(
    state_test: StateTestFiller,
    pre: Alloc,
    fork: Fork,
) -> None:
    """
    Test EXACT gas calculation with memory expansion.

    Memory expansion follows quadratic cost formula:
    cost = G_MEMORY * words + words^2 / 512
    """
    slot_result = 1

    code = (
        Op.PUSH1(0x42)
        + Op.PUSH1(0)
        + Op.MSTORE  # Memory expansion to 32 bytes
        + Op.PUSH1(0x43)
        + Op.PUSH1(32)
        + Op.MSTORE  # Memory expansion to 64 bytes
        + Op.PUSH1(0x44)
        + Op.PUSH1(64)
        + Op.MSTORE  # Memory expansion to 96 bytes
        + Op.PUSH1(0)
        + Op.MLOAD
        + Op.PUSH1(slot_result)
        + Op.SSTORE
        + Op.STOP
    )

    contract_address = pre.deploy_contract(code=code)
    sender = pre.fund_eoa()

    gas_calc = fork.execution_gas_calculator()
    gas_result = gas_calc(code=code, pre=pre, target=contract_address)

    intrinsic_calc = fork.transaction_intrinsic_cost_calculator()
    intrinsic_gas = intrinsic_calc(calldata=b"", contract_creation=False)

    total_gas = gas_result.total_gas + intrinsic_gas

    tx = Transaction(
        sender=sender,
        to=contract_address,
        gas_limit=total_gas,
        value=0,
        expected_receipt=TransactionReceipt(gas_used=total_gas),
    )

    post = {
        contract_address: Account(
            storage={
                slot_result: 0x42,
            }
        )
    }

    state_test(env=Environment(), pre=pre, post=post, tx=tx)


@pytest.mark.valid_from("Berlin")
def test_gas_opcode_exact_gas(
    state_test: StateTestFiller,
    pre: Alloc,
    fork: Fork,
) -> None:
    """
    Test exact gas calculation with GAS opcode in the code.

    The GAS opcode itself costs 2 gas. This test verifies we correctly
    account for it in our gas calculation.
    """
    slot_result = 1

    # Code that uses GAS opcode but only stores a computed result
    code = (
        Op.GAS  # 2 gas - get remaining gas (value doesn't matter for test)
        + Op.POP  # 2 gas - discard it
        + Op.PUSH1(5)  # 3 gas
        + Op.PUSH1(3)  # 3 gas
        + Op.ADD  # 3 gas
        + Op.PUSH1(slot_result)  # 3 gas
        + Op.SSTORE  # 22100 gas (cold slot, 0->8)
        + Op.STOP  # 0 gas
    )

    contract_address = pre.deploy_contract(code=code)
    sender = pre.fund_eoa()

    gas_calc = fork.execution_gas_calculator()
    gas_result = gas_calc(code=code, pre=pre, target=contract_address)

    intrinsic_calc = fork.transaction_intrinsic_cost_calculator()
    intrinsic_gas = intrinsic_calc(calldata=b"", contract_creation=False)

    total_gas = gas_result.total_gas + intrinsic_gas

    tx = Transaction(
        sender=sender,
        to=contract_address,
        gas_limit=total_gas,
        value=0,
        expected_receipt=TransactionReceipt(gas_used=total_gas),
    )

    post = {
        contract_address: Account(
            storage={
                slot_result: 8,  # 5 + 3 = 8
            }
        )
    }

    state_test(env=Environment(), pre=pre, post=post, tx=tx)
