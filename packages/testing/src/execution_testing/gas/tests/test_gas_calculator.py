"""Test gas calculator functionality using the spec's trace API."""

from execution_testing.base_types import Account, Address, Alloc, Storage
from execution_testing.forks.forks.forks import Berlin, Cancun, Prague
from execution_testing.vm import Op

from ..executor import GasResult


def create_test_alloc(
    target_code: bytes = b"",
    target_storage: dict | None = None,
    extra_accounts: dict | None = None,
) -> tuple[Alloc, Address]:
    """
    Create a test Alloc with a funded sender and target contract.

    Args:
        target_code: Bytecode for the target contract
        target_storage: Storage slots for the target contract
        extra_accounts: Additional accounts to add to the alloc

    Returns:
        Tuple of (Alloc, target_address)
    """
    sender = Address(bytes([0xCA, 0xFE] + [0] * 18))
    target = Address(bytes([0xDE, 0xAD] + [0] * 18))

    storage = Storage(target_storage) if target_storage else Storage({})

    accounts: dict[Address, Account | None] = {
        sender: Account(nonce=0, balance=10**18, code=b""),
        target: Account(nonce=1, balance=0, code=target_code, storage=storage),
    }

    if extra_accounts:
        accounts.update(extra_accounts)

    alloc = Alloc(accounts)
    return alloc, target


class TestGasCalculator:
    """Tests for the gas calculator using Fork.execution_gas_calculator()."""

    def test_simple_opcodes(self) -> None:
        """Test gas calculation for simple opcodes (PUSH, ADD)."""
        # PUSH1 1 + PUSH1 2 + ADD + STOP = 3 + 3 + 3 + 0 = 9 gas
        code = Op.PUSH1(1) + Op.PUSH1(2) + Op.ADD + Op.STOP
        pre, target = create_test_alloc(target_code=bytes(code))

        gas_calc = Cancun.execution_gas_calculator()
        result = gas_calc(code=code, pre=pre, target=target)

        assert result.total_gas == 9
        assert result.error is None
        assert len(result.per_opcode) == 4

    def test_memory_expansion(self) -> None:
        """Test gas calculation with memory expansion."""
        # PUSH1 0x42 + PUSH1 0 + MSTORE + STOP
        # MSTORE: 3 (base) + 3 (memory expansion for 32 bytes)
        code = Op.PUSH1(0x42) + Op.PUSH1(0) + Op.MSTORE + Op.STOP
        pre, target = create_test_alloc(target_code=bytes(code))

        gas_calc = Cancun.execution_gas_calculator()
        result = gas_calc(code=code, pre=pre, target=target)

        # PUSH1(3) + PUSH1(3) + MSTORE(3 base + 3 memory) + STOP(0) = 12
        assert result.total_gas == 12
        assert result.error is None

    def test_sload_cold(self) -> None:
        """Test SLOAD gas for cold storage access."""
        # PUSH32 slot + SLOAD + POP + STOP
        # SLOAD cold: 2100 gas (Cancun)
        slot = bytes(32)
        code = Op.PUSH32(slot) + Op.SLOAD + Op.POP + Op.STOP
        pre, target = create_test_alloc(target_code=bytes(code))

        gas_calc = Cancun.execution_gas_calculator()
        result = gas_calc(code=code, pre=pre, target=target)

        # PUSH32(3) + SLOAD(2100 cold) + POP(2) + STOP(0)
        assert result.total_gas == 3 + 2100 + 2 + 0
        assert result.error is None

    def test_sload_warm(self) -> None:
        """Test SLOAD gas for warm storage access (after first access)."""
        # Access same slot twice - second should be warm
        slot = bytes(32)
        code = (
            Op.PUSH32(slot)
            + Op.SLOAD
            + Op.POP
            + Op.PUSH32(slot)
            + Op.SLOAD
            + Op.POP
            + Op.STOP
        )
        pre, target = create_test_alloc(target_code=bytes(code))

        gas_calc = Cancun.execution_gas_calculator()
        result = gas_calc(code=code, pre=pre, target=target)

        # First: PUSH32(3) + SLOAD(2100 cold) + POP(2)
        # Second: PUSH32(3) + SLOAD(100 warm) + POP(2)
        # STOP(0)
        expected = 3 + 2100 + 2 + 3 + 100 + 2 + 0
        assert result.total_gas == expected
        assert result.error is None


class TestForkExecutionGasCalculator:
    """Tests for the Fork.execution_gas_calculator() method across forks."""

    def test_cancun_simple(self) -> None:
        """Test Cancun fork execution_gas_calculator with simple opcodes."""
        code = Op.PUSH1(1) + Op.PUSH1(2) + Op.ADD + Op.STOP
        pre, target = create_test_alloc(target_code=bytes(code))

        gas_calc = Cancun.execution_gas_calculator()
        result = gas_calc(code=code, pre=pre, target=target)

        assert isinstance(result, GasResult)
        assert result.total_gas == 9
        assert result.error is None

    def test_prague_simple(self) -> None:
        """Test Prague fork execution_gas_calculator with simple opcodes."""
        code = Op.PUSH1(1) + Op.PUSH1(2) + Op.ADD + Op.STOP
        pre, target = create_test_alloc(target_code=bytes(code))

        gas_calc = Prague.execution_gas_calculator()
        result = gas_calc(code=code, pre=pre, target=target)

        assert isinstance(result, GasResult)
        assert result.total_gas == 9
        assert result.error is None

    def test_berlin_sstore_cold(self) -> None:
        """Test Berlin fork SSTORE with cold storage access."""
        # SSTORE to a new slot (0 -> non-zero) with cold access
        # Gas = cold access (2100) + SSTORE_SET (20000) = 22100
        slot = 1
        code = (
            Op.PUSH1(42)  # value
            + Op.PUSH1(slot)  # key
            + Op.SSTORE
            + Op.STOP
        )
        pre, target = create_test_alloc(target_code=bytes(code))

        gas_calc = Berlin.execution_gas_calculator()
        result = gas_calc(code=code, pre=pre, target=target)

        # PUSH1(3) + PUSH1(3) + SSTORE(22100) + STOP(0) = 22106
        assert result.total_gas == 22106
        assert result.error is None

    def test_sstore_with_storage(self) -> None:
        """Test SSTORE gas with pre-existing storage value."""
        slot = bytes(32)
        # PUSH1 0 + PUSH32 slot + SSTORE + STOP
        # Setting a non-zero slot to zero: should be SSTORE_RESET cost
        code = Op.PUSH1(0) + Op.PUSH32(slot) + Op.SSTORE + Op.STOP
        pre, target = create_test_alloc(
            target_code=bytes(code),
            target_storage={slot: 100},  # Slot has value 100
        )

        gas_calc = Cancun.execution_gas_calculator()
        result = gas_calc(code=code, pre=pre, target=target)

        # This is clearing a slot (100 -> 0), which costs:
        # SSTORE_RESET (cold slot): 2100 + 2900 = 5000
        # Plus: PUSH1(3) + PUSH32(3) + STOP(0)
        # And should have a refund
        assert result.error is None
        assert result.refund > 0  # Should get refund for clearing storage

    def test_gas_by_opcode(self) -> None:
        """Test per-opcode gas breakdown."""
        code = (
            Op.PUSH1(1) + Op.PUSH1(2) + Op.ADD + Op.PUSH1(3) + Op.MUL + Op.STOP
        )
        pre, target = create_test_alloc(target_code=bytes(code))

        gas_calc = Cancun.execution_gas_calculator()
        result = gas_calc(code=code, pre=pre, target=target)

        # Check we have the right number of opcodes
        assert len(result.per_opcode) == 6

        # Check opcode names
        opcode_names = [r.opcode.name for r in result.per_opcode]
        assert opcode_names == [
            "PUSH1",
            "PUSH1",
            "ADD",
            "PUSH1",
            "MUL",
            "STOP",
        ]


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_bytecode(self) -> None:
        """Test with empty bytecode."""
        code = b""
        pre, target = create_test_alloc(target_code=code)

        gas_calc = Cancun.execution_gas_calculator()
        result = gas_calc(code=code, pre=pre, target=target)

        assert result.total_gas == 0
        assert result.error is None
        assert len(result.per_opcode) == 0

    def test_invalid_opcode(self) -> None:
        """Test with invalid opcode."""
        # 0xFE is INVALID opcode
        code = bytes([0xFE])
        pre, target = create_test_alloc(target_code=code)

        gas_calc = Cancun.execution_gas_calculator()
        result = gas_calc(code=code, pre=pre, target=target)

        # Should have an error
        assert result.error is not None

    def test_large_push(self) -> None:
        """Test PUSH32 gas cost."""
        # PUSH32 costs 3 gas regardless of size
        value = bytes(32)
        code = Op.PUSH32(value) + Op.STOP
        pre, target = create_test_alloc(target_code=bytes(code))

        gas_calc = Cancun.execution_gas_calculator()
        result = gas_calc(code=code, pre=pre, target=target)

        # PUSH32(3) + STOP(0) = 3
        assert result.total_gas == 3
        assert result.error is None

    def test_dup_and_swap(self) -> None:
        """Test DUP and SWAP opcode gas costs."""
        # PUSH1 1 + DUP1 + SWAP1 + POP + POP + STOP
        code = Op.PUSH1(1) + Op.DUP1 + Op.SWAP1 + Op.POP + Op.POP + Op.STOP
        pre, target = create_test_alloc(target_code=bytes(code))

        gas_calc = Cancun.execution_gas_calculator()
        result = gas_calc(code=code, pre=pre, target=target)

        # PUSH1(3) + DUP1(3) + SWAP1(3) + POP(2) + POP(2) + STOP(0) = 13
        assert result.total_gas == 13
        assert result.error is None


class TestWarmAddresses:
    """Tests for warm address handling."""

    def test_balance_cold_address(self) -> None:
        """Test BALANCE gas for cold address (not in pre-state)."""
        # Query balance of an address not in pre-state - should be cold
        cold_addr = bytes([0xBE, 0xEF] + [0] * 18)
        code = Op.PUSH20(cold_addr) + Op.BALANCE + Op.POP + Op.STOP
        pre, target = create_test_alloc(target_code=bytes(code))

        gas_calc = Cancun.execution_gas_calculator()
        result = gas_calc(code=code, pre=pre, target=target)

        # PUSH20(3) + BALANCE(2600 cold) + POP(2) + STOP(0) = 2605
        assert result.total_gas == 2605
        assert result.error is None

    def test_balance_warm_address(self) -> None:
        """Test BALANCE gas for warm address (exists in pre-state)."""
        # Query balance of an address that exists in pre-state
        # The target and sender are warm because they're in the accessed_addresses set
        warm_addr = bytes([0xCA, 0xFE] + [0] * 18)  # This is the sender
        code = Op.PUSH20(warm_addr) + Op.BALANCE + Op.POP + Op.STOP
        pre, target = create_test_alloc(target_code=bytes(code))

        gas_calc = Cancun.execution_gas_calculator()
        result = gas_calc(code=code, pre=pre, target=target)

        # PUSH20(3) + BALANCE(100 warm) + POP(2) + STOP(0) = 105
        assert result.total_gas == 105
        assert result.error is None

    def test_balance_address_in_pre_but_not_accessed(self) -> None:
        """Test BALANCE gas for address in pre-state but not in accessed set."""
        # Add an extra account to pre-state that isn't the caller or target
        extra_addr = Address(bytes([0xAB, 0xCD] + [0] * 18))
        code = Op.PUSH20(bytes(extra_addr)) + Op.BALANCE + Op.POP + Op.STOP
        pre, target = create_test_alloc(
            target_code=bytes(code),
            extra_accounts={
                extra_addr: Account(nonce=0, balance=1000, code=b"")
            },
        )

        gas_calc = Cancun.execution_gas_calculator()
        result = gas_calc(code=code, pre=pre, target=target)

        # The address exists in state but isn't in accessed_addresses,
        # so BALANCE should be cold (2600)
        # PUSH20(3) + BALANCE(2600 cold) + POP(2) + STOP(0) = 2605
        assert result.total_gas == 2605
        assert result.error is None
