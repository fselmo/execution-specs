"""EVM execution utilities for gas calculation."""

import dataclasses
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Optional, Set, Type

from ethereum.trace import set_evm_trace
from ethereum_spec_tools.forks import Hardfork
from ethereum_types.bytes import Bytes, Bytes32
from ethereum_types.numeric import U64, U256, Uint

from .tracer import GasTracer

if TYPE_CHECKING:
    from execution_testing.base_types import Alloc
    from execution_testing.forks.base_fork import BaseFork

# Cache discovered spec forks to avoid repeated discovery
_SPEC_FORKS: list[Hardfork] | None = None


def _get_spec_fork(spec_module_name: str) -> Hardfork:
    """
    Get a Hardfork instance by spec module name.

    Args:
        spec_module_name: The spec module name (e.g., "cancun", "berlin")

    Returns:
        The matching Hardfork instance

    Raises:
        ValueError: If no matching spec fork is found
    """
    global _SPEC_FORKS
    if _SPEC_FORKS is None:
        _SPEC_FORKS = Hardfork.discover()

    for spec_fork in _SPEC_FORKS:
        if spec_fork.short_name == spec_module_name:
            return spec_fork

    raise ValueError(f"No spec fork found for spec module: {spec_module_name}")


@dataclass
class GasResult:
    """Result of gas calculation from EVM execution."""

    total_gas: int
    """Total gas charged during execution (before refunds)."""

    refund: int
    """Gas refund counter (e.g., from SSTORE clearing)."""

    per_opcode: list
    """Per-opcode gas breakdown (list of OpcodeGasRecord)."""

    error: Optional[Exception] = None
    """Execution error, if any."""

    def gas_used_after_refund(
        self, *, intrinsic_gas: int, max_refund_quotient: int
    ) -> int:
        """
        Calculate gas used after applying the refund cap.

        The refund is capped at gas_charged // max_refund_quotient:
        - Pre-London: max_refund_quotient = 2 (cap at 1/2)
        - London+: max_refund_quotient = 5 (cap at 1/5, per EIP-3529)

        Args:
            intrinsic_gas: Transaction intrinsic cost (21000 + calldata costs)
            max_refund_quotient: Fork's refund cap divisor (from fork.max_refund_quotient())

        Returns:
            The gas_used value that will appear in the transaction receipt
        """
        gas_charged = self.total_gas + intrinsic_gas
        max_refund = gas_charged // max_refund_quotient
        actual_refund = min(self.refund, max_refund)
        return gas_charged - actual_refund


@dataclass
class TransactionGasResult:
    """
    Complete gas calculation result for a transaction.

    This provides all the values a test writer needs without manual calculations:
    - gas_limit: Set this as the transaction's gas_limit
    - expected_gas_used: Expect this in the transaction receipt

    Example usage in tests:
        gas_result = fork.transaction_gas_calculator()(
            code=code,
            pre=pre,
            target=contract_address,
        )
        tx = Transaction(
            gas_limit=gas_result.gas_limit,
            expected_receipt=TransactionReceipt(gas_used=gas_result.expected_gas_used),
        )
    """

    gas_limit: int
    """Gas limit to set on the transaction (execution + intrinsic)."""

    expected_gas_used: int
    """Expected gas_used in receipt (after applying refund cap)."""

    execution_gas: int
    """Gas charged during EVM execution (before refunds)."""

    intrinsic_gas: int
    """Transaction intrinsic cost (21000 + calldata costs)."""

    refund: int
    """Raw refund counter from execution."""

    actual_refund: int
    """Refund actually applied (after cap)."""

    per_opcode: list
    """Per-opcode gas breakdown."""

    error: Optional[Exception] = None
    """Execution error, if any."""


def _build_dataclass_instance(cls: type, kwargs: Dict[str, Any]) -> Any:
    """
    Build a dataclass instance using only the fields it supports.

    This filters kwargs to only include fields that exist in the dataclass,
    allowing the same code to work across different fork versions with
    varying dataclass fields.

    Args:
        cls: The dataclass type to instantiate
        kwargs: All possible keyword arguments

    Returns:
        Instance of cls with only supported fields
    """
    supported_fields = {f.name for f in dataclasses.fields(cls)}
    filtered_kwargs = {
        k: v for k, v in kwargs.items() if k in supported_fields
    }
    return cls(**filtered_kwargs)


def _load_spec_modules(spec_module_name: str) -> Dict[str, Any]:
    """
    Load the spec modules for a given spec module name.

    Uses Hardfork.module() for cleaner module loading instead of raw importlib.

    Args:
        spec_module_name: The spec module name (e.g., "cancun", "spurious_dragon")

    Returns:
        Dictionary with loaded modules: state, vm, interpreter, fork_types
    """
    spec_fork = _get_spec_fork(spec_module_name)

    return {
        "state": spec_fork.module("state"),
        "vm": spec_fork.module("vm"),
        "interpreter": spec_fork.module("vm.interpreter"),
        "fork_types": spec_fork.module("fork_types"),
    }


def run_bytecode_with_pre(
    *,
    fork_cls: Type["BaseFork"],
    code: bytes,
    pre: "Alloc",
    target: bytes,
    block_number: int = 0,
    timestamp: int = 0,
    calldata: bytes = b"",
    value: int = 0,
) -> GasResult:
    """
    Run bytecode through the spec EVM using the test's pre-state.

    This function builds state from the Alloc object provided by the test,
    ensuring gas calculation uses the same addresses and balances as the
    actual test execution.

    Args:
        fork_cls: The fork class (e.g., Cancun, Berlin) - used to query fork properties
        code: Bytecode to execute
        pre: Pre-state allocation from the test (Alloc object)
        target: Target contract address (must exist in pre)
        block_number: Block number for fork property queries
        timestamp: Timestamp for fork property queries
        calldata: Call data to pass to the contract
        value: Value to send with call (in wei)

    Returns:
        GasResult with total_gas, refund, per_opcode breakdown, error
    """
    # Load fork-specific modules using fork's spec_module_name
    modules = _load_spec_modules(fork_cls.spec_module_name())
    state_mod = modules["state"]
    vm_mod = modules["vm"]
    interpreter_mod = modules["interpreter"]
    fork_types_mod = modules["fork_types"]

    # Get types from modules
    Address = fork_types_mod.Address
    Account = fork_types_mod.Account
    State = state_mod.State

    # TransientStorage was added in Cancun - older forks don't have it
    TransientStorage = getattr(state_mod, "TransientStorage", None)

    # Build state from pre allocation
    state = State()

    # Find a caller address (first EOA with balance) and track target
    caller_addr = None
    target_addr = Address(target)

    # Populate state from pre.root
    for addr, account in pre.root.items():
        if account is None:
            continue

        spec_addr = Address(bytes(addr))

        # Create account in state
        state_mod.set_account(
            state,
            spec_addr,
            Account(
                nonce=Uint(int(account.nonce)),
                balance=U256(int(account.balance)),
                code=Bytes(bytes(account.code)),
            ),
        )

        # Set storage values
        for slot, slot_value in account.storage.items():
            slot_bytes = Bytes32(int(slot).to_bytes(32, "big"))
            state_mod.set_storage(
                state, spec_addr, slot_bytes, U256(int(slot_value))
            )

        # Track first funded EOA as caller
        if caller_addr is None and account.balance > 0 and not account.code:
            caller_addr = spec_addr

    # Fallback: use a default caller if none found
    if caller_addr is None:
        caller_addr = Address(bytes(20))

    # Create transient storage (only for forks that support it)
    transient_storage = TransientStorage() if TransientStorage else None

    # Build accessed addresses (warm set)
    accessed_addresses: Set[Any] = {caller_addr, target_addr}

    # Add precompiles to warm set using fork's precompiles() method
    precompiles = fork_cls.precompiles(
        block_number=block_number, timestamp=timestamp
    )
    for precompile_addr in precompiles:
        accessed_addresses.add(Address(bytes(precompile_addr)))

    # Build block environment with ALL possible fields.
    # _build_dataclass_instance() filters to only fields the fork's dataclass supports.
    # This handles fork differences automatically:
    # - Pre-Paris has "difficulty" but not "prev_randao" → filter keeps difficulty
    # - Post-Paris has "prev_randao" but not "difficulty" → filter keeps prev_randao
    BlockEnvironment = vm_mod.BlockEnvironment
    block_env_kwargs: Dict[str, Any] = {
        "chain_id": U64(1),
        "state": state,
        "block_gas_limit": Uint(30_000_000),
        "block_hashes": [],
        "coinbase": Address(bytes(20)),
        "number": Uint(1),
        "time": U256(1000),
        # Pre-Paris field (filter removes if not in dataclass)
        "difficulty": Uint(1),
        # Post-London field
        "base_fee_per_gas": Uint(1_000_000_000),
        # Post-Paris field
        "prev_randao": Bytes32(bytes(32)),
        # Post-Cancun fields
        "excess_blob_gas": U64(0),
        "parent_beacon_block_root": Bytes32(bytes(32)),
    }
    block_env = _build_dataclass_instance(BlockEnvironment, block_env_kwargs)

    # Build transaction environment with ALL possible fields.
    TransactionEnvironment = vm_mod.TransactionEnvironment
    tx_env_kwargs: Dict[str, Any] = {
        "origin": caller_addr,
        "gas_price": Uint(1_000_000_000),
        "gas": Uint(2**63),  # Very high gas limit
        "index_in_block": Uint(0),
        "tx_hash": None,
        # Post-Berlin (EIP-2930) fields
        "access_list_addresses": set(),
        "access_list_storage_keys": set(),
        # Post-Cancun fields
        "transient_storage": transient_storage,
        "blob_versioned_hashes": (),
        # Post-Prague fields
        "authorizations": (),
    }
    tx_env = _build_dataclass_instance(TransactionEnvironment, tx_env_kwargs)

    # Build message
    Message = vm_mod.Message
    message_kwargs: Dict[str, Any] = {
        "block_env": block_env,
        "tx_env": tx_env,
        "caller": caller_addr,
        "target": target_addr,
        "current_target": target_addr,
        "gas": Uint(2**63),  # Very high gas limit
        "value": U256(value),
        "data": Bytes(calldata),
        "code_address": target_addr,
        "code": Bytes(code),
        "depth": Uint(0),
        "parent_evm": None,
        "should_transfer_value": False,  # Don't move ETH
        "is_static": False,
        "accessed_addresses": accessed_addresses,
        "accessed_storage_keys": set(),
        "disable_precompiles": frozenset(),
    }
    message = _build_dataclass_instance(Message, message_kwargs)

    # Install tracer and execute
    tracer = GasTracer()
    old_tracer = set_evm_trace(tracer)

    try:
        output = interpreter_mod.process_message_call(message)

        return GasResult(
            total_gas=tracer.total_gas,
            refund=int(output.refund_counter),
            per_opcode=list(tracer.records),
            error=output.error,
        )
    finally:
        # Always restore the original tracer
        set_evm_trace(old_tracer)
