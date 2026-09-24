"""
Converter module for transforming fuzzer DTOs to EEST domain models.

This module performs explicit transformation from fuzzer's
JSON-RPC format (captured in DTOs) to EEST's internal domain
models (Transaction, Account, etc.).

Key Responsibilities:
1. Field mapping (gas → gas_limit, from → sender, etc.)
2. Creating EOA objects from private keys
3. Building proper EEST domain models with all required context
4. Preventing TestAddress pollution by setting sender
   BEFORE model_post_init
"""

from typing import Dict, List, Optional

from execution_testing.base_types import Account, Address, Hash, HexNumber
from execution_testing.forks import Fork
from execution_testing.fuzzing import (
    blockhash_history,
    require_blockhash_history,
)
from execution_testing.specs import Block, BlockchainTest, StateTest
from execution_testing.test_types import (
    Alloc,
    AuthorizationTuple,
    Environment,
    Transaction,
    Withdrawal,
)
from execution_testing.test_types.account_types import EOA

from .models import (
    FuzzerAccountInput,
    FuzzerAuthorizationInput,
    FuzzerOutput,
    FuzzerTransactionInput,
)


def fuzzer_account_to_eest_account(
    fuzzer_account: FuzzerAccountInput,
) -> Account:
    """
    Convert fuzzer account DTO to EEST Account domain model.

    Args:
        fuzzer_account: Raw account data from fuzzer

    Returns:
        EEST Account ready for pre-state

    """
    return Account(
        balance=fuzzer_account.balance,
        nonce=fuzzer_account.nonce,
        code=fuzzer_account.code,
        storage=fuzzer_account.storage,
    )


def fuzzer_authorization_to_eest(
    fuzzer_auth: FuzzerAuthorizationInput,
) -> AuthorizationTuple:
    """
    Convert fuzzer authorization DTO to EEST AuthorizationTuple.

    Args:
        fuzzer_auth: Raw authorization data from fuzzer

    Returns:
        EEST AuthorizationTuple for EIP-7702 transactions

    """
    if fuzzer_auth.signer_key is not None:
        return AuthorizationTuple(
            chain_id=fuzzer_auth.chain_id,
            address=fuzzer_auth.address,
            nonce=fuzzer_auth.nonce,
            signer=EOA(key=fuzzer_auth.signer_key),
        )
    return AuthorizationTuple(
        chain_id=fuzzer_auth.chain_id,
        address=fuzzer_auth.address,
        nonce=fuzzer_auth.nonce,
        v=fuzzer_auth.v,
        r=fuzzer_auth.r,
        s=fuzzer_auth.s,
    )


def fuzzer_transaction_to_eest_transaction(
    fuzzer_tx: FuzzerTransactionInput,
    sender_eoa: EOA,
) -> Transaction:
    """
    Convert fuzzer transaction DTO to EEST Transaction domain model.

    This function performs explicit field mapping and MUST set sender BEFORE
    calling Transaction constructor to prevent TestAddress injection.

    Key Mappings:
    - fuzzer_tx.gas → transaction.gas_limit (JSON-RPC → EEST naming)
    - fuzzer_tx.from_ → sender_eoa (Address → EOA with private key)
    - fuzzer_tx.data → transaction.data (same field, explicit for clarity)

    Args:
        fuzzer_tx: Raw transaction data from fuzzer
        sender_eoa: EOA object created from private key (prevents TestAddress)

    Returns:
        EEST Transaction ready for block generation

    """
    # Build authorization list if present
    auth_list = None
    if fuzzer_tx.authorization_list:
        auth_list = [
            fuzzer_authorization_to_eest(auth)
            for auth in fuzzer_tx.authorization_list
        ]

    # Create Transaction with sender set BEFORE model_post_init runs
    # This prevents Transaction.model_post_init from injecting TestAddress
    return Transaction(
        sender=sender_eoa,  # ✓ Set explicitly to prevent TestAddress
        to=fuzzer_tx.to,
        gas_limit=fuzzer_tx.gas,  # ✓ Explicit mapping: gas → gas_limit
        gas_price=fuzzer_tx.gas_price,
        max_fee_per_gas=fuzzer_tx.max_fee_per_gas,
        max_priority_fee_per_gas=fuzzer_tx.max_priority_fee_per_gas,
        nonce=fuzzer_tx.nonce,
        data=fuzzer_tx.data,
        value=fuzzer_tx.value,
        access_list=fuzzer_tx.access_list,
        blob_versioned_hashes=fuzzer_tx.blob_versioned_hashes,
        max_fee_per_blob_gas=fuzzer_tx.max_fee_per_blob_gas,
        authorization_list=auth_list,
    )


def create_sender_eoa_map(
    accounts: Dict[Address, FuzzerAccountInput],
) -> Dict[Address, EOA]:
    """
    Create map of addresses to EOA objects from accounts with private keys.

    Args:
        accounts: Dictionary of address to fuzzer account data

    Returns:
        Dictionary mapping addresses to EOA objects for transaction signing

    Raises:
        AssertionError: If private key doesn't match the account address

    """
    senders: Dict[Address, EOA] = {}

    for addr, account in accounts.items():
        if account.private_key is None:
            continue

        # Create EOA from private key
        sender = EOA(key=account.private_key)

        # Verify private key matches address (safety check)
        assert Address(sender) == addr, (
            f"Private key for account {addr} does not match derived "
            f"address {sender}"
        )

        senders[addr] = sender

    return senders


class UnresolvedGasError(ValueError):
    """A case reached conversion with a gas limit still to be measured."""


def require_resolved_gas(fuzzer_output: FuzzerOutput) -> None:
    """
    Refuse a case whose derived gas limits were never measured.

    Converting it would run the drawn `gas` instead of the declared need
    times fraction, so the lane that forgot `resolve_measured_gas` would
    quietly run a different case from every other lane.
    """
    pending = [
        index
        for index, tx in enumerate(fuzzer_output.transactions)
        if tx.gas_need_fraction is not None
    ]
    if pending:
        raise UnresolvedGasError(
            f"transactions {pending} carry a gas need fraction; call "
            "resolve_measured_gas before converting"
        )


def blockchain_test_from_fuzzer(
    fuzzer_output: FuzzerOutput,
    fork: Fork,
    num_blocks: Optional[int] = None,
    block_strategy: str = "distribute",
    block_time: int = 12,
) -> BlockchainTest:
    """
    Convert fuzzer output to BlockchainTest instance.

    This is the main entry point for fuzzer-to-EEST conversion.
    It orchestrates:
    1. Parsing and validation (already done by FuzzerOutput DTO)
    2. Creating EOA objects from private keys
    3. Converting DTOs to domain models
    4. Building blocks and test structure

    Args:
        fuzzer_output: Parsed and validated fuzzer output (DTO)
        fork: Fork to use for the test
        num_blocks: Number of blocks to generate; the case's own
                    `block_count` when not given
        block_strategy: How to distribute transactions across blocks
                       - "distribute": Split evenly maintaining
                         nonce order
                       - "first-block": All transactions in first
                         block
        block_time: Seconds between block timestamps

    Returns:
        BlockchainTest instance ready for fixture generation

    Raises:
        AssertionError: If invariants are violated
                       (sender validation, etc.)

    """
    require_resolved_gas(fuzzer_output)
    # Step 1: Convert accounts to EEST Account domain models
    pre_dict: Dict[Address, Account | None] = {}
    for addr, fuzzer_account in fuzzer_output.accounts.items():
        pre_dict[addr] = fuzzer_account_to_eest_account(fuzzer_account)
    pre = Alloc(pre_dict)

    # Step 2: Create EOA map for transaction signing
    sender_eoa_map = create_sender_eoa_map(fuzzer_output.accounts)

    # Step 3: Convert transactions to EEST Transaction domain models
    eest_transactions: list[Transaction] = []
    for fuzzer_tx in fuzzer_output.transactions:
        # Verify sender has private key
        assert fuzzer_tx.from_ in sender_eoa_map, (
            f"Sender {fuzzer_tx.from_} not found in accounts with private keys"
        )

        # Convert with explicit sender (prevents TestAddress injection)
        eest_tx = fuzzer_transaction_to_eest_transaction(
            fuzzer_tx,
            sender_eoa=sender_eoa_map[fuzzer_tx.from_],
        )
        eest_transactions.append(eest_tx)

    # Step 4: Build genesis environment
    env = fuzzer_output.env
    genesis_env = Environment(
        fee_recipient=env.fee_recipient,
        difficulty=0,  # Post-merge
        gas_limit=int(env.gas_limit),
        number=0,
        timestamp=HexNumber(int(env.timestamp) - 12),
        prev_randao=env.prev_randao or Hash(0),
        base_fee_per_gas=env.base_fee_per_gas
        if env.base_fee_per_gas
        else None,
        excess_blob_gas=env.excess_blob_gas if env.excess_blob_gas else None,
        blob_gas_used=env.blob_gas_used if env.blob_gas_used else None,
    ).set_fork_requirements(fork)

    # Step 5: Distribute transactions across blocks
    assignment = None
    if num_blocks is None:
        # The case says which block each transaction was drawn for, and its
        # fees were drawn for that block's base fee, so it is honoured
        # rather than re-split.
        num_blocks = fuzzer_output.block_count
        block_strategy = "assigned"
        assignment = [tx.block for tx in fuzzer_output.transactions]
    blocks = _distribute_transactions_to_blocks(
        eest_transactions,
        num_blocks,
        block_strategy,
        block_time,
        env,
        fuzzer_output.parent_beacon_block_root,
        assignment=assignment,
        withdrawals=[
            Withdrawal(
                index=w.index,
                validator_index=w.validator_index,
                address=w.address,
                amount=w.amount,
            )
            for w in fuzzer_output.withdrawals
        ],
    )

    return BlockchainTest(
        pre=pre,
        fork=fork,
        blocks=blocks,
        post={},  # Post-state verification can be added later
        genesis_environment=genesis_env,
        chain_id=fuzzer_output.chain_id,
    )


def state_test_from_fuzzer(
    fuzzer_output: FuzzerOutput, fork: Fork
) -> StateTest:
    """
    Convert a single-transaction case to a `StateTest`.

    A state test is what a client team runs with zero setup, so it is the
    reproducer format for a minimized case with exactly one transaction.
    The environment is the one the case's block would have had.
    """
    require_resolved_gas(fuzzer_output)
    if len(fuzzer_output.transactions) != 1:
        raise ValueError(
            "a state test carries one transaction; this case has "
            f"{len(fuzzer_output.transactions)}"
        )
    (fuzzer_tx,) = fuzzer_output.transactions
    pre = Alloc(
        {
            addr: fuzzer_account_to_eest_account(account)
            for addr, account in fuzzer_output.accounts.items()
        }
    )
    sender_eoa_map = create_sender_eoa_map(fuzzer_output.accounts)
    tx = fuzzer_transaction_to_eest_transaction(
        fuzzer_tx, sender_eoa=sender_eoa_map[fuzzer_tx.from_]
    )
    env = fuzzer_output.env
    number = 1
    block_env = Environment(
        fee_recipient=env.fee_recipient,
        difficulty=0,
        gas_limit=int(env.gas_limit),
        number=number,
        block_hashes=blockhash_history(number),
        timestamp=env.timestamp,
        prev_randao=env.prev_randao or Hash(0),
        base_fee_per_gas=env.base_fee_per_gas
        if env.base_fee_per_gas
        else None,
        excess_blob_gas=env.excess_blob_gas if env.excess_blob_gas else None,
        blob_gas_used=env.blob_gas_used if env.blob_gas_used else None,
        parent_beacon_block_root=fuzzer_output.parent_beacon_block_root,
    ).set_fork_requirements(fork)
    require_blockhash_history(block_env)
    return StateTest(
        pre=pre,
        post={},
        tx=tx,
        env=block_env,
        fork=fork,
        chain_id=fuzzer_output.chain_id,
    )


def _distribute_transactions_to_blocks(
    transactions: list[Transaction],
    num_blocks: int,
    strategy: str,
    block_time: int,
    base_env: Environment,
    parent_beacon_block_root: Hash | None,
    assignment: List[int] | None = None,
    withdrawals: List[Withdrawal] | None = None,
) -> list[Block]:
    """
    Distribute transactions across multiple blocks.

    Args:
        transactions: List of EEST Transaction objects (ready for execution)
        num_blocks: Number of blocks to create
        strategy: Distribution strategy ("assigned", "distribute" or
                  "first-block")
        block_time: Seconds between blocks
        base_env: Base environment for first block
        parent_beacon_block_root: Beacon root (only for first block)
        assignment: The block of each transaction, for "assigned"
        withdrawals: Withdrawals for the last block, if any

    Returns:
        List of Block objects

    """
    if strategy == "assigned":
        if assignment is None or len(assignment) != len(transactions):
            raise ValueError("the assigned strategy needs one block per tx")
        if assignment != sorted(assignment) or not all(
            0 <= block < num_blocks for block in assignment
        ):
            # Out of order would put a sender's later nonce in an earlier
            # block than its earlier one.
            raise ValueError(f"block assignment {assignment} is not in order")
        tx_distribution = [
            [
                tx
                for tx, block in zip(transactions, assignment, strict=True)
                if block == i
            ]
            for i in range(num_blocks)
        ]
    elif strategy == "first-block":
        # All transactions in first block, rest empty
        tx_distribution = [transactions] + [[] for _ in range(num_blocks - 1)]
    elif strategy == "distribute":
        # Split transactions evenly maintaining nonce order
        if not transactions:
            tx_distribution = [[] for _ in range(num_blocks)]
        else:
            result = []
            chunk_size = len(transactions) // num_blocks
            remainder = len(transactions) % num_blocks

            start = 0
            for i in range(num_blocks):
                # Distribute remainder across first blocks
                current_chunk_size = chunk_size + (1 if i < remainder else 0)
                end = start + current_chunk_size
                result.append(transactions[start:end])
                start = end

            tx_distribution = result
    else:
        raise ValueError(f"Unknown block strategy: {strategy}")

    # Create blocks with incrementing timestamps
    base_timestamp = int(base_env.timestamp)
    blocks = []
    for i, block_txs in enumerate(tx_distribution):
        blocks.append(
            Block(
                txs=block_txs,
                timestamp=base_timestamp + (i * block_time),
                fee_recipient=base_env.fee_recipient,
                parent_beacon_block_root=parent_beacon_block_root
                if i == 0
                else None,
                # Withdrawals go on the last block, after every transaction
                # the case drew, which is where the spec processes them.
                withdrawals=withdrawals
                if withdrawals and i == len(tx_distribution) - 1
                else None,
            )
        )

    return blocks
