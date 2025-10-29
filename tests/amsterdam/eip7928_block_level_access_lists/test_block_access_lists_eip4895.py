"""Tests for the effects of EIP-4895 withdrawals on EIP-7928."""

import pytest
from execution_testing import (
    Account,
    Address,
    Alloc,
    BalAccountExpectation,
    BalBalanceChange,
    BalNonceChange,
    Block,
    BlockAccessListExpectation,
    BlockchainTestFiller,
    Op,
    Transaction,
    Withdrawal,
)

from .spec import ref_spec_7928

REFERENCE_SPEC_GIT_PATH = ref_spec_7928.git_path
REFERENCE_SPEC_VERSION = ref_spec_7928.version

pytestmark = pytest.mark.valid_from("Amsterdam")

ONE_GWEI = 10**9


def test_bal_withdrawal_empty_block(
    pre: Alloc,
    blockchain_test: BlockchainTestFiller,
) -> None:
    """
    Ensure BAL captures withdrawal balance changes in empty block.

    Charlie starts with 1 gwei balance (existing account).
    Block with 0 transactions and 1 withdrawal of 10 gwei to Charlie.
    Charlie ends with 11 gwei balance.
    """
    charlie = pre.fund_eoa(amount=1 * ONE_GWEI)

    block = Block(
        txs=[],
        withdrawals=[
            Withdrawal(
                index=0,
                validator_index=0,
                address=charlie,
                amount=10,
            )
        ],
        expected_block_access_list=BlockAccessListExpectation(
            account_expectations={
                charlie: BalAccountExpectation(
                    balance_changes=[
                        BalBalanceChange(
                            tx_index=1, post_balance=11 * ONE_GWEI
                        )
                    ],
                ),
            }
        ),
    )

    blockchain_test(
        pre=pre,
        blocks=[block],
        post={
            charlie: Account(balance=11 * ONE_GWEI),
        },
    )


def test_bal_withdrawal_with_transaction(
    pre: Alloc,
    blockchain_test: BlockchainTestFiller,
) -> None:
    """
    Ensure BAL captures both transaction and withdrawal balance changes.

    Alice starts with 1 ETH, Bob starts with 0, Charlie starts with 0.
    Alice sends 5 wei to Bob.
    Charlie receives 10 gwei withdrawal.
    Bob ends with 5 wei, Charlie ends with 10 gwei.
    """
    alice = pre.fund_eoa()
    bob = pre.fund_eoa(amount=0)
    charlie = pre.fund_eoa(amount=0)

    tx = Transaction(
        sender=alice,
        to=bob,
        value=5,
        gas_price=0xA,
    )

    block = Block(
        txs=[tx],
        withdrawals=[
            Withdrawal(
                index=0,
                validator_index=0,
                address=charlie,
                amount=10,
            )
        ],
        expected_block_access_list=BlockAccessListExpectation(
            account_expectations={
                alice: BalAccountExpectation(
                    nonce_changes=[BalNonceChange(tx_index=1, post_nonce=1)],
                ),
                bob: BalAccountExpectation(
                    balance_changes=[
                        BalBalanceChange(tx_index=1, post_balance=5)
                    ],
                ),
                charlie: BalAccountExpectation(
                    balance_changes=[
                        BalBalanceChange(
                            tx_index=2, post_balance=10 * ONE_GWEI
                        )
                    ],
                ),
            }
        ),
    )

    blockchain_test(
        pre=pre,
        blocks=[block],
        post={
            alice: Account(nonce=1),
            bob: Account(balance=5),
            charlie: Account(balance=10 * ONE_GWEI),
        },
    )


def test_bal_withdrawal_to_nonexistent_account(
    pre: Alloc,
    blockchain_test: BlockchainTestFiller,
) -> None:
    """
    Ensure BAL captures withdrawal to non-existent account.

    Charlie is a non-existent address (not in pre-state).
    Block with 0 transactions and 1 withdrawal of 10 gwei to Charlie.
    Charlie ends with 10 gwei balance.
    """
    charlie = Address(0xCC)

    block = Block(
        txs=[],
        withdrawals=[
            Withdrawal(
                index=0,
                validator_index=0,
                address=charlie,
                amount=10,
            )
        ],
        expected_block_access_list=BlockAccessListExpectation(
            account_expectations={
                charlie: BalAccountExpectation(
                    balance_changes=[
                        BalBalanceChange(
                            tx_index=1, post_balance=10 * ONE_GWEI
                        )
                    ],
                ),
            }
        ),
    )

    blockchain_test(
        pre=pre,
        blocks=[block],
        post={
            charlie: Account(balance=10 * ONE_GWEI),
        },
    )


def test_bal_withdrawal_no_evm_execution(
    pre: Alloc,
    blockchain_test: BlockchainTestFiller,
) -> None:
    """
    Ensure BAL captures withdrawal without triggering EVM execution.

    Oracle contract starts with 0 balance and storage slot 0x01 = 0x42.
    Oracle's code writes 0xFF to slot 0x01 when called.
    Block with 0 transactions and 1 withdrawal of 10 gwei to Oracle.
    Storage slot 0x01 remains 0x42 (EVM never executes).
    """
    oracle = pre.deploy_contract(
        code=Op.SSTORE(0x01, 0xFF),
        storage={0x01: 0x42},
    )

    block = Block(
        txs=[],
        withdrawals=[
            Withdrawal(
                index=0,
                validator_index=0,
                address=oracle,
                amount=10,
            )
        ],
        expected_block_access_list=BlockAccessListExpectation(
            account_expectations={
                oracle: BalAccountExpectation(
                    balance_changes=[
                        BalBalanceChange(
                            tx_index=1, post_balance=10 * ONE_GWEI
                        )
                    ],
                    storage_reads=[],
                    storage_changes=[],
                ),
            }
        ),
    )

    blockchain_test(
        pre=pre,
        blocks=[block],
        post={
            oracle: Account(
                balance=10 * ONE_GWEI,
                storage={0x01: 0x42},
            ),
        },
    )
