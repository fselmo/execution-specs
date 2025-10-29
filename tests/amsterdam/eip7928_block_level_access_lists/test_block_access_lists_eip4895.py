"""Tests for the effects of EIP-4895 withdrawals on EIP-7928."""

import pytest
from execution_testing import (
    Account,
    Alloc,
    BalAccountExpectation,
    BalBalanceChange,
    Block,
    BlockAccessListExpectation,
    BlockchainTestFiller,
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

    Charlie starts with 0 balance.
    Block with 0 transactions and 1 withdrawal of 10 gwei to Charlie.
    Charlie ends with 10 gwei balance.
    """
    charlie = pre.fund_eoa(amount=0)

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
