"""Test FIFO ordering and reuse of the builder request queues."""

from typing import List

import pytest
from execution_testing import (
    Alloc,
    BalAccountExpectation,
    BalStorageChange,
    BalStorageSlot,
    Block,
    BlockAccessListExpectation,
    BlockchainTestFiller,
    BuilderDepositRequest,
    BuilderExitRequest,
    SystemContractInteractionBase,
    SystemContractInteractionContract,
)
from execution_testing.checklists import EIPChecklist

from .spec import ref_spec_8282

REFERENCE_SPEC_GIT_PATH = ref_spec_8282.git_path
REFERENCE_SPEC_VERSION = ref_spec_8282.version

pytestmark = pytest.mark.valid_from("Amsterdam")


@pytest.fixture(
    params=[
        pytest.param(
            BuilderDepositRequest,
            id="deposit",
            marks=pytest.mark.execute(
                pytest.mark.skip(reason="Stakes over one hundred ETH")
            ),
        ),
        pytest.param(BuilderExitRequest, id="exit"),
    ],
)
def request_class(
    request: pytest.FixtureRequest,
) -> type[BuilderDepositRequest] | type[BuilderExitRequest]:
    """Return the builder request type under test."""
    return request.param


@pytest.fixture
def system_contract_interactions_per_block(
    request_class: type[BuilderDepositRequest] | type[BuilderExitRequest],
) -> List[List[SystemContractInteractionBase]]:
    """Enqueue distinct records before and after draining the queue."""
    cap = request_class.max_per_block
    first = [request_class.from_index(i + 1) for i in range(cap + 3)]
    second = [request_class.from_index(cap + 4 + i) for i in range(cap)]
    # Overwrite old nonzero record words after the head and tail reset.
    last = request_class.from_index(0).copy(pubkey=0)
    if isinstance(last, BuilderDepositRequest):
        last = last.copy(withdrawal_credentials=0, signature=0)
    return [
        [SystemContractInteractionContract(requests=first)],
        [SystemContractInteractionContract(requests=second)],
        [],
        [SystemContractInteractionContract(requests=[last])],
        [],
    ]


@EIPChecklist.SystemContract.Test.Inputs.Valid()
def test_backlog_with_new_requests(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    blocks: List[Block],
    request_class: type[BuilderDepositRequest] | type[BuilderExitRequest],
) -> None:
    """Drain old requests first and reuse the emptied queue."""
    # The third block drains the remaining backlog without new transactions.
    blocks[2].expected_block_access_list = BlockAccessListExpectation(
        account_expectations={
            request_class.system_contract_address: BalAccountExpectation(
                storage_changes=[
                    BalStorageSlot(
                        slot=slot,
                        slot_changes=[
                            BalStorageChange(
                                block_access_index=1,
                                post_value=0,
                            )
                        ],
                    )
                    for slot in (
                        request_class.queue_head_slot,
                        request_class.queue_tail_slot,
                    )
                ],
            ),
        },
    )
    blockchain_test(pre=pre, blocks=blocks, post={})
