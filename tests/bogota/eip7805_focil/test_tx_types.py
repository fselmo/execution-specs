"""Tests EIP-7805 FOCIL inclusion-list handling across transaction types."""

import ethereum_rlp as eth_rlp
import pytest
from ethereum_types.numeric import Uint
from execution_testing import (
    AccessList,
    Account,
    Address,
    Alloc,
    AuthorizationTuple,
    Block,
    BlockchainTestFiller,
    Bytes,
    Fork,
    Op,
    Transaction,
)
from spec256k1 import PrivateKey

from .spec import ref_spec_7805

REFERENCE_SPEC_GIT_PATH = ref_spec_7805.git_path
REFERENCE_SPEC_VERSION = ref_spec_7805.version

pytestmark = [
    pytest.mark.valid_from("Bogota"),
    pytest.mark.blockchain_test_engine_only,
]


@pytest.mark.parametrize(
    "scenario",
    [
        "type_0_protected",
        "type_0_unprotected",
        "type_0_creation",
        "type_1_access_list",
        "type_1_creation",
        "type_2",
        "type_2_creation",
        "type_4_delegation",
    ],
)
def test_included_il_tx_of_each_type_is_readable(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    scenario: str,
) -> None:
    """
    Every transaction type is decodable in the inclusion list.

    Each scenario places one transaction of a given type in both the block
    body and the inclusion list. Because the transaction is present in the
    block body, the inclusion list check is satisfied only if the execution
    layer can decode it as a transaction type valid for the active fork.
    The post-state confirms the transaction also executed as expected.
    """
    sender = pre.fund_eoa()
    post: dict = {}

    match scenario:
        case "type_0_protected":
            recipient = pre.nonexistent_account()
            il_tx = Transaction(
                ty=0, sender=sender, to=recipient, value=1, protected=True
            )
            post[recipient] = Account(balance=1)
        case "type_0_unprotected":
            recipient = pre.nonexistent_account()
            il_tx = Transaction(
                ty=0, sender=sender, to=recipient, value=1, protected=False
            )
            post[recipient] = Account(balance=1)
        case "type_0_creation":
            il_tx = Transaction(ty=0, sender=sender, to=None, data=Op.STOP)
            post[il_tx.created_contract] = Account(nonce=1)
        case "type_1_access_list":
            recipient = pre.nonexistent_account()
            il_tx = Transaction(
                ty=1,
                sender=sender,
                to=recipient,
                value=1,
                access_list=[
                    AccessList(address=recipient, storage_keys=[0x01])
                ],
            )
            post[recipient] = Account(balance=1)
        case "type_1_creation":
            il_tx = Transaction(
                ty=1,
                sender=sender,
                to=None,
                data=Op.STOP,
                access_list=[AccessList(address=sender, storage_keys=[0x01])],
            )
            post[il_tx.created_contract] = Account(nonce=1)
        case "type_2":
            recipient = pre.nonexistent_account()
            il_tx = Transaction(ty=2, sender=sender, to=recipient, value=1)
            post[recipient] = Account(balance=1)
        case "type_2_creation":
            il_tx = Transaction(ty=2, sender=sender, to=None, data=Op.STOP)
            post[il_tx.created_contract] = Account(nonce=1)
        case "type_4_delegation":
            authority = pre.fund_eoa()
            delegate_target = pre.deploy_contract(code=Op.STOP)
            il_tx = Transaction(
                ty=4,
                sender=sender,
                to=sender,
                authorization_list=[
                    AuthorizationTuple(
                        address=delegate_target, signer=authority
                    )
                ],
            )
            # A valid authorization bumps the authority's nonce and sets its
            # delegation designation.
            post[authority] = Account(nonce=1)
        case _:
            raise ValueError(f"unknown scenario: {scenario}")

    blockchain_test(
        pre=pre,
        post=post,
        blocks=[
            Block(
                txs=[il_tx],
                inclusion_list_txs=[il_tx],
                expected_inclusion_list_satisfied=True,
            )
        ],
    )


# L2 transaction types, whose type bytes Bogota does not define.
FEE_TOKEN_TX_TYPE = 0x7D
PRIVILEGED_TX_TYPE = 0x7E


def l2_typed_entry(type_byte: int, tx: Transaction) -> Bytes:
    """
    Re-encode a type-2 `tx` as an L2 transaction type: 0x7e carries its
    sender in place of a signature, 0x7d adds a fee token and is signed.
    """
    fields = tx.to_list(signing=True)
    if type_byte == PRIVILEGED_TX_TYPE:
        payload = [*fields, tx.sender]
    elif type_byte == FEE_TOKEN_TX_TYPE:
        assert tx.sender is not None and tx.sender.key is not None
        # No check reads the fee token, so any address will do.
        unsigned = [*fields, Address(0)]
        signing_hash = Bytes(
            bytes([type_byte]) + eth_rlp.encode(unsigned)
        ).keccak256()
        signature = PrivateKey(tx.sender.key).sign_recoverable(signing_hash)
        payload = [
            *unsigned,
            Uint(signature[64]),
            Uint(int.from_bytes(signature[0:32], "big")),
            Uint(int.from_bytes(signature[32:64], "big")),
        ]
    else:
        raise ValueError(f"unknown type byte: {type_byte:#x}")
    return Bytes(bytes([type_byte]) + eth_rlp.encode(payload))


@pytest.mark.parametrize(
    "type_byte",
    [
        pytest.param(FEE_TOKEN_TX_TYPE, id="fee_token_0x7d"),
        pytest.param(PRIVILEGED_TX_TYPE, id="privileged_0x7e"),
    ],
)
def test_pending_il_entry_of_l2_type_is_skipped(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    fork: Fork,
    type_byte: int,
) -> None:
    """
    An inclusion list entry with an L2 transaction type byte is skipped.

    The entry would be an appendable transfer from a funded sender if its
    type were defined, but Bogota cannot decode it, so omitting it leaves
    the block satisfied.
    """
    assert type_byte not in fork.tx_types()
    tx = Transaction(
        ty=2,
        sender=pre.fund_eoa(),
        to=pre.nonexistent_account(),
        gas_limit=fork.transaction_intrinsic_cost_calculator()(),
    )

    blockchain_test(
        pre=pre,
        post={},
        blocks=[
            Block(
                txs=[],
                inclusion_list_txs=[
                    tx.copy(rlp_override=l2_typed_entry(type_byte, tx))
                ],
                expected_inclusion_list_satisfied=True,
            )
        ],
    )
