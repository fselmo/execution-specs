"""
Hardfork Utility Functions For The Message Data-structure
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. contents:: Table of Contents
    :backlinks: none
    :local:

Introduction
------------

Message specific functions used in this tangerine whistle version of
specification.
"""
from ethereum_types.bytes import Bytes, Bytes0
from ethereum_types.numeric import Uint

from ..fork_types import Address
from ..state import get_account
from ..transactions import Transaction
from ..vm import BlockEnvironment, Message, TransactionEnvironment
from .address import compute_contract_address


def prepare_message(
    block_env: BlockEnvironment,
    tx_env: TransactionEnvironment,
    tx: Transaction,
) -> Message:
    """
    Execute a transaction against the provided environment.

    Parameters
    ----------
    block_env :
        Environment for the Ethereum Virtual Machine.
    tx_env :
        Environment for the transaction.
    tx :
        Transaction to be executed.

    Returns
    -------
    message: `ethereum.tangerine_whistle.vm.Message`
        Items containing contract creation or message call specific data.
    """
    if isinstance(tx.to, Bytes0):
        current_target = compute_contract_address(
            tx_env.origin,
            get_account(block_env.state, tx_env.origin).nonce - Uint(1),
        )
        msg_data = Bytes(b"")
        code = tx.data
        code_address = None
    elif isinstance(tx.to, Address):
        current_target = tx.to
        msg_data = tx.data
        code = get_account(block_env.state, tx.to).code

        code_address = tx.to
    else:
        raise AssertionError("Target must be address or empty bytes")

    return Message(
        block_env=block_env,
        tx_env=tx_env,
        caller=tx_env.origin,
        target=tx.to,
        gas=tx_env.gas,
        value=tx.value,
        data=msg_data,
        code=code,
        depth=Uint(0),
        current_target=current_target,
        code_address=code_address,
        should_transfer_value=True,
        parent_evm=None,
    )
