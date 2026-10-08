"""
Properties of transaction signing and sender recovery.

The framework signs each transaction, so the hash it signs and the sender
it signs as are known apart from the spec.
"""

from dataclasses import replace
from types import ModuleType
from typing import Any

import pytest
from ethereum_types.bytes import Bytes
from ethereum_types.numeric import U64, U256
from execution_testing import Transaction, TransactionType
from execution_testing.forks import Fork
from hypothesis import given
from hypothesis import strategies as st

from ethereum.crypto.elliptic_curve import SECP256K1N
from ethereum.exceptions import InvalidSignatureError
from ethereum.state import Address

from .forks import requires
from .spec_api import signing_hash, spec_transaction
from .strategies import (
    addresses,
    bytes_data,
    framework_tx,
    framework_txs,
    private_keys,
)


@given(data=st.data())
def test_signing_matches_the_framework(
    fork: Fork, transactions: ModuleType, data: st.DataObject
) -> None:
    """
    Every transaction type, with or without an EIP-155 chain id, hashes to
    what the framework signed and recovers the framework's sender.
    """
    framework = data.draw(framework_txs(fork))
    tx = spec_transaction(transactions, framework)
    assert signing_hash(transactions, tx) == (
        framework.rlp_signing_bytes().keccak256()
    )
    assert transactions.recover_sender(tx) == framework.sender


def signed_legacy_tx(key: int, data: Bytes, to: Address) -> Transaction:
    """Return a legacy call signed by `key`, without a chain id."""
    return framework_tx(
        TransactionType.LEGACY,
        protected=False,
        secret_key=key,
        data=data,
        to=to,
    ).with_signature_and_sender()


@given(key=private_keys, data=bytes_data(max_size=64), to=addresses())
def test_high_s_signatures_are_rejected_from_eip_2(
    fork: Fork, transactions: ModuleType, key: int, data: Bytes, to: Address
) -> None:
    """
    A malleable high-s signature recovers the same sender before EIP-2 and
    is rejected from EIP-2 on.
    """
    framework = signed_legacy_tx(key, data, to)
    tx = spec_transaction(transactions, framework)
    # Negating `s` and flipping the parity gives a second valid signature.
    flipped = replace(tx, v=U256(55) - tx.v, s=SECP256K1N - tx.s)
    if fork.is_eip_enabled(2):
        with pytest.raises(InvalidSignatureError):
            transactions.recover_sender(flipped)
    else:
        assert transactions.recover_sender(flipped) == framework.sender


@given(key=private_keys, data=bytes_data(max_size=64), to=addresses())
def test_zero_r_or_s_is_rejected(
    transactions: ModuleType, key: int, data: Bytes, to: Address
) -> None:
    """Zero r or s values are rejected."""
    tx = spec_transaction(transactions, signed_legacy_tx(key, data, to))
    for bad in (replace(tx, r=U256(0)), replace(tx, s=U256(0))):
        with pytest.raises(InvalidSignatureError):
            transactions.recover_sender(bad)


@requires(lambda fork: fork.supports_protected_txs())
def test_replay_protected_signing_matches_the_worked_example(
    transactions: ModuleType,
) -> None:
    """The spec reproduces the signing hash and sender of EIP-155's example."""
    example: Any = Transaction(
        ty=TransactionType.LEGACY,
        nonce=9,
        gas_price=20 * 10**9,
        gas_limit=21000,
        to=b"\x35" * 20,
        value=10**18,
        v=37,
        r=18515461264373351373200002665853028612451056578545711640558177340181847433846,
        s=46948507304638947509940763649030358759909902576025900602547168820602576006531,
    )
    tx = spec_transaction(transactions, example)
    assert transactions.signing_hash_155(tx, U64(1)) == bytes.fromhex(
        "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
    )
    assert transactions.recover_sender(tx) == Address(
        bytes.fromhex("9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f")
    )
