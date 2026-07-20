"""Properties of transaction signing and sender recovery."""

import importlib
from dataclasses import replace
from types import ModuleType
from typing import Any

import pytest
from ethereum_types.bytes import Bytes
from ethereum_types.numeric import U64, U256, Uint
from hypothesis import given
from hypothesis import strategies as st
from spec256k1 import PrivateKey

from ethereum.crypto.elliptic_curve import SECP256K1N
from ethereum.crypto.hash import keccak256
from ethereum.exceptions import InvalidSignatureError
from ethereum.state import Address

from .strategies import addresses, bytes_data

private_keys = st.integers(min_value=1, max_value=int(SECP256K1N) - 1)


@pytest.fixture(scope="session")
def transactions(fork_name: str) -> ModuleType:
    """Transactions module of the fork under test."""
    return importlib.import_module(f"ethereum.forks.{fork_name}.transactions")


def unsigned_legacy_tx(
    transactions: ModuleType, data: Bytes, to: Address
) -> Any:
    """Build a legacy transaction with a zeroed signature."""
    return transactions.LegacyTransaction(
        nonce=U256(0),
        gas_price=Uint(10),
        gas=Uint(21_000_000),
        to=to,
        value=U256(1),
        data=data,
        v=U256(0),
        r=U256(0),
        s=U256(0),
    )


def sign_hash(key: int, msg_hash: bytes) -> tuple[U256, U256, int]:
    """Sign a 32-byte hash, returning (r, s, parity)."""
    # spec256k1 (the spec's signing backend, replacing coincurve upstream)
    # signs the raw 32-byte digest directly — no extra hashing.
    private_key = PrivateKey(key.to_bytes(32, "big"))
    signature = private_key.sign_recoverable(msg_hash)
    r = U256.from_be_bytes(signature[:32])
    s = U256.from_be_bytes(signature[32:64])
    return r, s, signature[64]


def address_of(key: int) -> Address:
    """Derive the address of a private key."""
    public_key = PrivateKey(key.to_bytes(32, "big")).public_key.format(
        compressed=False
    )[1:]
    return Address(keccak256(public_key)[12:32])


@given(key=private_keys, data=bytes_data(max_size=64), to=addresses())
def test_recover_sender_inverts_signing_pre155(
    transactions: ModuleType, key: int, data: Bytes, to: Address
) -> None:
    """Pre-EIP-155 signing round-trips through recovery."""
    tx = unsigned_legacy_tx(transactions, data, to)
    msg_hash = transactions.signing_hash_pre155(tx)
    r, s, parity = sign_hash(key, bytes(msg_hash))
    signed = replace(tx, v=U256(27 + parity), r=r, s=s)
    assert transactions.recover_sender(signed) == address_of(key)


@given(key=private_keys, data=bytes_data(max_size=64), to=addresses())
def test_recover_sender_inverts_signing_eip155(
    transactions: ModuleType, key: int, data: Bytes, to: Address
) -> None:
    """EIP-155 signing round-trips through recovery."""
    chain_id = U64(1)
    tx = unsigned_legacy_tx(transactions, data, to)
    msg_hash = transactions.signing_hash_155(tx, chain_id)
    r, s, parity = sign_hash(key, bytes(msg_hash))
    v = U256(35 + 2 * int(chain_id) + parity)
    signed = replace(tx, v=v, r=r, s=s)
    assert transactions.recover_sender(signed) == address_of(key)


@given(key=private_keys, data=bytes_data(max_size=64), to=addresses())
def test_high_s_signatures_are_rejected(
    transactions: ModuleType, key: int, data: Bytes, to: Address
) -> None:
    """Malleable high-s signatures are rejected."""
    tx = unsigned_legacy_tx(transactions, data, to)
    msg_hash = transactions.signing_hash_pre155(tx)
    r, s, parity = sign_hash(key, bytes(msg_hash))
    high_s = U256(int(SECP256K1N) - int(s))
    flipped = replace(tx, v=U256(27 + (1 - parity)), r=r, s=high_s)
    with pytest.raises(InvalidSignatureError):
        transactions.recover_sender(flipped)


@given(key=private_keys, data=bytes_data(max_size=64), to=addresses())
def test_zero_r_or_s_is_rejected(
    transactions: ModuleType, key: int, data: Bytes, to: Address
) -> None:
    """Zero r or s values are rejected."""
    tx = unsigned_legacy_tx(transactions, data, to)
    msg_hash = transactions.signing_hash_pre155(tx)
    r, s, parity = sign_hash(key, bytes(msg_hash))
    for bad in (
        replace(tx, v=U256(27 + parity), r=U256(0), s=s),
        replace(tx, v=U256(27 + parity), r=r, s=U256(0)),
    ):
        with pytest.raises(InvalidSignatureError):
            transactions.recover_sender(bad)
