"""
Properties of the signature values sender recovery accepts.

The framework signs each transaction, so a valid signature and the sender
it recovers are known apart from the spec. Each rule is then broken from
that signature, at the first value past its bound and beyond.
"""

from dataclasses import replace
from types import ModuleType
from typing import Any, Callable, Dict, Sequence

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
from .spec_api import (
    sender_of,
    spec_transaction,
)
from .strategies import (
    MAX_U256,
    addresses,
    bytes_data,
    framework_tx,
    framework_txs,
    private_keys,
)

TYPED = [ty for ty in TransactionType if ty != TransactionType.LEGACY]
# EIP-155: a protected `v` is `35 + 2 * chain_id + parity`.
FIRST_PROTECTED_V = 35


def past(bound: int, offset: int) -> U256:
    """Return the value `offset` past `bound`, within 256 bits."""
    return U256(min(bound + offset, MAX_U256))


def highest_s(fork: Fork) -> int:
    """Return the largest `s` a fork accepts."""
    # EIP-2 keeps `s` in the lower half of the curve order.
    return (
        int(SECP256K1N) // 2 if fork.is_eip_enabled(2) else int(SECP256K1N) - 1
    )


# Each break returns the signed transaction `tx` with one signature value at
# its bound plus `offset`, given by keyword along with the `fork`.
BREAKS: Dict[str, Callable[..., Any]] = {
    "r_zero": lambda tx, **_: replace(tx, r=U256(0)),
    "r_past_the_curve_order": lambda tx, offset, **_: replace(
        tx, r=past(int(SECP256K1N), offset)
    ),
    "s_zero": lambda tx, **_: replace(tx, s=U256(0)),
    "s_past_its_bound": lambda tx, fork, offset: replace(
        tx, s=past(highest_s(fork) + 1, offset)
    ),
    "y_parity_past_one": lambda tx, offset, **_: replace(
        tx, y_parity=past(2, offset)
    ),
    "v_below_the_protected_range": lambda tx, offset, **_: replace(
        tx, v=U256(29 + offset % (FIRST_PROTECTED_V - 29))
    ),
    "chain_id_past_64_bits": lambda tx, offset, **_: replace(
        tx, v=past(FIRST_PROTECTED_V + 2 * 2**64, 2 * offset)
    ),
}
BREAK_TYPES: Dict[str, Sequence[int]] = {
    "y_parity_past_one": TYPED,
    "v_below_the_protected_range": [TransactionType.LEGACY],
    "chain_id_past_64_bits": [TransactionType.LEGACY],
}
# Each rule flips at its bound and nothing changes past it, so the first
# value past it and the top of the field are the offsets that matter.
OFFSETS = st.sampled_from([0, 1, 2**64, MAX_U256])


def breakable(break_name: str) -> Any:
    """Return the break as a parameter for forks with a type it breaks."""
    types = BREAK_TYPES.get(break_name, list(TransactionType))
    has_a_type = requires(
        lambda fork: any(ty in fork.tx_types() for ty in types)
    )
    return pytest.param(break_name, marks=has_a_type)


@pytest.mark.parametrize("break_name", [breakable(b) for b in sorted(BREAKS)])
@given(data=st.data(), offset=OFFSETS)
def test_signature_values_past_their_bounds_are_rejected(
    fork: Fork,
    transactions: ModuleType,
    break_name: str,
    data: st.DataObject,
    offset: int,
) -> None:
    """
    A valid signature recovers the framework's sender, and the same
    transaction with one signature value at or past its bound is rejected.
    """
    types = BREAK_TYPES.get(break_name, list(TransactionType))
    types = [ty for ty in types if ty in fork.tx_types()]
    framework = data.draw(framework_txs(fork, types))
    tx = spec_transaction(transactions, framework)
    assert sender_of(transactions, tx) == framework.sender

    with pytest.raises(InvalidSignatureError):
        broken = BREAKS[break_name](tx=tx, fork=fork, offset=offset)
        sender_of(transactions, broken)


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
