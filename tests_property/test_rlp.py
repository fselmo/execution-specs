"""
Properties of how the spec RLP-encodes its blocks, transactions and receipts.

Transactions are compared with the framework's own encoding of the same
transaction. Headers and receipts, which the framework does not encode, are
compared with a reference encoder written from the Yellow Paper's RLP rules
(Appendix B), on byte fields sized around the point where a short length
prefix gives way to a long one.
"""

from dataclasses import fields, is_dataclass
from types import ModuleType
from typing import Any, List

import pytest
from ethereum_rlp import rlp
from ethereum_types.bytes import Bytes
from ethereum_types.numeric import FixedUnsigned, Uint
from execution_testing.forks import Fork
from hypothesis import given
from hypothesis import strategies as st

from .forks import requires
from .spec_api import (
    decode_transaction,
    encode_transaction,
    spec_transaction,
    transaction_types,
    type_byte,
    zeroed,
)
from .strategies import framework_tx, framework_txs

# Yellow Paper: payloads shorter than this take a one-byte length prefix.
SHORT_PAYLOAD_LIMIT = 56
# Yellow Paper: prefix bases for byte strings and lists, short and long.
SHORT_STRING_BASE = 0x80
LONG_STRING_BASE = 0xB7
SHORT_LIST_BASE = 0xC0
LONG_LIST_BASE = 0xF7

# `encode_receipt` arrives with typed transactions.
with_typed_transactions = requires(lambda fork: max(fork.tx_types()) > 0)


def rlp_bytes() -> st.SearchStrategy[Bytes]:
    """
    Return byte strings weighted toward the sizes where RLP's length prefix
    changes form: one byte, and 55 against 56 bytes.
    """
    single_bytes = st.sampled_from([0x00, 0x7F, 0x80, 0xFF]).map(
        lambda byte: Bytes([byte])
    )
    sizes = st.one_of(
        st.sampled_from([0, 1, 54, 55, 56, 57, 255, 256]),
        st.integers(min_value=0, max_value=64),
        st.integers(min_value=0, max_value=300),
    )
    return st.one_of(
        single_bytes,
        sizes.flatmap(lambda n: st.binary(min_size=n, max_size=n)).map(Bytes),
    )


def _prefixed(payload: bytes, short_base: int, long_base: int) -> bytes:
    if len(payload) < SHORT_PAYLOAD_LIMIT:
        return bytes([short_base + len(payload)]) + payload
    length = len(payload).to_bytes((len(payload).bit_length() + 7) // 8)
    return bytes([long_base + len(length)]) + length + payload


def reference_encode(value: Any) -> bytes:
    """Encode `value` by the Yellow Paper's RLP rules."""
    if isinstance(value, bool):
        return reference_encode(b"\x01" if value else b"")
    if isinstance(value, (Uint, FixedUnsigned)):
        number = int(value)
        return reference_encode(
            number.to_bytes((number.bit_length() + 7) // 8)
        )
    if isinstance(value, (bytes, bytearray)):
        if len(value) == 1 and value[0] < SHORT_STRING_BASE:
            return bytes(value)
        return _prefixed(bytes(value), SHORT_STRING_BASE, LONG_STRING_BASE)
    if is_dataclass(value):
        return reference_encode(
            [getattr(value, f.name) for f in fields(value)]
        )
    if isinstance(value, (list, tuple)):
        payload = b"".join(reference_encode(item) for item in value)
        return _prefixed(payload, SHORT_LIST_BASE, LONG_LIST_BASE)
    raise TypeError(f"no RLP rule for {type(value).__name__}")


def test_transaction_types_match_the_framework(
    fork: Fork, transactions: ModuleType
) -> None:
    """The spec defines exactly the transaction types the framework lists."""
    spec_type_bytes = [
        type_byte(tx_type) for tx_type in transaction_types(transactions)
    ]
    assert sorted(spec_type_bytes) == sorted(fork.tx_types())


@given(data=st.data())
def test_transaction_encoding_matches_the_framework(
    fork: Fork, transactions: ModuleType, data: st.DataObject
) -> None:
    """
    Every transaction type encodes to the framework's encoding of the same
    transaction, and decodes back to itself.
    """
    framework = data.draw(framework_txs(fork))
    tx = spec_transaction(transactions, framework)
    assert encode_transaction(transactions, tx) == framework.rlp()
    assert decode_transaction(transactions, framework.rlp()) == tx


@pytest.mark.parametrize(
    "payload_size,list_prefix",
    [
        pytest.param(
            SHORT_PAYLOAD_LIMIT - 1,
            bytes([SHORT_LIST_BASE + SHORT_PAYLOAD_LIMIT - 1]),
            id="short_list",
        ),
        pytest.param(
            SHORT_PAYLOAD_LIMIT,
            bytes([LONG_LIST_BASE + 1, SHORT_PAYLOAD_LIMIT]),
            id="long_list",
        ),
    ],
)
def test_transaction_list_prefix_boundary(
    fork: Fork, transactions: ModuleType, payload_size: int, list_prefix: bytes
) -> None:
    """
    A transaction whose fields encode to 55 bytes takes a one-byte list
    prefix, and one with 56 bytes takes a long prefix, for every type
    small enough to reach those sizes.
    """

    def unsigned(ty: int, data: bytes) -> Any:
        return framework_tx(ty, data=data, v=0, r=0, s=0)

    checked = 0
    for ty in fork.tx_types():
        type_prefix_size = 1 if ty else 0
        # A string of two or more bytes under 56 adds one prefix byte, so
        # each data byte grows the list payload by exactly one. Drop the
        # list prefix and the three bytes of the two-byte data.
        two_byte_data = unsigned(ty, b"\x00\x00").rlp()
        base_size = len(two_byte_data) - type_prefix_size - 1 - 3
        data_size = payload_size - base_size - 1
        if not 2 <= data_size < SHORT_PAYLOAD_LIMIT:
            continue
        framework = unsigned(ty, b"\x01" * data_size)
        encoded = encode_transaction(
            transactions, spec_transaction(transactions, framework)
        )
        assert encoded == framework.rlp()
        assert encoded[type_prefix_size:].startswith(list_prefix)
        checked += 1
    assert checked > 0


@given(extra_data=rlp_bytes(), gas_used=st.integers(0, (1 << 64) - 1))
def test_header_encoding_follows_the_rlp_rules(
    blocks: ModuleType, extra_data: Bytes, gas_used: int
) -> None:
    """A header encodes to the reference RLP and decodes back to itself."""
    header = zeroed(
        blocks.Header, extra_data=extra_data, gas_used=Uint(gas_used)
    )
    encoded = rlp.encode(header)
    assert encoded == reference_encode(header)
    assert rlp.decode_to(blocks.Header, encoded) == header


@with_typed_transactions
@given(
    succeeded=st.booleans(),
    log_data=st.lists(rlp_bytes(), max_size=3),
    draw=st.data(),
)
def test_receipt_encoding_follows_the_rlp_rules(
    fork: Fork,
    blocks: ModuleType,
    transactions: ModuleType,
    succeeded: bool,
    log_data: List[Bytes],
    draw: st.DataObject,
) -> None:
    """
    A receipt for every transaction type encodes to the reference RLP,
    after the type byte for a typed transaction, and decodes back.
    """
    ty = draw.draw(st.sampled_from(fork.tx_types()))
    tx = spec_transaction(transactions, framework_tx(ty))
    logs = tuple(zeroed(blocks.Log, data=data) for data in log_data)
    receipt = zeroed(blocks.Receipt, succeeded=succeeded, logs=logs)

    encoded = blocks.encode_receipt(tx, receipt)
    if isinstance(encoded, bytes):
        assert encoded[0] == ty
        assert encoded[1:] == reference_encode(receipt)
        assert blocks.decode_receipt(encoded) == receipt
    else:
        assert rlp.encode(encoded) == reference_encode(receipt)
        decoded = rlp.decode_to(blocks.Receipt, rlp.encode(encoded))
        assert decoded == receipt
