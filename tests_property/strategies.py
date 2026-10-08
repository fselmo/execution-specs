"""
Strategies for spec base types and framework transactions, weighted toward
boundary values.

Uniform random integers almost never land on the values where EVM
semantics change (zero, one, word boundaries, type maxima), so every
numeric strategy here mixes explicit boundary sampling with the full
range.
"""

from typing import Any, Dict, List

from ethereum_types.bytes import Bytes, Bytes20
from ethereum_types.numeric import U64, U256, Uint
from execution_testing import (
    EOA,
    AuthorizationTuple,
    Hash,
    Transaction,
    TransactionType,
)
from execution_testing.base_types import AccessList
from execution_testing.forks import Fork
from hypothesis import strategies as st

from ethereum.crypto.elliptic_curve import SECP256K1N
from ethereum.state import Address

# EIP-4844: a versioned hash starts with the KZG version byte.
VERSIONED_HASH = Hash(b"\x01" + b"\x00" * 31)

MAX_U64 = int(U64.MAX_VALUE)
MAX_U256 = int(U256.MAX_VALUE)

private_keys = st.integers(min_value=1, max_value=int(SECP256K1N) - 1)


def _boundaries(bits: int) -> List[int]:
    values = {0, 1, 2, (1 << bits) - 1, (1 << bits) - 2}
    for exp in (7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255):
        if exp < bits:
            values.update({1 << exp, (1 << exp) - 1, (1 << exp) + 1})
    return sorted(values)


def ints(max_value: int) -> st.SearchStrategy[int]:
    """Return ints up to `max_value`, weighted toward boundaries."""
    boundaries = [b for b in _boundaries(256) if b <= max_value]
    return st.one_of(
        st.sampled_from(boundaries + [max_value]),
        st.integers(min_value=0, max_value=max_value),
    )


def u256s() -> st.SearchStrategy[U256]:
    """Return 256-bit unsigned integers, weighted toward boundaries."""
    return ints(MAX_U256).map(U256)


def u64s() -> st.SearchStrategy[U64]:
    """Return 64-bit unsigned integers, weighted toward boundaries."""
    return ints(MAX_U64).map(U64)


def uints(max_value: int = MAX_U64) -> st.SearchStrategy[Uint]:
    """Return `Uint`s up to `max_value`, weighted toward boundaries."""
    return ints(max_value).map(Uint)


def addresses() -> st.SearchStrategy[Address]:
    """Return random addresses."""
    return st.binary(min_size=20, max_size=20).map(
        lambda b: Address(Bytes20(b))
    )


def bytes_data(
    min_size: int = 0, max_size: int = 256
) -> st.SearchStrategy[Bytes]:
    """
    Return byte strings with sizes weighted toward 32-byte word
    boundaries, where memory expansion and calldata pricing change.
    """
    hotspot_sizes = sorted(
        {0, 1, 31, 32, 33, 63, 64, 65} & set(range(min_size, max_size + 1))
    )
    return st.one_of(
        st.sampled_from(hotspot_sizes).flatmap(
            lambda n: st.binary(min_size=n, max_size=n)
        ),
        st.binary(min_size=min_size, max_size=max_size),
    ).map(Bytes)


def framework_tx(ty: int, **fields: Any) -> Transaction:
    """
    Return a framework transaction of type `ty`, with one blob or one
    authorization where the type needs it, unless `fields` sets them.
    """
    defaults: Dict[str, Any] = {"gas_limit": 21_000}
    if ty == TransactionType.BLOB_TRANSACTION:
        defaults["blob_versioned_hashes"] = [VERSIONED_HASH]
    elif ty == TransactionType.SET_CODE:
        unsigned = AuthorizationTuple(address=0xCC, v=0, r=0, s=0)
        defaults["authorization_list"] = [unsigned]
    return Transaction(ty=ty, **{**defaults, **fields})


@st.composite
def framework_txs(draw: st.DrawFn, fork: Fork) -> Transaction:
    """
    Return signed framework transactions of every type `fork` allows, with
    random fields that still pass the spec's validation apart from gas.
    """
    ty = draw(st.sampled_from(fork.tx_types()))
    key = draw(private_keys)
    sender = EOA(key=key)
    recipients: List[Any] = [draw(addresses()), sender]
    if ty in fork.contract_creating_tx_types():
        recipients.append(None)
    fields: Dict[str, Any] = {
        "secret_key": key,
        "to": draw(st.sampled_from(recipients)),
        # EIP-2681: the highest nonce is invalid.
        "nonce": draw(ints(MAX_U64 - 1)),
        "gas_limit": draw(ints(MAX_U64)),
        "value": draw(ints(MAX_U256)),
        "data": draw(bytes_data()),
        "chain_id": draw(st.integers(1, MAX_U64)),
    }
    if ty == TransactionType.LEGACY:
        fields["protected"] = fork.supports_protected_txs() and draw(
            st.booleans()
        )
    if ty in (TransactionType.LEGACY, TransactionType.ACCESS_LIST):
        fields["gas_price"] = draw(ints(MAX_U64))
    else:
        fee_cap = draw(ints(MAX_U64))
        fields["max_fee_per_gas"] = fee_cap
        fields["max_priority_fee_per_gas"] = draw(ints(fee_cap))
    if ty != TransactionType.LEGACY:
        fields["access_list"] = draw(access_lists())
    if ty == TransactionType.BLOB_TRANSACTION:
        fields["max_fee_per_blob_gas"] = draw(ints(MAX_U64))
        blob_count = draw(st.integers(1, fork.max_blobs_per_tx()))
        fields["blob_versioned_hashes"] = [VERSIONED_HASH] * blob_count
    if ty == TransactionType.SET_CODE:
        authorization = AuthorizationTuple(
            chain_id=draw(ints(MAX_U64)),
            address=draw(addresses()),
            nonce=draw(ints(MAX_U64)),
            secret_key=draw(private_keys),
        )
        fields["authorization_list"] = [authorization] * draw(
            st.integers(1, 4)
        )
    return framework_tx(ty, **fields).with_signature_and_sender()


def access_lists() -> st.SearchStrategy[List[AccessList]]:
    """Return short framework access lists."""
    entries = st.tuples(
        addresses().map(bytes),
        st.lists(st.binary(min_size=32, max_size=32), max_size=3),
    )
    return st.lists(
        entries.map(
            lambda entry: AccessList(address=entry[0], storage_keys=entry[1])
        ),
        max_size=3,
    )
