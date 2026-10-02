"""
Strategies for spec base types, weighted toward boundary values.

Uniform random integers almost never land on the values where EVM
semantics change (zero, one, word boundaries, type maxima), so every
numeric strategy here mixes explicit boundary sampling with the full
range.
"""

import importlib
from typing import List, Tuple

from ethereum_rlp import Extended
from ethereum_types.bytes import Bytes, Bytes20
from ethereum_types.numeric import U64, U256, Uint
from hypothesis import strategies as st

from ethereum.state import Address

from ..forks import PROPERTY_TEST_FORKS


def _boundaries(bits: int) -> List[int]:
    values = {0, 1, 2, (1 << bits) - 1, (1 << bits) - 2}
    for exp in (7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255):
        if exp < bits:
            values.update({1 << exp, (1 << exp) - 1, (1 << exp) + 1})
    return sorted(values)


def _bounded_ints(bits: int) -> st.SearchStrategy[int]:
    return st.one_of(
        st.sampled_from(_boundaries(bits)),
        st.integers(min_value=0, max_value=(1 << bits) - 1),
    )


def u256s() -> st.SearchStrategy[U256]:
    """Return 256-bit unsigned integers, weighted toward boundaries."""
    return _bounded_ints(256).map(U256)


def u64s() -> st.SearchStrategy[U64]:
    """Return 64-bit unsigned integers, weighted toward boundaries."""
    return _bounded_ints(64).map(U64)


def uints(max_value: int = (1 << 64) - 1) -> st.SearchStrategy[Uint]:
    """
    Return `Uint`s up to `max_value`, weighted toward boundaries.

    `Uint` is unbounded in the spec; tests bound it to keep arithmetic
    cheap while still crossing every interesting word boundary.
    """
    boundaries = [b for b in _boundaries(64) if b <= max_value]
    return st.one_of(
        st.sampled_from(boundaries),
        st.integers(min_value=0, max_value=max_value),
    ).map(Uint)


PRECOMPILE_ADDRESSES = sorted(
    {
        address
        for fork_name in PROPERTY_TEST_FORKS
        for address in importlib.import_module(
            f"ethereum.forks.{fork_name}.vm.precompiled_contracts.mapping"
        ).PRE_COMPILED_CONTRACTS
    }
)


def addresses() -> st.SearchStrategy[Address]:
    """Return addresses, mixing random ones with precompiles."""
    return st.one_of(
        st.sampled_from(PRECOMPILE_ADDRESSES),
        st.binary(min_size=20, max_size=20).map(lambda b: Address(Bytes20(b))),
    )


def bytes_data(max_size: int = 256) -> st.SearchStrategy[Bytes]:
    """
    Return byte strings with sizes weighted toward 32-byte word
    boundaries, where memory expansion and calldata pricing change.
    """
    hotspot_sizes = sorted(
        {0, 1, 31, 32, 33, 63, 64, 65} & set(range(max_size + 1))
    )
    return st.one_of(
        st.sampled_from(hotspot_sizes).flatmap(
            lambda n: st.binary(min_size=n, max_size=n)
        ),
        st.binary(max_size=max_size),
    ).map(Bytes)


def trie_items(
    max_items: int = 32,
) -> st.SearchStrategy[List[Tuple[Bytes, Bytes]]]:
    """
    Return `(key, value)` lists with unique keys, for trie tests.

    Keys share prefixes deliberately: drawing from a small alphabet of
    short keys forces branch and extension nodes, which uniform random
    keys almost never produce.
    """
    clustered_keys = st.lists(
        st.sampled_from([0x00, 0x01, 0x10, 0x11, 0xFF]),
        min_size=1,
        max_size=4,
    ).map(bytes)
    keys = st.one_of(
        clustered_keys,
        st.binary(min_size=1, max_size=8),
    ).map(Bytes)
    values = st.binary(min_size=1, max_size=32).map(Bytes)
    return st.dictionaries(keys, values, max_size=max_items).map(
        lambda d: list(d.items())
    )


def rlp_extended() -> st.SearchStrategy[Extended]:
    """
    Return nested lists of byte strings, the part of `Extended` whose
    decoding gives back the same structure.
    """
    return st.recursive(
        st.binary(max_size=64).map(Bytes),
        lambda children: st.lists(children, max_size=8),
        max_leaves=24,
    )
