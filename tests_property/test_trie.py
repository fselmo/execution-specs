"""Properties of the shared Merkle Patricia Trie implementation."""

import random
from typing import List, Tuple

from ethereum_types.bytes import Bytes
from execution_testing.base_types import EmptyTrieRoot
from hypothesis import assume, given
from hypothesis import strategies as st

from ethereum.merkle_patricia_trie import (
    Trie,
    copy_trie,
    root,
    trie_get,
    trie_set,
)

secured = st.booleans()


def trie_items(
    max_items: int = 32,
) -> st.SearchStrategy[List[Tuple[Bytes, Bytes]]]:
    """
    Return `(key, value)` lists with unique keys, many sharing a prefix so
    the trie gets branch and extension nodes.
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


def make_trie(
    is_secured: bool, items: List[Tuple[Bytes, Bytes]]
) -> Trie[Bytes, Bytes]:
    """Build a trie from (key, value) items."""
    trie: Trie[Bytes, Bytes] = Trie(secured=is_secured, default=Bytes(b""))
    for key, value in items:
        trie_set(trie, key, value)
    return trie


@given(is_secured=secured, items=trie_items(), seed=st.randoms())
def test_root_is_insertion_order_independent(
    is_secured: bool, items: List[Tuple[Bytes, Bytes]], seed: random.Random
) -> None:
    """The root commits to contents, not insertion order."""
    shuffled = items[:]
    seed.shuffle(shuffled)
    assert root(make_trie(is_secured, items)) == root(
        make_trie(is_secured, shuffled)
    )


@given(
    is_secured=secured,
    items=trie_items(),
    extra_key=st.binary(min_size=1, max_size=8).map(Bytes),
    extra_value=st.binary(min_size=1, max_size=32).map(Bytes),
)
def test_insert_then_delete_restores_root(
    is_secured: bool,
    items: List[Tuple[Bytes, Bytes]],
    extra_key: Bytes,
    extra_value: Bytes,
) -> None:
    """Inserting then deleting a key restores the prior root."""
    trie = make_trie(is_secured, items)
    assume(trie_get(trie, extra_key) == trie.default)
    original_root = root(trie)
    trie_set(trie, extra_key, extra_value)
    trie_set(trie, extra_key, trie.default)
    assert root(trie) == original_root


@given(is_secured=secured, items=trie_items())
def test_copy_preserves_root_and_isolates_mutation(
    is_secured: bool, items: List[Tuple[Bytes, Bytes]]
) -> None:
    """A copy shares the root but not subsequent mutations."""
    trie = make_trie(is_secured, items)
    original_root = root(trie)
    copied = copy_trie(trie)
    assert root(copied) == original_root
    trie_set(copied, Bytes(b"\xde\xad"), Bytes(b"\xbe\xef"))
    assert root(trie) == original_root


def test_known_root() -> None:
    """An unsecured trie matches the "dogs" vector in ethereum/tests."""
    trie = make_trie(
        False,
        [
            (Bytes(b"doe"), Bytes(b"reindeer")),
            (Bytes(b"dog"), Bytes(b"puppy")),
            (Bytes(b"dogglesworth"), Bytes(b"cat")),
        ],
    )
    assert root(trie) == bytes.fromhex(
        "8aad789dff2f538bca5d8ea56e8abe10f4c7ba3a5dea95fea4cd6e7c3a1168d3"
    )


@given(is_secured=secured, items=trie_items())
def test_storing_default_equals_absence(
    is_secured: bool, items: List[Tuple[Bytes, Bytes]]
) -> None:
    """
    Storing the default value removes the key, so a trie whose every key
    is set back to the default has the empty trie root.
    """
    with_explicit_default = make_trie(is_secured, items)
    for key, _ in items:
        trie_set(with_explicit_default, key, with_explicit_default.default)
    assert root(with_explicit_default) == EmptyTrieRoot
