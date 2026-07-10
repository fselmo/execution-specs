"""Properties of the shared Merkle Patricia Trie implementation."""

from typing import List, Tuple

from ethereum_types.bytes import Bytes
from hypothesis import assume, given
from hypothesis import strategies as st

from ethereum.merkle_patricia_trie import (
    EMPTY_TRIE_ROOT,
    Trie,
    copy_trie,
    root,
    trie_get,
    trie_set,
)

from .strategies import trie_items

secured = st.booleans()


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
    is_secured: bool, items: List[Tuple[Bytes, Bytes]], seed: object
) -> None:
    """The root commits to contents, not insertion order."""
    shuffled = items[:]
    seed.shuffle(shuffled)  # type: ignore[attr-defined]
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


@given(is_secured=secured, items=trie_items())
def test_get_returns_what_set_stored(
    is_secured: bool, items: List[Tuple[Bytes, Bytes]]
) -> None:
    """Every stored value is retrievable."""
    trie = make_trie(is_secured, items)
    for key, value in items:
        assert trie_get(trie, key) == value


@given(is_secured=secured)
def test_empty_trie_root(is_secured: bool) -> None:
    """An empty trie hashes to the canonical empty root."""
    trie: Trie[Bytes, Bytes] = Trie(secured=is_secured, default=Bytes(b""))
    assert root(trie) == EMPTY_TRIE_ROOT


@given(is_secured=secured, items=trie_items())
def test_storing_default_equals_absence(
    is_secured: bool, items: List[Tuple[Bytes, Bytes]]
) -> None:
    """Storing the default value equals removing the key."""
    with_explicit_default = make_trie(is_secured, items)
    for key, _ in items:
        trie_set(with_explicit_default, key, with_explicit_default.default)
    empty: Trie[Bytes, Bytes] = Trie(secured=is_secured, default=Bytes(b""))
    assert root(with_explicit_default) == root(empty)
