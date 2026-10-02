"""Properties of the memory and blob gas functions."""

import importlib
from types import ModuleType
from typing import Any, List, Tuple

import pytest
from ethereum_types.numeric import U64, U256, Uint
from hypothesis import given
from hypothesis import strategies as st

from .strategies import uints
from .strategies.builders import (
    build_tx,
    kzg_versioned_hash,
    transaction_types,
    zeroed,
)

MEMORY_BOUND = 1 << 24

# Keeps `excess_blob_gas + blob_gas_used` far from the U64 limit and the
# blob price series cheap, while staying far above realistic values.
BLOB_GAS_BOUND = 1 << 30
BASE_FEE_BOUND = 1 << 40
MAX_BLOBS = 64

# EIP-4844: the blob gas price never falls below this.
MIN_BASE_FEE_PER_BLOB_GAS = 1


@pytest.fixture(scope="session")
def blocks(fork_name: str) -> ModuleType:
    """Return the blocks module of the fork under test, for `Header`."""
    return importlib.import_module(f"ethereum.forks.{fork_name}.blocks")


def blob_u64(bound: int) -> st.SearchStrategy[U64]:
    """Return `U64`s up to `bound`, weighted toward boundaries."""
    return uints(bound).map(lambda u: U64(int(u)))


def blob_tx(transactions: ModuleType, count: int) -> Any:
    """Return a blob transaction carrying `count` versioned hashes."""
    return build_tx(
        transactions,
        transactions.BlobTransaction,
        blob_versioned_hashes=(kzg_versioned_hash(transactions),) * count,
    )


def parent_header(
    blocks: ModuleType, excess: U64, used: U64, base_fee: Uint
) -> Any:
    """Return a parent header whose only set fields drive blob pricing."""
    return zeroed(
        blocks.Header,
        excess_blob_gas=excess,
        blob_gas_used=used,
        base_fee_per_gas=base_fee,
    )


def ceil32_int(value: int) -> int:
    """Round up to the next multiple of 32."""
    return (value + 31) // 32 * 32


@given(size=uints(MEMORY_BOUND), delta=uints(MEMORY_BOUND))
def test_memory_gas_cost_is_monotonic(
    gas: ModuleType, size: Uint, delta: Uint
) -> None:
    """Larger memory never costs less."""
    assert gas.calculate_memory_gas_cost(
        size + delta
    ) >= gas.calculate_memory_gas_cost(size)


@given(size=uints(MEMORY_BOUND))
def test_memory_gas_cost_is_word_quantized(
    gas: ModuleType, size: Uint
) -> None:
    """Memory cost depends only on the size rounded up to whole words."""
    aligned = Uint(ceil32_int(int(size)))
    assert gas.calculate_memory_gas_cost(
        size
    ) == gas.calculate_memory_gas_cost(aligned)


@given(a=uints(MEMORY_BOUND), b=uints(MEMORY_BOUND))
def test_memory_gas_cost_is_superadditive_on_words(
    gas: ModuleType, a: Uint, b: Uint
) -> None:
    """
    One allocation of whole words costs at least as much as two smaller
    allocations adding up to it.
    """
    a_aligned = Uint(ceil32_int(int(a)))
    b_aligned = Uint(ceil32_int(int(b)))
    assert gas.calculate_memory_gas_cost(
        a_aligned + b_aligned
    ) >= gas.calculate_memory_gas_cost(
        a_aligned
    ) + gas.calculate_memory_gas_cost(b_aligned)


@given(
    initial_words=uints(64),
    extensions=st.lists(
        st.tuples(uints(MEMORY_BOUND), uints(MEMORY_BOUND)),
        max_size=8,
    ),
)
def test_memory_extension_charging_is_path_independent(
    gas: ModuleType,
    initial_words: Uint,
    extensions: List[Tuple[Uint, Uint]],
) -> None:
    """
    Extending memory in any number of steps costs the same as one step to
    the largest size reached.
    """
    memory = bytearray(int(initial_words) * 32)
    extend_pairs = [
        (U256(int(start)), U256(int(size))) for start, size in extensions
    ]
    result = gas.calculate_gas_extend_memory(memory, extend_pairs)

    final_size = ceil32_int(len(memory))
    for start, size in extend_pairs:
        if int(size) == 0:
            continue
        final_size = max(final_size, ceil32_int(int(start) + int(size)))

    expected = gas.calculate_memory_gas_cost(
        Uint(final_size)
    ) - gas.calculate_memory_gas_cost(Uint(ceil32_int(len(memory))))
    assert result.cost == expected
    assert Uint(len(memory)) + result.expand_by == Uint(final_size)


@given(length=uints(1 << 17), delta=uints(1 << 17))
def test_init_code_cost_is_monotonic_and_word_quantized(
    gas: ModuleType, length: Uint, delta: Uint
) -> None:
    """Init code cost grows with length, one 32-byte word at a time."""
    assert gas.init_code_cost(length + delta) >= gas.init_code_cost(length)
    assert gas.init_code_cost(length) == gas.init_code_cost(
        Uint(ceil32_int(int(length)))
    )


def test_blob_gas_price_at_zero_excess_is_the_minimum(
    gas: ModuleType,
) -> None:
    """With no excess blob gas, the blob gas price is the EIP-4844 floor."""
    assert gas.calculate_blob_gas_price(U64(0)) == Uint(
        MIN_BASE_FEE_PER_BLOB_GAS
    )


@given(excess=blob_u64(BLOB_GAS_BOUND), delta=blob_u64(BLOB_GAS_BOUND))
def test_blob_gas_price_is_monotonic_and_floored(
    gas: ModuleType, excess: U64, delta: U64
) -> None:
    """
    The blob gas price never falls as excess blob gas grows, and never
    drops below the EIP-4844 floor.
    """
    lower = gas.calculate_blob_gas_price(excess)
    higher = gas.calculate_blob_gas_price(U64(int(excess) + int(delta)))
    assert higher >= lower
    assert lower >= Uint(MIN_BASE_FEE_PER_BLOB_GAS)


def test_non_blob_transactions_use_no_blob_gas(
    gas: ModuleType, transactions: ModuleType
) -> None:
    """Every transaction type without blobs uses no blob gas."""
    for tx_type in transaction_types(transactions):
        if tx_type is transactions.BlobTransaction:
            continue
        tx = build_tx(transactions, tx_type)
        assert gas.calculate_total_blob_gas(tx) == U64(0)


@given(excess=blob_u64(BLOB_GAS_BOUND))
def test_data_fee_zero_for_non_blob_tx(
    gas: ModuleType, transactions: ModuleType, excess: U64
) -> None:
    """A transaction without blobs owes no blob fee at any excess."""
    tx = build_tx(transactions, transactions.LegacyTransaction)
    assert gas.calculate_data_fee(excess, tx) == Uint(0)


@given(count=st.integers(min_value=0, max_value=MAX_BLOBS))
def test_data_fee_at_zero_excess_equals_total_blob_gas(
    gas: ModuleType, transactions: ModuleType, count: int
) -> None:
    """
    At zero excess the blob fee equals the blob gas used, since the price
    sits at its floor of one.
    """
    tx = blob_tx(transactions, count)
    assert gas.calculate_data_fee(U64(0), tx) == Uint(
        gas.calculate_total_blob_gas(tx)
    )


@given(
    count=st.integers(min_value=1, max_value=MAX_BLOBS),
    excess=blob_u64(BLOB_GAS_BOUND),
    delta=blob_u64(BLOB_GAS_BOUND),
)
def test_data_fee_is_monotonic_in_excess(
    gas: ModuleType,
    transactions: ModuleType,
    count: int,
    excess: U64,
    delta: U64,
) -> None:
    """For a fixed blob transaction, more excess never lowers the fee."""
    tx = blob_tx(transactions, count)
    lower = gas.calculate_data_fee(excess, tx)
    higher = gas.calculate_data_fee(U64(int(excess) + int(delta)), tx)
    assert higher >= lower


def test_excess_blob_gas_zero_without_a_blob_parent(gas: ModuleType) -> None:
    """A parent without blob fields, as at a fork block, gives no excess."""
    assert gas.calculate_excess_blob_gas(None) == U64(0)


@given(data=st.data(), base_fee=uints(BASE_FEE_BOUND))
def test_excess_blob_gas_zero_below_target(
    gas: ModuleType, blocks: ModuleType, data: st.DataObject, base_fee: Uint
) -> None:
    """A parent whose excess plus used blob gas is below target resets it."""
    target = int(gas.GasCosts.BLOB_TARGET_GAS_PER_BLOCK)
    excess = data.draw(blob_u64(target - 1))
    largest_used = target - 1 - int(excess)
    used = data.draw(
        st.one_of(st.just(U64(largest_used)), blob_u64(largest_used))
    )
    parent = parent_header(blocks, excess, used, base_fee)
    assert gas.calculate_excess_blob_gas(parent) == U64(0)


@given(excess=blob_u64(BLOB_GAS_BOUND))
def test_excess_blob_gas_unchanged_at_target_without_reserve(
    gas: ModuleType, blocks: ModuleType, excess: U64
) -> None:
    """
    A parent that used exactly the target leaves excess unchanged, when a
    zero base fee keeps the EIP-7918 reserve price out of play.
    """
    target = gas.GasCosts.BLOB_TARGET_GAS_PER_BLOCK
    parent = parent_header(blocks, excess, target, Uint(0))
    assert gas.calculate_excess_blob_gas(parent) == excess


@given(
    excess=blob_u64(BLOB_GAS_BOUND),
    blob_gas_used=blob_u64(BLOB_GAS_BOUND),
    extra_used=blob_u64(BLOB_GAS_BOUND),
)
def test_excess_blob_gas_monotonic_in_parent_usage(
    gas: ModuleType,
    blocks: ModuleType,
    excess: U64,
    blob_gas_used: U64,
    extra_used: U64,
) -> None:
    """
    With a zero base fee, more blob gas used by the parent never lowers the
    next block's excess.
    """
    more = U64(int(blob_gas_used) + int(extra_used))
    fewer = parent_header(blocks, excess, blob_gas_used, Uint(0))
    larger = parent_header(blocks, excess, more, Uint(0))
    assert gas.calculate_excess_blob_gas(
        larger
    ) >= gas.calculate_excess_blob_gas(fewer)


@given(data=st.data())
def test_excess_blob_gas_reserve_prevents_reset(
    gas: ModuleType, blocks: ModuleType, data: st.DataObject
) -> None:
    """
    EIP-7918: once the execution base fee outprices the blobs, a parent at
    the target keeps a positive excess, below the gas it used. One unit of
    base fee less and the excess resets to zero.
    """
    costs = gas.GasCosts
    target = costs.BLOB_TARGET_GAS_PER_BLOCK
    # EIP-7918 applies the reserve when BLOB_BASE_COST * base_fee exceeds
    # GAS_PER_BLOB * blob_gas_price, here at zero excess.
    blob_price = Uint(costs.PER_BLOB) * gas.calculate_blob_gas_price(U64(0))
    lowest_reserve_fee = int(blob_price // costs.BLOB_BASE_COST) + 1
    base_fee = data.draw(
        st.one_of(
            st.just(lowest_reserve_fee),
            st.integers(
                min_value=lowest_reserve_fee, max_value=BASE_FEE_BOUND
            ),
        )
    )
    with_reserve = parent_header(blocks, U64(0), target, Uint(base_fee))
    assert U64(0) < gas.calculate_excess_blob_gas(with_reserve) < target

    without_reserve = parent_header(
        blocks, U64(0), target, Uint(lowest_reserve_fee - 1)
    )
    assert gas.calculate_excess_blob_gas(without_reserve) == U64(0)
