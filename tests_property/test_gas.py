"""
The spec's gas formulas agree with the testing framework's calculators.

Each property draws random inputs and compares the spec function with the
framework's own calculator for the same fork, which is written apart from
`src/`. Where the framework has no calculator, the rule comes from its EIP.
"""

from types import ModuleType
from typing import Any, List, Tuple

from ethereum_types.numeric import U64, U256, Uint
from execution_testing.forks import Fork
from hypothesis import given
from hypothesis import strategies as st

from ethereum_spec_tools.forks import Hardfork

from .forks import requires
from .spec_api import spec_transaction, zeroed
from .strategies import framework_txs, ints, uints

MEMORY_BOUND = 1 << 24
# Far above realistic values, and far from the U64 limit when added up.
BLOB_GAS_BOUND = 1 << 30
BASE_FEE_BOUND = 1 << 40
GAS_LIMIT_BOUND = 1 << 40

with_blobs = requires(lambda fork: fork.supports_blobs())


def ceil32(value: int) -> int:
    """Round up to the next multiple of 32."""
    return (value + 31) // 32 * 32


@given(size=uints(MEMORY_BOUND))
def test_memory_gas_cost(gas: ModuleType, fork: Fork, size: Uint) -> None:
    """The cost of memory of a given size matches the framework."""
    expected = fork.memory_expansion_gas_calculator()(new_bytes=int(size))
    assert gas.calculate_memory_gas_cost(size) == expected


@given(
    initial_words=ints(64),
    extensions=st.lists(
        st.tuples(ints(MEMORY_BOUND), ints(MEMORY_BOUND)), max_size=8
    ),
)
def test_memory_extension(
    gas: ModuleType,
    fork: Fork,
    initial_words: int,
    extensions: List[Tuple[int, int]],
) -> None:
    """
    Extending memory by several ranges at once grows it to the end of the
    furthest non-empty range and costs what the framework charges for
    that growth.
    """
    memory = bytearray(initial_words * 32)
    final_size = len(memory)
    for start, size in extensions:
        if size > 0:
            final_size = max(final_size, ceil32(start + size))

    result = gas.calculate_gas_extend_memory(
        memory, [(U256(start), U256(size)) for start, size in extensions]
    )

    assert len(memory) + int(result.expand_by) == final_size
    assert result.cost == fork.memory_expansion_gas_calculator()(
        new_bytes=final_size, previous_bytes=len(memory)
    )


@requires(lambda fork: fork.header_base_fee_required())
@given(data=st.data())
def test_base_fee_per_gas(
    spec: Hardfork, fork: Fork, data: st.DataObject
) -> None:
    """The next block's base fee matches the framework."""
    minimum = fork.minimum_block_gas_limit()
    gas_limit = data.draw(
        st.one_of(st.just(minimum), st.integers(minimum, GAS_LIMIT_BOUND))
    )
    gas_target = gas_limit // fork.base_fee_elasticity_multiplier()
    gas_used = data.draw(
        st.one_of(
            st.sampled_from([0, gas_target - 1, gas_target, gas_target + 1]),
            ints(gas_limit),
        )
    )
    base_fee = data.draw(ints(BASE_FEE_BOUND))

    # A block that keeps its parent's gas limit is always valid.
    actual = spec.module("fork").calculate_base_fee_per_gas(
        Uint(gas_limit), Uint(gas_limit), Uint(gas_used), Uint(base_fee)
    )
    assert actual == fork.base_fee_per_gas_calculator()(
        parent_base_fee_per_gas=base_fee,
        parent_gas_used=gas_used,
        parent_gas_limit=gas_limit,
    )


@with_blobs
@given(excess=ints(BLOB_GAS_BOUND))
def test_blob_gas_price(gas: ModuleType, fork: Fork, excess: int) -> None:
    """The blob gas price at any excess blob gas matches the framework."""
    expected = fork.blob_gas_price_calculator()(excess_blob_gas=excess)
    assert gas.calculate_blob_gas_price(U64(excess)) == expected


def parent_header(
    blocks: ModuleType, excess: int, used: int, base_fee: int
) -> Any:
    """Return a parent header whose only set fields drive blob pricing."""
    return zeroed(
        blocks.Header,
        excess_blob_gas=U64(excess),
        blob_gas_used=U64(used),
        base_fee_per_gas=Uint(base_fee),
    )


@with_blobs
@given(data=st.data())
def test_excess_blob_gas(
    gas: ModuleType, fork: Fork, blocks: ModuleType, data: st.DataObject
) -> None:
    """
    The next block's excess blob gas matches the framework, around the
    blob target and, where EIP-7918 applies, around its reserve price.
    """
    blob_gas_per_blob = fork.blob_gas_per_blob()
    target = fork.target_blobs_per_block() * blob_gas_per_blob
    excess = data.draw(
        st.one_of(st.sampled_from([0, target - 1, target]), ints(4 * target))
    )
    used = data.draw(
        st.integers(0, fork.max_blobs_per_block()).map(
            lambda blobs: blobs * blob_gas_per_blob
        )
    )
    base_fees = ints(BASE_FEE_BOUND)
    if fork.blob_reserve_price_active():
        # The reserve applies once the base fee times `BLOB_BASE_COST`
        # outprices one blob at the current blob gas price.
        blob_price = fork.blob_gas_price_calculator()(excess_blob_gas=excess)
        lowest_reserve_fee = (
            blob_gas_per_blob * blob_price // fork.blob_base_cost() + 1
        )
        base_fees = st.one_of(
            st.sampled_from([lowest_reserve_fee - 1, lowest_reserve_fee]),
            base_fees,
        )
    base_fee = data.draw(base_fees)

    parent = parent_header(blocks, excess, used, base_fee)
    assert gas.calculate_excess_blob_gas(parent) == (
        fork.excess_blob_gas_calculator()(
            parent_excess_blob_gas=excess,
            parent_blob_gas_used=used,
            parent_base_fee_per_gas=base_fee,
        )
    )


@with_blobs
@given(excess=ints(BLOB_GAS_BOUND), data=st.data())
def test_blob_fee(
    gas: ModuleType,
    fork: Fork,
    transactions: ModuleType,
    excess: int,
    data: st.DataObject,
) -> None:
    """
    A transaction uses blob gas only for its blobs, and pays the blob gas
    price for each unit of it.
    """
    framework = data.draw(framework_txs(fork))
    tx = spec_transaction(transactions, framework)

    blob_count = len(framework.blob_versioned_hashes or [])
    blob_gas = blob_count * fork.blob_gas_per_blob()
    blob_price = fork.blob_gas_price_calculator()(excess_blob_gas=excess)
    assert gas.calculate_total_blob_gas(tx) == blob_gas
    assert gas.calculate_data_fee(U64(excess), tx) == blob_gas * blob_price
