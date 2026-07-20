"""Properties of the gas calculation functions."""

import dataclasses
import importlib
from types import ModuleType, UnionType
from typing import Any, List, Tuple, Union, get_args, get_origin

import pytest
from ethereum_types.numeric import U64, U256, Uint
from hypothesis import assume, given
from hypothesis import strategies as st

from .strategies import uints

MEMORY_BOUND = 1 << 24

# Blob-gas inputs are bounded well below the U64 ceiling so that
# `excess_blob_gas + blob_gas_used` never overflows and the Taylor
# expansion in `calculate_blob_gas_price` stays cheap, while still far
# exceeding any realistic mainnet value.
BLOB_GAS_BOUND = 1 << 30
BLOB_SUBTARGET_BOUND = 1 << 19
BASE_FEE_BOUND = 1 << 40
MAX_BLOBS = 64


@pytest.fixture(scope="session")
def gas(fork_name: str) -> ModuleType:
    """Gas module of the fork under test."""
    return importlib.import_module(f"ethereum.forks.{fork_name}.vm.gas")


@pytest.fixture(scope="session")
def blocks(fork_name: str) -> ModuleType:
    """Blocks module of the fork under test (for `Header`)."""
    return importlib.import_module(f"ethereum.forks.{fork_name}.blocks")


@pytest.fixture(scope="session")
def transactions(fork_name: str) -> ModuleType:
    """Transactions module of the fork under test."""
    return importlib.import_module(f"ethereum.forks.{fork_name}.transactions")


def blob_u64(bound: int) -> st.SearchStrategy[U64]:
    """Boundary-weighted `U64`s up to `bound`."""
    return uints(bound).map(lambda u: U64(int(u)))


def _zero_field(field_type: Any) -> Any:
    """Return a valid zero/empty value for a dataclass field annotation."""
    origin = get_origin(field_type)
    if origin in (UnionType, Union):
        field_type = get_args(field_type)[0]
        origin = get_origin(field_type)
    if origin in (tuple, list):
        return () if origin is tuple else []
    if isinstance(field_type, type) and issubclass(field_type, bool):
        return False
    if isinstance(field_type, type) and issubclass(
        field_type, (U64, U256, Uint)
    ):
        return field_type(0)
    length = getattr(field_type, "LENGTH", None)
    if length is not None:
        return field_type(b"\x00" * length)
    return field_type(b"")


def build_zeroed(cls: Any, **overrides: Any) -> Any:
    """
    Build a dataclass instance with every field zero/empty except overrides.

    Used to construct `Header` / transaction objects whose only meaningful
    fields (for the blob-gas calculators) are the ones passed as overrides.
    The remaining fields are irrelevant to these pure functions, so filling
    them with type-correct zeros keeps the input sound without coupling the
    test to each fork's exact field set.
    """
    fields = {f.name: _zero_field(f.type) for f in dataclasses.fields(cls)}
    fields.update(overrides)
    return cls(**fields)


def blob_tx(transactions: ModuleType, count: int) -> Any:
    """A `BlobTransaction` carrying `count` versioned hashes."""
    versioned_hash = transactions.VersionedHash
    return build_zeroed(
        transactions.BlobTransaction,
        blob_versioned_hashes=tuple(
            versioned_hash(b"\x01" * versioned_hash.LENGTH)
            for _ in range(count)
        ),
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
    """Cost depends only on the word-aligned size."""
    aligned = Uint(ceil32_int(int(size)))
    assert gas.calculate_memory_gas_cost(
        size
    ) == gas.calculate_memory_gas_cost(aligned)


@given(size=uints(MEMORY_BOUND))
def test_memory_gas_cost_matches_formula(gas: ModuleType, size: Uint) -> None:
    """
    Memory cost matches the Yellow Paper's expansion formula.

    C_mem(a) = G_memory * a + floor(a**2 / 512), where a = ceil(size/32)
    words. The quadratic denominator (512) and the linear/quadratic split
    are normative; only the per-word coefficient is a fork-repriced
    constant, so it is read from the fork rather than hard-coded.
    """
    words = ceil32_int(int(size)) // 32
    per_word = int(gas.GasCosts.MEMORY_PER_WORD)
    expected = per_word * words + words**2 // 512
    assert int(gas.calculate_memory_gas_cost(size)) == expected


@given(a=uints(MEMORY_BOUND), b=uints(MEMORY_BOUND))
def test_memory_gas_cost_is_superadditive_on_words(
    gas: ModuleType, a: Uint, b: Uint
) -> None:
    """
    Check that one allocation never costs less than two.

    For word-aligned sizes, a single allocation of `a + b` costs at
    least as much as separate allocations of `a` and `b`: growing
    memory never gets cheaper per word. Sub-word sizes round up to a
    full word, so the law only holds on aligned sizes.
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
    Extending memory in any number of steps must cost exactly the
    difference between the final and initial aligned-size costs: gas
    charged for memory depends only on the peak size reached, never on
    the path taken to reach it.
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


@given(provided_gas=uints((1 << 63) - 1))
def test_max_message_call_gas_reserves_one_64th(
    gas: ModuleType, provided_gas: Uint
) -> None:
    """A call forwards all but one 64th of available gas."""
    forwarded = gas.max_message_call_gas(provided_gas)
    assert forwarded <= provided_gas
    assert provided_gas - forwarded == provided_gas // Uint(64)


@given(length=uints(1 << 17), delta=uints(1 << 17))
def test_init_code_cost_is_monotonic_and_word_quantized(
    gas: ModuleType, length: Uint, delta: Uint
) -> None:
    """Init code cost grows with length, per 32-byte word."""
    assert gas.init_code_cost(length + delta) >= gas.init_code_cost(length)
    assert gas.init_code_cost(length) == gas.init_code_cost(
        Uint(ceil32_int(int(length)))
    )


def test_blob_gas_price_at_zero_excess_is_minimum(gas: ModuleType) -> None:
    """
    At zero excess blob gas the price is the minimum blob gasprice.

    Grounding: EIP-4844 sets ``MIN_BLOB_GASPRICE = 1`` and defines the price
    as ``fake_exponential(MIN_BLOB_GASPRICE, excess_blob_gas, ...)``, which
    equals the factor when the numerator is zero. Non-circular: it pins the
    documented floor/base case against the ``BLOB_MIN_GASPRICE`` constant
    rather than re-deriving the Taylor series.
    """
    assert (
        gas.calculate_blob_gas_price(U64(0)) == gas.GasCosts.BLOB_MIN_GASPRICE
    )


@given(excess=blob_u64(BLOB_GAS_BOUND), delta=blob_u64(BLOB_GAS_BOUND))
def test_blob_gas_price_is_monotonic_and_floored(
    gas: ModuleType, excess: U64, delta: U64
) -> None:
    """
    Blob gasprice never decreases as excess blob gas grows, and never drops
    below the minimum.

    Grounding: EIP-4844 designs the blob gasprice to rise exponentially with
    excess blob gas (more blobs than target raises the price, fewer lowers
    it). Non-circular: monotonicity and the ``>= MIN_BLOB_GASPRICE`` floor are
    qualitative claims that hold for any exponential, so they catch sign or
    off-by-one errors without restating the exact series.
    """
    lower = gas.calculate_blob_gas_price(excess)
    higher = gas.calculate_blob_gas_price(U64(int(excess) + int(delta)))
    assert higher >= lower
    assert lower >= gas.GasCosts.BLOB_MIN_GASPRICE


def test_total_blob_gas_zero_for_non_blob_tx(
    gas: ModuleType, transactions: ModuleType
) -> None:
    """
    A non-blob transaction consumes no blob gas.

    Grounding: EIP-4844's ``get_total_blob_gas`` and the function docstring
    scope blob gas to blob-carrying transactions only. Non-circular boundary:
    it fixes the zero case for the entire non-blob transaction family.
    """
    for name in (
        "LegacyTransaction",
        "AccessListTransaction",
        "FeeMarketTransaction",
    ):
        tx = build_zeroed(getattr(transactions, name))
        assert gas.calculate_total_blob_gas(tx) == U64(0)


@given(count=st.integers(min_value=0, max_value=MAX_BLOBS))
def test_total_blob_gas_scales_with_blob_count(
    gas: ModuleType, transactions: ModuleType, count: int
) -> None:
    """
    Total blob gas is ``GAS_PER_BLOB`` for every versioned hash carried.

    Grounding: EIP-4844 defines ``get_total_blob_gas(tx) = GAS_PER_BLOB *
    len(tx.blob_versioned_hashes)``, with ``GAS_PER_BLOB`` a published
    normative constant read here from the fork. Non-circular: it ties the
    output to the *count of versioned hashes* and the external constant, so a
    wrong multiplier or a count of the wrong field is caught.
    """
    per_blob = gas.GasCosts.PER_BLOB
    total = gas.calculate_total_blob_gas(blob_tx(transactions, count))
    assert total == per_blob * U64(count)
    assert int(total) % int(per_blob) == 0


@given(excess=blob_u64(BLOB_GAS_BOUND))
def test_data_fee_zero_for_non_blob_tx(
    gas: ModuleType, transactions: ModuleType, excess: U64
) -> None:
    """
    A non-blob transaction owes no blob data fee, at any excess blob gas.

    Grounding: the data fee is ``total_blob_gas * blob_gasprice`` (EIP-4844)
    and a non-blob transaction has zero total blob gas. Non-circular boundary:
    it holds regardless of the (always positive) gasprice factor.
    """
    tx = build_zeroed(transactions.LegacyTransaction)
    assert gas.calculate_data_fee(excess, tx) == Uint(0)


@given(count=st.integers(min_value=0, max_value=MAX_BLOBS))
def test_data_fee_at_zero_excess_equals_total_blob_gas(
    gas: ModuleType, transactions: ModuleType, count: int
) -> None:
    """
    At zero excess blob gas the data fee equals the total blob gas.

    Grounding: composes two independently documented facts -- the data fee is
    ``total_blob_gas * blob_gasprice`` (EIP-4844) and the gasprice floor at
    zero excess is ``MIN_BLOB_GASPRICE = 1``. Non-circular: it combines the
    price floor with the total-gas definition rather than restating the
    internal multiplication, so it fails if either the floor or the product is
    wrong.
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
    """
    For a fixed blob transaction, a higher excess blob gas never lowers the
    data fee.

    Grounding: EIP-4844 -- the data fee scales with the blob gasprice, which
    rises with excess blob gas. Non-circular metamorphic relation between two
    calls on the same transaction; it inherits price monotonicity without
    hard-coding the fee amount.
    """
    tx = blob_tx(transactions, count)
    lower = gas.calculate_data_fee(excess, tx)
    higher = gas.calculate_data_fee(U64(int(excess) + int(delta)), tx)
    assert higher >= lower


def test_excess_blob_gas_zero_at_fork_block(gas: ModuleType) -> None:
    """
    When the parent is not this fork's ``Header``, excess blob gas is zero.

    Grounding: the ``# At the fork block, these are defined as zero`` comment
    and the ``isinstance(parent_header, Header)`` guard -- at a fork
    transition the parent header is a different (pre-blob) type. Non-circular
    boundary for the fork-transition path (self-descriptive tier).
    """
    assert gas.calculate_excess_blob_gas(None) == U64(0)


@given(
    excess=blob_u64(BLOB_SUBTARGET_BOUND),
    blob_gas_used=blob_u64(BLOB_SUBTARGET_BOUND),
    base_fee=uints(BASE_FEE_BOUND),
)
def test_excess_blob_gas_zero_below_target(
    gas: ModuleType,
    blocks: ModuleType,
    excess: U64,
    blob_gas_used: U64,
    base_fee: Uint,
) -> None:
    """
    If the parent's total blob gas is below target, next excess is zero.

    Grounding: EIP-4844 -- a block that did not reach the blob-gas target
    resets the running excess to zero. Non-circular boundary that holds for
    both the standard and the EIP-7918 reserve regime (the target check
    precedes the branch), so it catches a broken ``< target`` guard.
    """
    target = int(gas.GasCosts.BLOB_TARGET_GAS_PER_BLOCK)
    assume(int(excess) + int(blob_gas_used) < target)
    parent = build_zeroed(
        blocks.Header,
        excess_blob_gas=excess,
        blob_gas_used=blob_gas_used,
        base_fee_per_gas=base_fee,
    )
    assert gas.calculate_excess_blob_gas(parent) == U64(0)


@given(excess=blob_u64(BLOB_GAS_BOUND))
def test_excess_blob_gas_unchanged_at_target_without_reserve(
    gas: ModuleType, blocks: ModuleType, excess: U64
) -> None:
    """
    A parent that used exactly the target blob gas leaves excess unchanged
    (equilibrium), when the EIP-7918 reserve mechanism is inactive.

    Grounding: EIP-4844 -- the target is the equilibrium point; consuming
    exactly the target keeps excess (hence the blob gasprice) constant. A
    zero execution base fee keeps the EIP-7918 reserve branch inactive, so the
    standard update applies. Non-circular fixed point: it pins the ``+ used -
    target`` cancellation and catches a sign/target error in that subtraction.
    """
    target = gas.GasCosts.BLOB_TARGET_GAS_PER_BLOCK
    parent = build_zeroed(
        blocks.Header,
        excess_blob_gas=excess,
        blob_gas_used=target,
        base_fee_per_gas=Uint(0),
    )
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
    With the reserve mechanism inactive, more blob gas used by the parent
    never lowers the next block's excess blob gas.

    Grounding: EIP-4844 -- excess accumulates the parent's over-target blob
    usage, so it is non-decreasing in the parent's blob gas used. A zero base
    fee keeps the EIP-7918 reserve branch inactive. Non-circular metamorphic
    monotonicity between two parents differing only in blob gas used.
    """

    def excess_for(used: U64) -> U64:
        parent = build_zeroed(
            blocks.Header,
            excess_blob_gas=excess,
            blob_gas_used=used,
            base_fee_per_gas=Uint(0),
        )
        return gas.calculate_excess_blob_gas(parent)

    more = U64(int(blob_gas_used) + int(extra_used))
    assert excess_for(more) >= excess_for(blob_gas_used)


@given(base_fee=uints(BASE_FEE_BOUND))
def test_excess_blob_gas_reserve_prevents_reset(
    gas: ModuleType, blocks: ModuleType, base_fee: Uint
) -> None:
    """
    EIP-7918: when the execution base fee dominates the blob base fee, a
    parent that used exactly the target does not reset excess to zero.

    With zero parent excess (blob gasprice at its floor) and a realistic
    execution base fee, the reserve branch keeps a positive -- but dampened --
    excess, instead of the zero the standard EIP-4844 update would produce.

    Grounding: EIP-7918 introduces a reserve price so the blob base fee cannot
    collapse while blobs are cheap relative to execution gas. Non-circular:
    it asserts the qualitative outcome (excess stays positive yet below the
    parent's blob gas used) that distinguishes the reserve regime from the
    standard one, without re-deriving the dampening fraction.
    """
    target = gas.GasCosts.BLOB_TARGET_GAS_PER_BLOCK
    # base_fee >= 17 guarantees BLOB_BASE_COST * base_fee exceeds
    # PER_BLOB * MIN_BLOB_GASPRICE, activating the reserve branch.
    assume(int(base_fee) >= 17)
    parent = build_zeroed(
        blocks.Header,
        excess_blob_gas=U64(0),
        blob_gas_used=target,
        base_fee_per_gas=base_fee,
    )
    result = gas.calculate_excess_blob_gas(parent)
    assert U64(0) < result < target
