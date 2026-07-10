"""Properties of the gas calculation functions."""

import importlib
from types import ModuleType
from typing import List, Tuple

import pytest
from ethereum_types.numeric import U256, Uint
from hypothesis import given
from hypothesis import strategies as st

from .strategies import uints

MEMORY_BOUND = 1 << 24


@pytest.fixture(scope="session")
def gas(fork_name: str) -> ModuleType:
    """Gas module of the fork under test."""
    return importlib.import_module(f"ethereum.forks.{fork_name}.vm.gas")


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
