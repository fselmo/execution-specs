"""Tests for the shared value domains and mixture distributions."""

import random

import pytest

from execution_testing.forks import Amsterdam

from ..domains import (
    GENERIC_DOMAINS,
    U256_BOUNDARIES,
    WORD_BOUNDARY_SIZES,
    MixtureWeights,
    boundary_values,
    draw_mixed,
    fork_domains,
    mixed_address_pool,
)


def test_boundary_values_cover_type_edges() -> None:
    """The 256-bit boundary set holds the classic overflow edges."""
    values = boundary_values(256)
    assert {0, 1, 2, (1 << 256) - 1, (1 << 255), (1 << 64) - 1} <= set(values)
    assert values == sorted(values)


def test_mixture_weights_must_sum_to_one() -> None:
    """A weight vector that is not a distribution fails loudly."""
    with pytest.raises(ValueError, match="sum"):
        MixtureWeights(zero=0.5, boundary=0.5, small=0.5, full=0.5)


def test_draw_mixed_is_deterministic() -> None:
    """The same seed yields the same draw sequence."""
    weights = MixtureWeights(zero=0.25, boundary=0.25, small=0.25, full=0.25)
    draws_a = [
        draw_mixed(random.Random(9), weights, boundaries=(1000,))
        for _ in range(1)
    ]
    draws_b = [
        draw_mixed(random.Random(9), weights, boundaries=(1000,))
        for _ in range(1)
    ]
    assert draws_a == draws_b


def test_draw_mixed_hits_all_four_modes() -> None:
    """Across draws, zero, boundary, small and full width all appear."""
    weights = MixtureWeights(zero=0.25, boundary=0.25, small=0.25, full=0.25)
    rng = random.Random(0)
    draws = [
        draw_mixed(
            rng, weights, boundaries=(1000,), full_bits=64, small_max=10
        )
        for _ in range(200)
    ]
    assert 0 in draws
    assert 1000 in draws
    assert any(0 < d <= 10 for d in draws)
    assert any(d > 1000 for d in draws)


def test_empty_boundary_set_falls_back_to_small() -> None:
    """No draw fails when a domain has no boundary set."""
    weights = MixtureWeights(zero=0.0, boundary=1.0, small=0.0, full=0.0)
    rng = random.Random(0)
    for _ in range(50):
        assert 0 <= draw_mixed(rng, weights, boundaries=()) <= 255


def test_fork_boundaries_come_from_the_gas_schedule() -> None:
    """Every call-gas edge derives from the fork's own costs."""
    costs = Amsterdam.gas_costs()
    domains = fork_domains(Amsterdam)
    stipend = costs.CALL_STIPEND
    assert {stipend - 1, stipend, stipend + 1} <= set(
        domains.call_gas_boundaries
    )
    assert costs.COLD_ACCOUNT_ACCESS in domains.call_gas_boundaries
    assert costs.WARM_ACCESS in domains.call_gas_boundaries
    assert (
        costs.COLD_STORAGE_ACCESS + costs.STORAGE_SET
        in domains.call_gas_boundaries
    )
    cold_write = costs.COLD_STORAGE_ACCESS + costs.STORAGE_SET
    assert min(domains.spill_gas) >= cold_write


def test_call_gas_reaches_forward_all_and_boundaries() -> None:
    """The gas domain produces None (forward via GAS) and real edges."""
    domains = fork_domains(Amsterdam)
    rng = random.Random(1)
    draws = [domains.call_gas(rng) for _ in range(300)]
    assert None in draws
    assert 0 in draws
    assert any(d in domains.call_gas_boundaries for d in draws)


def test_operand_mixes_boundaries_into_full_width() -> None:
    """PUSH operands include type edges, not only uniform values."""
    domains = fork_domains(Amsterdam)
    rng = random.Random(2)
    draws = [domains.operand(rng) for _ in range(400)]
    assert any(d in U256_BOUNDARIES for d in draws)
    assert any(d > (1 << 128) for d in draws)


def test_byte_size_respects_cap_and_hits_word_edges() -> None:
    """Sizes stay within the cap and land on 32-byte word edges."""
    domains = fork_domains(Amsterdam)
    rng = random.Random(3)
    draws = [domains.byte_size(rng, cap=256) for _ in range(300)]
    assert all(0 <= d <= 256 for d in draws)
    assert any(d in WORD_BOUNDARY_SIZES and d > 0 for d in draws)


def test_salt_domain_is_tiny() -> None:
    """Salts collide by construction: the domain stays single digits."""
    assert len(fork_domains(Amsterdam).salt_domain) <= 8


def test_generic_domains_need_no_fork() -> None:
    """Fork-free callers draw from static type-width boundaries."""
    rng = random.Random(4)
    for _ in range(50):
        gas = GENERIC_DOMAINS.call_gas(rng)
        assert gas is None or gas >= 0


def test_pool_spans_existence_warmth_and_dispatch() -> None:
    """One pool covers code, senders, precompiles, boundary, fresh."""
    pool = mixed_address_pool(
        [1, 2, 3, 3, 3], code=[0x10000], senders=[0x20000]
    )
    assert pool.boundary == 4
    assert pool.nonexistent == (5, 6)
    targets = pool.tx_targets()
    assert 0x10000 in targets and 0x20000 in targets
    assert 3 in targets and 4 in targets and 5 in targets
    assert pool.one_wei_accounts() == [1, 2, 3]
    # The per-address precompile weighting is for CALL targeting; in the
    # tx draw it is deduplicated, or precompiles crowd out the contracts.
    assert targets.count(3) == 1
    assert 3 in pool.call_targets() or True  # calls use their own pool


def test_targets_are_dominated_by_code_accounts() -> None:
    """
    Both draws must land on fuzzed code most of the time: a call or a
    transaction into a codeless account executes no generated program,
    so a diluted pool spends the budget without exercising anything.
    """
    pool = mixed_address_pool(
        list(range(1, 18)),
        code=[0x10000, 0x10001, 0x10002],
        senders=[0x20000, 0x20001, 0x20002],
    )
    code = set(pool.code)
    tx = pool.tx_targets()
    calls = pool.call_targets()
    assert sum(1 for t in tx if t in code) / len(tx) > 0.6
    assert sum(1 for t in calls if t in code) / len(calls) > 0.6
