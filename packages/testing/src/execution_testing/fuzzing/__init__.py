"""
Reusable input strategies for authoring fuzz tests.

These helpers let a test author draw fuzzed-but-valid inputs from a seeded
``random.Random`` in the ordinary test-writing idiom::

    import random

    from execution_testing import (
        Alloc, Environment, StateTestFiller, Transaction,
    )
    from execution_testing.fuzzing import fuzzed_bytecode, fuzzed_calldata


    @pytest.mark.valid_from("Osaka")
    @pytest.mark.parametrize("seed", range(8))
    def test_fuzzed_execution(
        state_test: StateTestFiller, pre: Alloc, seed: int
    ) -> None:
        rng = random.Random(seed)
        contract = pre.deploy_contract(code=fuzzed_bytecode(rng))
        sender = pre.fund_eoa()
        tx = Transaction(
            sender=sender,
            to=contract,
            gas_limit=1_000_000,
            data=fuzzed_calldata(rng),
        )
        # `post={}` — the reference spec computes the expected state; the
        # fill-time invariant checks (`--invariant-checks`) validate it.
        state_test(env=Environment(), pre=pre, post={}, tx=tx)

Each seed fills a deterministic, reproducible fixture, so in CI a fuzz test
is just a parametrized test; under a fuzzing service the same authoring
artifact is driven over an unbounded seed range.
"""

from .domains import (
    GENERIC_DOMAINS,
    AddressPool,
    MixtureWeights,
    ValueDomains,
    WalkWeights,
    boundary_values,
    draw_mixed,
    fork_domains,
    mixed_address_pool,
)
from .strategies import fuzzed_bytecode, fuzzed_calldata

__all__ = [
    "AddressPool",
    "GENERIC_DOMAINS",
    "MixtureWeights",
    "ValueDomains",
    "WalkWeights",
    "boundary_values",
    "draw_mixed",
    "fork_domains",
    "fuzzed_bytecode",
    "fuzzed_calldata",
    "mixed_address_pool",
]
