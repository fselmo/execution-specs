"""
Example fuzz tests authored with the shared strategy library.

These demonstrate the in-file fuzzing idiom: draw fuzzed-but-valid inputs
from a seeded ``random.Random`` and let the reference spec compute the
expected state (``post={}``). Each seed fills a deterministic, reproducible
fixture, so under ``fill`` this is an ordinary parametrized test; the
fill-time invariant checks (``--invariant-checks``) validate the computed
state on every case.
"""

import random

import pytest
from execution_testing import (
    Alloc,
    StateTestFiller,
    Transaction,
)
from execution_testing.fuzzing import (
    fuzz_environment,
    fuzzed_bytecode,
    fuzzed_calldata,
)


@pytest.mark.valid_from("Osaka")
@pytest.mark.parametrize("seed", range(8))
def test_fuzzed_contract_execution(
    state_test: StateTestFiller, pre: Alloc, seed: int
) -> None:
    """
    Execute fuzzed contract code with fuzzed calldata.

    The code can read recent block hashes, so the environment carries the
    whole BLOCKHASH window.
    """
    rng = random.Random(seed)
    contract = pre.deploy_contract(code=fuzzed_bytecode(rng))
    sender = pre.fund_eoa()
    tx = Transaction(
        sender=sender,
        to=contract,
        gas_limit=1_000_000,
        data=fuzzed_calldata(rng),
    )
    state_test(env=fuzz_environment(), pre=pre, post={}, tx=tx)
