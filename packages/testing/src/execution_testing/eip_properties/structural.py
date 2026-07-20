"""
Support for structural archetypes (the execution-presence oracle tier).

A structural property asks: does a declared change actually show up in a built
block? That confirms the *wiring* end-to-end — the fork predicate says a header
field is required, and a freshly built block's header really carries it — not
merely that the predicate returns the expected value (which would be circular).

Some structural changes need a small, explicit *observable*: the manifest names
the fork predicate that changed (`header_bal_hash_required`), but the thing to
look at is the header field it governs (`block_access_list_hash`). That mapping
is bespoke by nature, so it lives in an explicit, reviewable registry that an
archetype author or agent extends — never inferred and silently wrong.
"""

from typing import Dict, Optional

from execution_testing.client_clis.clis.execution_specs import (
    ExecutionSpecsTransitionTool,
)
from execution_testing.fixtures.blockchain import FixtureHeader
from execution_testing.forks import Fork
from execution_testing.specs import Block, BlockchainTest
from execution_testing.specs.blockchain import (
    environment_from_parent_header,
)
from execution_testing.test_types import Alloc, Environment

# Fork predicate (as it appears in the manifest) -> the FixtureHeader field it
# governs. Extend this when an EIP adds a header field gated by a predicate.
HEADER_FIELD_FEATURES: Dict[str, str] = {
    "header_bal_hash_required": "block_access_list_hash",
    "header_slot_number_required": "slot_number",
    "header_requests_required": "requests_hash",
    "header_excess_blob_gas_required": "excess_blob_gas",
    "header_blob_gas_used_required": "blob_gas_used",
    "header_withdrawals_required": "withdrawals_root",
    "header_beacon_root_required": "parent_beacon_block_root",
    "header_base_fee_required": "base_fee_per_gas",
}

_t8n: Optional[ExecutionSpecsTransitionTool] = None


def _tool() -> ExecutionSpecsTransitionTool:
    global _t8n
    if _t8n is None:
        _t8n = ExecutionSpecsTransitionTool()
    return _t8n


def built_header_at_fork(fork: Fork) -> FixtureHeader:
    """
    Build a minimal (empty) block at ``fork`` and return its header.

    The reference spec computes the header, so a field that is present here
    genuinely flowed through block construction — not just the predicate.
    """
    test = BlockchainTest(
        pre=Alloc(),
        blocks=[Block(txs=[])],
        post={},
        fork=fork,
        genesis_environment=Environment(),
    )
    pre, genesis = test.make_genesis(apply_pre_allocation_blockchain=True)
    env = environment_from_parent_header(genesis.header)
    built = test.generate_block_data(
        t8n=_tool(),
        block=test.blocks[0],
        previous_env=env,
        previous_alloc=pre,
    )
    return built.header
