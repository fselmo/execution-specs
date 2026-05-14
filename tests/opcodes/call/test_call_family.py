"""
CALL family — Category-Partition matrix driver.

This is the single driver test for the *CALL family code-path coverage
layer. The matrix is declared as data in `_matrix.py` (`AXES` for the
parameter dimensions, `CONSTRAINTS` for axis interactions); per-fork
expectations live in `expectations.py::expected_call` and (when sibling
opcodes land) dispatch via `match` inside `expected_call_family`.

Design references:
- Category-Partition Method (Ostrand & Balcer 1988) for the dimension /
  class / boundary structure.
- Specification Pattern (Eric Evans, *Domain-Driven Design*) for the
  `Axis` and `Constraint` dataclasses that catalog the matrix in code.
- The `apply_matrix()` decorator factory in `_matrix.py` translates the
  catalog into `pytest.mark.parametrize` + `filter_combinations`.

PoC scope today is `Op.CALL` × `target_kind ∈ {eoa, contract}` ×
`value_kind ∈ {zero, nonzero}` — see the migration plan for axes and
sibling opcodes still to land.

The body is intentionally thin: build the target via `_scenarios.build_target`,
build the caller via `_scenarios.build_caller`, compute the expectation via
`expectations.expected_call`, run `state_test`, assert.
"""

import pytest
from execution_testing import (
    Account,
    Alloc,
    Environment,
    Fork,
    Op,
    StateTestFiller,
    Transaction,
)

from .._shared.wrappers import HARNESS_RESULT_SLOT, assemble_wrapped
from ._matrix import apply_matrix
from ._scenarios import (
    build_capsule,
    build_target,
    caller_starting_balance_for,
    target_starting_balance,
)
from .expectations import expected_call_family

# NOTE: PoC scope is Berlin onward. Pre-Berlin is blocked by two
# pre-existing framework issues:
#   1. `Op.CALL(...).gas_cost(fork)` returns Berlin cold costs for older
#      forks (same TODO as legacy `tests/frontier/opcodes/test_call.py`).
#   2. `Transaction` default signing emits EIP-155 `v` values that Frontier
#      t8n rejects (`bad v`).
# Both are tracked as follow-ups; the matrix pattern doesn't depend on them.
pytestmark = pytest.mark.valid_from("Berlin")


@apply_matrix()
def test_call(
    state_test: StateTestFiller,
    pre: Alloc,
    fork: Fork,
    opcode: Op,
    target_kind: str,
    value_kind: str,
    wrapper: str,
    gas_variant: str,
    transfer_value: int,
) -> None:
    """
    Run a single CALL and assert against the per-fork expectation.

    Test-capsule architecture (see `_scenarios.build_capsule` and
    `_shared/wrappers.assemble_wrapped`):
        tx -> harness -> [(optional) intermediate per wrapper] -> capsule
    The capsule runs the opcode-under-test and RETURNs the measured gas.
    The harness SSTOREs that value into its own storage; the test asserts
    on `harness.storage[HARNESS_RESULT_SLOT]`.
    """
    # Runtime skip for axis values that need fork gates beyond what
    # pytest's per-param `valid_from` can express in combination with
    # the module-level pytestmark. (target_kind="7702-delegated" needs
    # EIP-7702, only enabled Prague+.)
    if target_kind == "7702-delegated" and not fork.is_eip_enabled(7702):
        pytest.skip("target_kind=7702-delegated requires EIP-7702 (Prague+)")

    caller_start = caller_starting_balance_for(gas_variant)
    target, target_secondary = build_target(pre, target_kind, fork)
    capsule = build_capsule(
        pre,
        fork,
        opcode,
        target,
        transfer_value,
        starting_balance=caller_start,
    )
    sender = pre.fund_eoa()

    harness = assemble_wrapped(
        capsule_address=capsule, wrapper=wrapper, pre=pre, fork=fork
    )

    expected = expected_call_family(
        fork,
        opcode=opcode,
        target_kind=target_kind,
        value_kind=value_kind,
        wrapper=wrapper,
        gas_variant=gas_variant,
        transfer_value=transfer_value,
        # Pass runtime addresses + balance so expected_call_family can
        # build a BAL expectation on Amsterdam+ (EIP-7928). Pre-Amsterdam,
        # these are unused.
        caller_address=capsule,
        target_address=target,
        target_secondary_address=target_secondary,
        caller_starting_balance=caller_start,
    )

    tx = Transaction(to=harness, sender=sender, gas_limit=500_000, value=0)
    target_start = target_starting_balance(target_kind)
    post: dict = {
        harness: Account(
            storage={HARNESS_RESULT_SLOT: expected.measured_call_gas},
        ),
        capsule: Account(
            balance=caller_start + expected.caller_balance_delta,
        ),
    }
    # Precompile addresses are not pre-funded — they only appear in the
    # post-allocation if the call actually moved value to them. Other
    # target kinds pre-exist with a starting balance and always appear.
    if target_start > 0 or expected.target_balance_delta != 0:
        post[target] = Account(
            balance=target_start + expected.target_balance_delta,
        )
    state_test(
        env=Environment(),
        pre=pre,
        tx=tx,
        post=post,
        # `None` pre-Amsterdam (BAL not enabled); on Amsterdam+ this is
        # a BlockAccessListExpectation that the framework verifies via
        # subsequence matching against the t8n-produced BAL.
        expected_block_access_list=expected.block_access_list,
    )
