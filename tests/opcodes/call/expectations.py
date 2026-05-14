"""
Per-fork expected outcomes for the CALL family.

`expected_call_family` is the single dispatch point for everything that
differs about the *CALL opcodes across forks. The matrix-parametrized
driver (`test_call_family.py`) reads one `CallExpected` per parameter
combination and asserts against it. To answer "what changes about CALL
on fork X?" — read this file.

Per-opcode dispatch is via `match opcode: case Op.CALL: ...` (Dimension 1
final pick). Each arm contains the opcode's own logic; no central
`if opcode is …` cascade.

The `CallExpected` dataclass and the test-matrix catalog live in
`_matrix.py`.
"""

from typing import Optional

from execution_testing import (
    Address,
    BalAccountExpectation,
    BalBalanceChange,
    BlockAccessListExpectation,
    Fork,
    Op,
)

from ._matrix import CallExpected
from ._scenarios import (
    PRECOMPILE_IDENTITY_BASE_GAS,
    TARGET_STARTING_BALANCE,
)


def expected_call_family(
    fork: Fork,
    *,
    opcode: Op,
    target_kind: str,
    value_kind: str,
    wrapper: str,
    gas_variant: str,
    transfer_value: int,
    caller_address: Optional[Address] = None,
    target_address: Optional[Address] = None,
    target_secondary_address: Optional[Address] = None,
    caller_starting_balance: int = 0,
) -> CallExpected:
    """
    Compute the expected outcome of a *CALL invocation under `fork`.

    Dispatches on `opcode` to the appropriate arm. All per-fork branching
    for an opcode lives inside its arm; new EIP-introduced observable
    effects (BAL, transfer logs, etc.) are added as inline
    `if fork.is_eip_enabled(NNN):` branches near the end of each arm.
    """
    match opcode:
        case Op.CALL:
            return _expected_call(
                fork,
                target_kind=target_kind,
                value_kind=value_kind,
                wrapper=wrapper,
                gas_variant=gas_variant,
                transfer_value=transfer_value,
                caller_address=caller_address,
                target_address=target_address,
                target_secondary_address=target_secondary_address,
                caller_starting_balance=caller_starting_balance,
            )
        case Op.CALLCODE:
            return _expected_callcode(
                fork,
                target_kind=target_kind,
                value_kind=value_kind,
                wrapper=wrapper,
                gas_variant=gas_variant,
                transfer_value=transfer_value,
            )
        case Op.DELEGATECALL:
            # DELEGATECALL filtered to gas_variant="sufficient" only.
            return _expected_delegatecall(
                fork,
                target_kind=target_kind,
                wrapper=wrapper,
            )
        case Op.STATICCALL:
            # STATICCALL filtered to gas_variant="sufficient" only.
            return _expected_staticcall(
                fork,
                target_kind=target_kind,
                wrapper=wrapper,
            )
        case _:
            raise NotImplementedError(
                f"unexpected opcode in CALL family: {opcode!r}"
            )


def _expected_call(
    fork: Fork,
    *,
    target_kind: str,
    value_kind: str,
    wrapper: str,
    gas_variant: str,
    transfer_value: int,
    caller_address: Optional[Address] = None,
    target_address: Optional[Address] = None,
    target_secondary_address: Optional[Address] = None,
    caller_starting_balance: int = 0,
) -> CallExpected:
    """
    CALL transfers value (when nonzero) from caller to target; runs the
    target's code in target's own context.

    Precompile targets exercise the EIP-2929 warm-access path (precompile
    addresses are auto-warmed). With `gas=0` forwarded:
    - value=zero: precompile (15 gas needed) OOGs; CALL returns 0.
    - value=nonzero: 2300 stipend covers IDENTITY's 15-gas need;
      CALL returns 1 and value transfers.

    gas_variant=insufficient-balance: caller has 0 balance. Nonzero
    value triggers the `sender_balance < value` check (spec line 437);
    CALL pushes 0; upfront gas is paid; the `sub_call` portion (incl.
    stipend) is refunded; NO value transferred.
    """
    _check_target_kind(target_kind)
    sending_value = _check_value_kind(value_kind)
    _check_wrapper(wrapper)

    is_precompile = target_kind == "precompile"
    is_delegated = target_kind == "7702-delegated"
    insufficient_balance = gas_variant == "insufficient-balance"

    # Static-context revert: a CALL with nonzero value inside a static
    # context raises WriteInStaticContext (spec line 374). The capsule's
    # frame aborts; STATICCALL returns 0 with no return data; the harness
    # MLOADs zero from fresh memory and SSTOREs 0. Nothing transfers.
    if wrapper == "under-STATICCALL" and sending_value:
        return CallExpected(
            call_returns_one=False,
            measured_call_gas=0,
            caller_balance_delta=0,
            target_balance_delta=0,
        )

    gross_call_gas = Op.CALL(
        address_warm=is_precompile,  # precompiles pre-warmed per EIP-2929
        value_transfer=sending_value,
        # Precompile addresses have no balance/code, so sending value to
        # one charges NEW_ACCOUNT. Non-precompile targets are pre-funded
        # with TARGET_STARTING_BALANCE so they're "alive."
        account_new=is_precompile and sending_value,
        # 7702-delegated targets charge an additional cold-access cost
        # for the delegate address. delegated_address_warm=False since
        # we don't pre-warm the delegate.
        delegated_address=is_delegated,
        delegated_address_warm=False,
    ).gas_cost(fork)

    if insufficient_balance:
        # sender_balance < value: spec push 0, refund sub_call (which
        # includes the stipend). Measured gas = upfront only (= gross
        # minus the stipend, since the stipend was added to sub_call).
        return CallExpected(
            call_returns_one=False,
            measured_call_gas=(gross_call_gas - fork.gas_costs().CALL_STIPEND),
            caller_balance_delta=0,  # nothing transferred
            target_balance_delta=0,
        )

    if is_precompile and not sending_value:
        # No stipend; IDENTITY OOGs; CALL returns 0; no refund.
        return CallExpected(
            call_returns_one=False,
            measured_call_gas=gross_call_gas,
            caller_balance_delta=0,
            target_balance_delta=0,
        )

    if is_precompile and sending_value:
        # Stipend (2300) covers IDENTITY (15); 2285 refunded.
        stipend_refund = (
            fork.gas_costs().CALL_STIPEND - PRECOMPILE_IDENTITY_BASE_GAS
        )
        return CallExpected(
            call_returns_one=True,
            measured_call_gas=gross_call_gas - stipend_refund,
            caller_balance_delta=-transfer_value,
            target_balance_delta=transfer_value,
            block_access_list=_bal_for_call_transfer(
                fork,
                caller_address=caller_address,
                target_address=target_address,
                target_secondary_address=target_secondary_address,
                caller_starting_balance=caller_starting_balance,
                target_kind=target_kind,
                transfer_value=transfer_value,
            ),
        )

    # Non-precompile path (eoa/contract/7702). STOP callee, full stipend
    # refunded when value > 0.
    if sending_value:
        measured_call_gas = gross_call_gas - fork.gas_costs().CALL_STIPEND
    else:
        measured_call_gas = gross_call_gas

    return CallExpected(
        call_returns_one=True,
        measured_call_gas=measured_call_gas,
        caller_balance_delta=-transfer_value if sending_value else 0,
        target_balance_delta=transfer_value if sending_value else 0,
        block_access_list=(
            _bal_for_call_transfer(
                fork,
                caller_address=caller_address,
                target_address=target_address,
                target_secondary_address=target_secondary_address,
                caller_starting_balance=caller_starting_balance,
                target_kind=target_kind,
                transfer_value=transfer_value,
            )
            if sending_value
            else None
        ),
    )


def _expected_callcode(
    fork: Fork,
    *,
    target_kind: str,
    value_kind: str,
    wrapper: str,
    gas_variant: str,
    transfer_value: int,
) -> CallExpected:
    """
    CALLCODE runs the target's code in the *caller's* storage/balance
    context. The `value` argument affects gas (value-transfer cost +
    stipend) and `msg.value` inside the callee, but no actual balance
    moves between accounts. Caller and target balances are unchanged.

    Precompile target: same stipend / OOG behavior as CALL, but never
    moves balance (CALLCODE doesn't transfer value).

    gas_variant=insufficient-balance: same `sender_balance < value`
    branch as CALL — push 0, refund sub_call.
    """
    _check_target_kind(target_kind)
    sending_value = _check_value_kind(value_kind)
    _check_wrapper(wrapper)

    is_precompile = target_kind == "precompile"
    is_delegated = target_kind == "7702-delegated"
    insufficient_balance = gas_variant == "insufficient-balance"
    gross_call_gas = Op.CALLCODE(
        address_warm=is_precompile,
        value_transfer=sending_value,
        # CALLCODE never actually moves balance, so NEW_ACCOUNT is not
        # charged even when the target is a non-alive precompile.
        # (Differs from CALL, which does transfer.)
        account_new=False,
        delegated_address=is_delegated,
        delegated_address_warm=False,
    ).gas_cost(fork)

    if insufficient_balance:
        return CallExpected(
            call_returns_one=False,
            measured_call_gas=(gross_call_gas - fork.gas_costs().CALL_STIPEND),
            caller_balance_delta=0,
            target_balance_delta=0,
        )

    if is_precompile and not sending_value:
        return CallExpected(
            call_returns_one=False,
            measured_call_gas=gross_call_gas,
            caller_balance_delta=0,
            target_balance_delta=0,
        )

    if is_precompile and sending_value:
        stipend_refund = (
            fork.gas_costs().CALL_STIPEND - PRECOMPILE_IDENTITY_BASE_GAS
        )
        return CallExpected(
            call_returns_one=True,
            measured_call_gas=gross_call_gas - stipend_refund,
            caller_balance_delta=0,  # CALLCODE never moves value
            target_balance_delta=0,
        )

    if sending_value:
        measured_call_gas = gross_call_gas - fork.gas_costs().CALL_STIPEND
    else:
        measured_call_gas = gross_call_gas

    return CallExpected(
        call_returns_one=True,
        measured_call_gas=measured_call_gas,
        caller_balance_delta=0,
        target_balance_delta=0,
    )


def _expected_delegatecall(
    fork: Fork,
    *,
    target_kind: str,
    wrapper: str,
) -> CallExpected:
    """
    DELEGATECALL runs target's code in caller's storage/balance/sender
    context. No value argument; no balance changes; no stipend.

    Precompile target: no stipend means IDENTITY OOGs with `gas=0`
    forwarded; DELEGATECALL returns 0 but still costs the warm-access
    gas upfront.
    """
    _check_target_kind(target_kind)
    _check_wrapper(wrapper)

    is_precompile = target_kind == "precompile"
    is_delegated = target_kind == "7702-delegated"
    measured_call_gas = Op.DELEGATECALL(
        address_warm=is_precompile,
        delegated_address=is_delegated,
        delegated_address_warm=False,
    ).gas_cost(fork)

    return CallExpected(
        call_returns_one=not is_precompile,
        measured_call_gas=measured_call_gas,
        caller_balance_delta=0,
        target_balance_delta=0,
    )


def _expected_staticcall(
    fork: Fork,
    *,
    target_kind: str,
    wrapper: str,
) -> CallExpected:
    """
    STATICCALL runs target's code in a static sub-context where state-
    modifying operations would revert. No value argument; no balance
    changes; no stipend.

    Precompile target: like DELEGATECALL, OOGs with `gas=0` forwarded.
    """
    _check_target_kind(target_kind)
    _check_wrapper(wrapper)

    is_precompile = target_kind == "precompile"
    is_delegated = target_kind == "7702-delegated"
    measured_call_gas = Op.STATICCALL(
        address_warm=is_precompile,
        delegated_address=is_delegated,
        delegated_address_warm=False,
    ).gas_cost(fork)

    return CallExpected(
        call_returns_one=not is_precompile,
        measured_call_gas=measured_call_gas,
        caller_balance_delta=0,
        target_balance_delta=0,
    )


# -------- small input-validation helpers shared across arms --------


def _check_target_kind(target_kind: str) -> None:
    if target_kind not in (
        "eoa",
        "contract",
        "precompile",
        "7702-delegated",
    ):
        raise NotImplementedError(
            f"target_kind={target_kind!r} not yet handled in expectations."
        )


def _check_value_kind(value_kind: str) -> bool:
    """Return True iff value_kind asks for a nonzero transfer."""
    if value_kind == "zero":
        return False
    if value_kind == "nonzero":
        return True
    raise NotImplementedError(
        f"value_kind={value_kind!r} not yet handled in expectations."
    )


def _check_wrapper(wrapper: str) -> None:
    if wrapper not in ("direct", "under-CALL", "under-STATICCALL"):
        raise NotImplementedError(
            f"wrapper={wrapper!r} not yet handled in expectations. "
            "Additional wrappers (under-CALLCODE / under-DELEGATECALL / "
            "CREATE-init / tx-init) land when balance/storage "
            "attribution is wired through the driver."
        )


# ---------------------------------------------------------------------------
# EIP-7928 (Block-level Access List) — inline branch.
#
# Pattern mirrors the existing Amsterdam BAL opcode tests under
# `tests/amsterdam/eip7928_*`:
# build a `BlockAccessListExpectation` per scenario, mapping address →
# `BalAccountExpectation`. Verification uses subsequence matching, so we
# only assert on the accounts whose changes we care about (caller and
# target on a successful value transfer). Other touched accounts (sender,
# coinbase, harness, intermediate) are present in the actual BAL but
# don't need explicit assertions to validate.
# ---------------------------------------------------------------------------


def _bal_for_call_transfer(
    fork: Fork,
    *,
    caller_address: Optional[Address],
    target_address: Optional[Address],
    target_secondary_address: Optional[Address],
    caller_starting_balance: int,
    target_kind: str,
    transfer_value: int,
) -> Optional[BlockAccessListExpectation]:
    """
    Build the BAL expectation for a successful CALL value-transfer.

    Returns `None` pre-Amsterdam (EIP-7928 not enabled) or when caller
    / target addresses are unavailable (the test body didn't pass them
    through — defensive default).

    The capsule (the address we treat as "caller" for value-flow
    purposes) shows `post_balance = start - transfer_value`. The target
    shows `post_balance = start + transfer_value`. For precompile
    targets, start is 0 (precompile addresses aren't pre-funded).

    For `target_kind="7702-delegated"`, the delegation_target (the
    contract whose code the EVM fetches when invoking the delegated
    account) is asserted to appear in the BAL with no changes (touched-
    but-not-modified) — mirroring the pattern in
    `tests/amsterdam/eip7928_*/test_block_access_lists_opcodes.py::test_bal_call_7702_delegation_and_oog`.

    `block_access_index=1` matches the single-tx-per-block layout the
    framework produces by default: index 0 is the system/coinbase pre-tx
    set; index 1 is this tx's effects.
    """
    if not fork.is_eip_enabled(7928):
        return None
    if caller_address is None or target_address is None:
        return None

    target_start = (
        0 if target_kind == "precompile" else TARGET_STARTING_BALANCE
    )

    account_expectations: dict[Address, BalAccountExpectation] = {
        caller_address: BalAccountExpectation(
            balance_changes=[
                BalBalanceChange(
                    block_access_index=1,
                    post_balance=caller_starting_balance - transfer_value,
                )
            ],
        ),
        target_address: BalAccountExpectation(
            balance_changes=[
                BalBalanceChange(
                    block_access_index=1,
                    post_balance=target_start + transfer_value,
                )
            ],
        ),
    }

    # EIP-7702: the delegate's code is fetched, so it's "touched" in the
    # access list but has no state changes. `BalAccountExpectation.empty()`
    # asserts "in BAL with no changes."
    if (
        target_kind == "7702-delegated"
        and target_secondary_address is not None
    ):
        account_expectations[target_secondary_address] = (
            BalAccountExpectation.empty()
        )

    return BlockAccessListExpectation(
        account_expectations=account_expectations
    )
