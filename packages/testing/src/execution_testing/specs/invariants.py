"""
Global chain invariants checked on filled blocks.

These are laws of the state transition that must hold for every valid
block regardless of what the test exercises: ether conservation, gas
accounting consistency, and nonce monotonicity. They are checked against
the transition tool output while filling, so a violation means either a
spec bug, a test-framework bug, or an invariant with an unmodeled
funds/nonce flow — all worth surfacing.

Enabled with ``fill --invariant-checks``. Violations are emitted as
``InvariantViolationWarning`` warnings (warn-only while the invariant
ledger is validated against the full test suite) and recorded in the
fixture's ``_info`` metadata via ``FillResult.metadata``.
"""

import warnings
from typing import TYPE_CHECKING, List, Type

from pydantic import BaseModel

if TYPE_CHECKING:
    from ..base_types import Address
    from ..client_clis.cli_types import Result
    from ..forks.base_fork import BaseFork
    from ..test_types import Alloc, Environment, Transaction

GWEI = 10**9


class InvariantViolationWarning(UserWarning):
    """Warning category for chain invariant violations found during fill."""


class InvariantViolation(BaseModel):
    """A single violated invariant, with a human-readable breakdown."""

    invariant: str
    message: str


_ENABLED = False


def enable_invariant_checks() -> None:
    """Enable invariant checking for this process."""
    global _ENABLED
    _ENABLED = True


def invariant_checks_enabled() -> bool:
    """Return whether invariant checking is enabled."""
    return _ENABLED


def _total_balance(alloc: "Alloc") -> int:
    return sum(
        int(account.balance or 0)
        for account in alloc.root.values()
        if account is not None
    )


def _accepted_txs(
    txs: List["Transaction"], result: "Result"
) -> List["Transaction"]:
    rejected_indices = {
        int(rejected.index) for rejected in result.rejected_transactions
    }
    return [
        tx for index, tx in enumerate(txs) if index not in rejected_indices
    ]


def check_ether_conservation(
    fork: Type["BaseFork"],
    pre_alloc: "Alloc",
    post_alloc: "Alloc",
    result: "Result",
    env: "Environment",
    txs: List["Transaction"],
    reward: int | None = None,
    base_fee_per_gas: int | None = None,
) -> List[InvariantViolation]:
    """
    Total ether may change only by issuance (withdrawals, pre-merge
    rewards) minus what the protocol burns (base fees, blob fees).

    Known unmodeled flow: SELFDESTRUCT with the destroyed account as
    beneficiary burns the balance; a violation on such a test is the
    invariant's blind spot, not a spec bug.
    """
    delta = _total_balance(post_alloc) - _total_balance(pre_alloc)

    withdrawals_wei = 0
    if env.withdrawals is not None:
        withdrawals_wei = sum(int(w.amount) for w in env.withdrawals) * GWEI

    if base_fee_per_gas is None and env.base_fee_per_gas is not None:
        base_fee_per_gas = int(env.base_fee_per_gas)
    base_fee_burn = (base_fee_per_gas or 0) * int(result.gas_used)

    blob_fee_burn = 0
    if fork.supports_blobs():
        # The transition tool result does not carry blob gas used;
        # derive it from the accepted transactions' blob counts, the
        # same way the block header is populated.
        if result.blob_gas_used is not None:
            blob_gas_used = int(result.blob_gas_used)
        else:
            blob_count = sum(
                len(tx.blob_versioned_hashes or [])
                for tx in _accepted_txs(txs, result)
            )
            blob_gas_used = fork.blob_gas_per_blob() * blob_count
        if blob_gas_used > 0:
            excess_blob_gas = (
                result.excess_blob_gas
                if result.excess_blob_gas is not None
                else env.excess_blob_gas
            )
            blob_gas_price = fork.blob_gas_price_calculator()(
                excess_blob_gas=int(excess_blob_gas or 0)
            )
            blob_fee_burn = blob_gas_used * int(blob_gas_price)

    if reward is None:
        reward = fork.get_reward()

    expected_delta = withdrawals_wei + reward - base_fee_burn - blob_fee_burn
    if delta != expected_delta:
        return [
            InvariantViolation(
                invariant="ether_conservation",
                message=(
                    f"balance delta {delta} != expected {expected_delta} "
                    f"(withdrawals={withdrawals_wei}, reward={reward}, "
                    f"base_fee_burn={base_fee_burn}, "
                    f"blob_fee_burn={blob_fee_burn}, "
                    f"unexplained={delta - expected_delta})"
                ),
            )
        ]
    return []


def check_gas_accounting(
    result: "Result", env: "Environment"
) -> List[InvariantViolation]:
    """
    Block gas used must not exceed the gas limit, and receipt cumulative
    gas must be strictly increasing and sum to the block's gas used.
    """
    violations: List[InvariantViolation] = []
    gas_used = int(result.gas_used)

    if gas_used > int(env.gas_limit):
        violations.append(
            InvariantViolation(
                invariant="gas_used_within_limit",
                message=(
                    f"block gas_used {gas_used} exceeds "
                    f"gas_limit {int(env.gas_limit)}"
                ),
            )
        )

    cumulative = 0
    for index, receipt in enumerate(result.receipts):
        if receipt.cumulative_gas_used is None:
            continue
        receipt_cumulative = int(receipt.cumulative_gas_used)
        if receipt_cumulative <= cumulative and index > 0:
            violations.append(
                InvariantViolation(
                    invariant="receipt_gas_monotonicity",
                    message=(
                        f"receipt {index} cumulative gas "
                        f"{receipt_cumulative} <= previous {cumulative}"
                    ),
                )
            )
        cumulative = receipt_cumulative
    if result.receipts and cumulative and cumulative != gas_used:
        violations.append(
            InvariantViolation(
                invariant="receipt_gas_totals",
                message=(
                    f"last receipt cumulative gas {cumulative} != "
                    f"block gas_used {gas_used}"
                ),
            )
        )
    return violations


def check_nonce_monotonicity(
    pre_alloc: "Alloc",
    post_alloc: "Alloc",
    txs: List["Transaction"],
    result: "Result",
) -> List[InvariantViolation]:
    """
    Account nonces never decrease, and each sender's nonce advances by
    at least its number of accepted transactions in the block.

    Known legitimate trigger: an account that SELFDESTRUCTs and is
    re-created in the same block (for example by a withdrawal credit)
    restarts at nonce 0. Account death is the only spec-level path to a
    lower nonce, so the warning still marks exactly the cases worth a
    look.
    """
    violations: List[InvariantViolation] = []

    def nonce_of(alloc: "Alloc", address: "Address") -> int | None:
        account = alloc.root.get(address)
        if account is None:
            return None
        return int(account.nonce or 0)

    for address, account in pre_alloc.root.items():
        if account is None:
            continue
        pre_nonce = int(account.nonce or 0)
        post_nonce = nonce_of(post_alloc, address)
        if post_nonce is not None and post_nonce < pre_nonce:
            violations.append(
                InvariantViolation(
                    invariant="nonce_never_decreases",
                    message=(
                        f"nonce of {address} decreased "
                        f"{pre_nonce} -> {post_nonce}"
                    ),
                )
            )

    accepted_count_by_sender: dict = {}
    for tx in _accepted_txs(txs, result):
        if tx.sender is None:
            continue
        accepted_count_by_sender[tx.sender] = (
            accepted_count_by_sender.get(tx.sender, 0) + 1
        )

    for sender, count in accepted_count_by_sender.items():
        pre_account = pre_alloc.root.get(sender)
        pre_nonce = (
            int(pre_account.nonce or 0) if pre_account is not None else 0
        )
        post_nonce = nonce_of(post_alloc, sender)
        if post_nonce is not None and post_nonce < pre_nonce + count:
            violations.append(
                InvariantViolation(
                    invariant="sender_nonce_advances",
                    message=(
                        f"sender {sender} nonce {pre_nonce} -> "
                        f"{post_nonce} after {count} accepted "
                        "transactions"
                    ),
                )
            )
    return violations


def check_block_invariants(
    fork: Type["BaseFork"],
    pre_alloc: "Alloc",
    post_alloc: "Alloc",
    result: "Result",
    env: "Environment",
    txs: List["Transaction"],
    reward: int | None = None,
    base_fee_per_gas: int | None = None,
) -> List[InvariantViolation]:
    """Run all block-level invariant checks and warn on violations."""
    violations = [
        *check_ether_conservation(
            fork,
            pre_alloc,
            post_alloc,
            result,
            env,
            txs,
            reward,
            base_fee_per_gas,
        ),
        *check_gas_accounting(result, env),
        *check_nonce_monotonicity(pre_alloc, post_alloc, txs, result),
    ]
    for violation in violations:
        warnings.warn(
            f"[{violation.invariant}] {violation.message}",
            InvariantViolationWarning,
            stacklevel=3,
        )
    return violations
