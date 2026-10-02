"""
Chain invariants checked on every valid block while filling.

Enabled with `fill --invariant-checks`. A violation is emitted as an
`InvariantViolationWarning`; CI turns that warning into an error.
"""

import warnings
from collections import Counter
from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Dict,
    List,
    Optional,
    Sequence,
    Tuple,
    Type,
)

from execution_testing.base_types import Account
from execution_testing.test_types.block_access_list import BalAccountChange
from execution_testing.vm import Op

if TYPE_CHECKING:
    from ..base_types import Address
    from ..client_clis.cli_types import Result
    from ..evm_tools.t8n.evm_trace.bal_witness import BalWitness
    from ..forks.base_fork import BaseFork
    from ..test_types import Alloc, Environment, Transaction
    from ..test_types.block_access_list import BlockAccessList

GWEI = 10**9


class InvariantViolationWarning(UserWarning):
    """Warning category for chain invariant violations found during fill."""


@dataclass(frozen=True)
class InvariantViolation:
    """A single violated invariant, with a human-readable breakdown."""

    invariant: str
    message: str


_ENABLED = False


def enable_invariant_checks(enabled: bool = True) -> None:
    """Enable or disable invariant checking for this process."""
    global _ENABLED
    _ENABLED = enabled


def invariant_checks_enabled() -> bool:
    """Return whether invariant checking is enabled."""
    return _ENABLED


def _accepted_txs(
    txs: Sequence["Transaction"], result: "Result"
) -> List["Transaction"]:
    rejected_indices = {
        int(rejected.index) for rejected in result.rejected_transactions
    }
    return [
        tx for index, tx in enumerate(txs) if index not in rejected_indices
    ]


def _cumulative_gas(result: "Result") -> List[int]:
    """Return each receipt's cumulative gas used, in order."""
    return [
        int(receipt.cumulative_gas_used)
        for receipt in result.receipts
        if receipt.cumulative_gas_used is not None
    ]


def _may_have_run_selfdestruct(result: "Result") -> bool:
    """
    Return whether SELFDESTRUCT may have run in the block.

    A transition tool without opcode counts cannot rule it out.
    """
    if result.opcode_count is None:
        return True
    return result.opcode_count.root.get(Op.SELFDESTRUCT, 0) > 0


def check_ether_conservation(
    fork: Type["BaseFork"],
    pre_alloc: "Alloc",
    post_alloc: "Alloc",
    result: "Result",
    env: "Environment",
    txs: Sequence["Transaction"],
    reward: int,
) -> List[InvariantViolation]:
    """
    Check that total ether changes only by issuance minus the fee burn.

    Before EIP-8246, SELFDESTRUCT can also burn ether, so a block that ran
    it may only lose more ether than the fees explain, never gain any.
    """
    delta = sum(
        int(account.balance) for account in post_alloc.root.values() if account
    ) - sum(
        int(account.balance) for account in pre_alloc.root.values() if account
    )

    withdrawals = 0
    if env.withdrawals is not None:
        withdrawals = sum(int(w.amount) for w in env.withdrawals) * GWEI

    base_fee = int(result.base_fee_per_gas or env.base_fee_per_gas or 0)
    base_fee_burn = base_fee * (_cumulative_gas(result) or [0])[-1]

    blob_fee_burn = 0
    if fork.supports_blobs():
        blob_gas_used = int(result.blob_gas_used or 0)
        if result.blob_gas_used is None:
            blob_gas_used = fork.blob_gas_per_blob() * sum(
                len(tx.blob_versioned_hashes or [])
                for tx in _accepted_txs(txs, result)
            )
        excess_blob_gas = result.excess_blob_gas or env.excess_blob_gas
        blob_gas_price = fork.blob_gas_price_calculator()(
            excess_blob_gas=int(excess_blob_gas or 0)
        )
        blob_fee_burn = blob_gas_used * blob_gas_price

    expected = withdrawals + reward - base_fee_burn - blob_fee_burn
    may_burn = not fork.is_eip_enabled(8246) and _may_have_run_selfdestruct(
        result
    )
    if delta == expected or (may_burn and delta < expected):
        return []
    return [
        InvariantViolation(
            invariant="ether_conservation",
            message=(
                f"balance delta {delta} != expected {expected} "
                f"(withdrawals={withdrawals}, reward={reward}, "
                f"base_fee_burn={base_fee_burn}, "
                f"blob_fee_burn={blob_fee_burn}, "
                f"unexplained={delta - expected})"
            ),
        )
    ]


def check_gas_accounting(
    fork: Type["BaseFork"], result: "Result", env: "Environment"
) -> List[InvariantViolation]:
    """
    Check the header's gas used against the gas limit and the receipts.

    Without EIP-7778 and EIP-8037 the last receipt's cumulative gas equals
    the header's. EIP-7778 keeps refunds in the header, and a refund is at
    most `1 / max_refund_quotient` of a transaction's gas, so the header is
    at most 5/4 of the receipts for a quotient of 5. EIP-8037 makes the
    header the larger of two dimensions whose per-transaction sum covers
    each receipt, so it is at least half.
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

    cumulative = _cumulative_gas(result)
    for index in range(1, len(cumulative)):
        if cumulative[index] <= cumulative[index - 1]:
            violations.append(
                InvariantViolation(
                    invariant="receipt_gas_monotonicity",
                    message=(
                        f"receipt {index} cumulative gas "
                        f"{cumulative[index]} <= previous "
                        f"{cumulative[index - 1]}"
                    ),
                )
            )
    if not cumulative:
        return violations

    receipts_gas = cumulative[-1]
    lowest = receipts_gas
    highest = receipts_gas
    if fork.is_eip_enabled(8037):
        lowest = (receipts_gas + 1) // 2
    if fork.is_eip_enabled(7778) or fork.is_eip_enabled(8037):
        quotient = fork.max_refund_quotient()
        highest = receipts_gas * quotient // (quotient - 1)
    if not lowest <= gas_used <= highest:
        violations.append(
            InvariantViolation(
                invariant="receipt_gas_totals",
                message=(
                    f"block gas_used {gas_used} outside [{lowest}, "
                    f"{highest}] for receipts totaling {receipts_gas}"
                ),
            )
        )
    return violations


def check_nonce_monotonicity(
    pre_alloc: "Alloc",
    post_alloc: "Alloc",
    txs: Sequence["Transaction"],
    result: "Result",
) -> List[InvariantViolation]:
    """
    Check that nonces never decrease and senders advance per transaction.

    Account deletion is the only way a nonce goes down, and it needs
    SELFDESTRUCT, so a block that ran it skips the decrease check.
    """
    violations: List[InvariantViolation] = []

    def nonce_of(alloc: "Alloc", address: "Address") -> int | None:
        account = alloc.root.get(address)
        if account is None:
            return None
        return int(account.nonce)

    if not _may_have_run_selfdestruct(result):
        for address in pre_alloc.root:
            pre_nonce = nonce_of(pre_alloc, address)
            post_nonce = nonce_of(post_alloc, address)
            if (
                pre_nonce is not None
                and post_nonce is not None
                and post_nonce < pre_nonce
            ):
                violations.append(
                    InvariantViolation(
                        invariant="nonce_never_decreases",
                        message=(
                            f"nonce of {address} decreased "
                            f"{pre_nonce} -> {post_nonce}"
                        ),
                    )
                )

    accepted = Counter(
        tx.sender for tx in _accepted_txs(txs, result) if tx.sender is not None
    )
    for sender, count in accepted.items():
        pre_nonce = nonce_of(pre_alloc, sender) or 0
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


def _check_changes(
    address: "Address",
    field: str,
    pre_value: object,
    post_value: object,
    recorded: Sequence[object],
) -> List[InvariantViolation]:
    """Check one field's recorded post-values against its pre and post."""
    if not recorded:
        if pre_value == post_value:
            return []
        return [
            InvariantViolation(
                invariant="bal_state_diff",
                message=f"{address} {field} changed but the BAL has no entry",
            )
        ]
    violations = []
    if recorded[-1] != post_value:
        violations.append(
            InvariantViolation(
                invariant="bal_state_diff",
                message=(
                    f"{address} {field} last BAL value {recorded[-1]!r} "
                    f"!= post-state {post_value!r}"
                ),
            )
        )
    previous = pre_value
    for value in recorded:
        if value == previous:
            violations.append(
                InvariantViolation(
                    invariant="bal_state_diff",
                    message=(
                        f"{address} {field} BAL records a no-op change "
                        f"to {value!r}"
                    ),
                )
            )
        previous = value
    return violations


def check_bal_against_state_diff(
    pre_alloc: "Alloc",
    post_alloc: "Alloc",
    block_access_list: Optional["BlockAccessList"],
) -> List[InvariantViolation]:
    """
    Check the block access list against the block's pre/post state diff.

    Every changed balance, nonce, code or storage value has an entry, the
    entry at the last index equals the post-state, and no entry repeats
    the value before it. Storage is skipped for an account that starts
    with storage but no code and no nonce: creating over it or deleting it
    wipes the storage, which the BAL has no way to record.
    """
    if block_access_list is None:
        return []
    entries = {entry.address: entry for entry in block_access_list.root}
    violations: List[InvariantViolation] = []
    addresses = pre_alloc.root.keys() | post_alloc.root.keys() | entries.keys()
    for address in addresses:
        pre = pre_alloc.root.get(address) or Account()
        post = post_alloc.root.get(address) or Account()
        entry = entries.get(address) or BalAccountChange(address=address)

        # Each field maps to (pre value, post value, recorded post-values).
        fields: Dict[str, Tuple[object, object, Sequence[object]]] = {
            "balance": (
                int(pre.balance),
                int(post.balance),
                [int(c.post_balance) for c in entry.balance_changes],
            ),
            "nonce": (
                int(pre.nonce),
                int(post.nonce),
                [int(c.post_nonce) for c in entry.nonce_changes],
            ),
            "code": (
                bytes(pre.code),
                bytes(post.code),
                [bytes(c.new_code) for c in entry.code_changes],
            ),
        }
        pre_storage = {int(k): int(v) for k, v in pre.storage.root.items()}
        post_storage = {int(k): int(v) for k, v in post.storage.root.items()}
        recorded_storage = {
            int(slot.slot): [int(c.post_value) for c in slot.slot_changes]
            for slot in entry.storage_changes
        }
        storage_only = (
            any(pre_storage.values()) and not pre.code and pre.nonce == 0
        )
        if not storage_only:
            for slot in (
                pre_storage.keys()
                | post_storage.keys()
                | recorded_storage.keys()
            ):
                fields[f"storage[{slot:#x}]"] = (
                    pre_storage.get(slot, 0),
                    post_storage.get(slot, 0),
                    recorded_storage.get(slot, []),
                )

        for field, (pre_value, post_value, recorded) in fields.items():
            violations += _check_changes(
                address, field, pre_value, post_value, recorded
            )
    return violations


def check_bal_access_witness(
    witness: Optional["BalWitness"],
    block_access_list: Optional["BlockAccessList"],
) -> List[InvariantViolation]:
    """
    Check the BAL's storage slots against the slots execution accessed.

    The witness comes from the trace stream, not from the state tracker
    that builds the BAL, so a slot the tracker dropped or invented shows
    up here. Only the EELS transition tool produces a witness.
    """
    if witness is None or block_access_list is None:
        return []
    from execution_testing.evm_tools.t8n.evm_trace.bal_witness import (
        bal_slots,
        check_bal_relation,
    )

    return [
        InvariantViolation(
            invariant="bal_access_witness",
            message=str(disagreement),
        )
        for disagreement in check_bal_relation(
            witness, bal_slots(block_access_list)
        )
    ]


def check_block_invariants(
    *,
    fork: Type["BaseFork"],
    pre_alloc: "Alloc",
    post_alloc: "Alloc",
    result: "Result",
    env: "Environment",
    txs: Sequence["Transaction"],
    reward: int,
    block_access_list: Optional["BlockAccessList"] = None,
    bal_witness: Optional["BalWitness"] = None,
) -> List[InvariantViolation]:
    """Run every block-level invariant check and warn on each violation."""
    violations = [
        *check_ether_conservation(
            fork, pre_alloc, post_alloc, result, env, txs, reward
        ),
        *check_gas_accounting(fork, result, env),
        *check_nonce_monotonicity(pre_alloc, post_alloc, txs, result),
        *check_bal_against_state_diff(
            pre_alloc, post_alloc, block_access_list
        ),
        *check_bal_access_witness(bal_witness, block_access_list),
    ]
    for violation in violations:
        warnings.warn(
            f"[{violation.invariant}] {violation.message}",
            InvariantViolationWarning,
            stacklevel=3,
        )
    return violations
