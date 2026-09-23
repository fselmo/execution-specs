"""
Withdrawals in the generated block, witnessed by their effect.

Each test fills a real case with a chosen withdrawal and reads the effect
the shape claims from the fixture itself -- the post-state balance, the
block access list the header commits to -- and only then checks that the
BAL observer names the same cell. The observer and the fixture are
different measures, so their agreement means something; the observer
agreeing with the derivation did not, the one time both were measuring a
recorder's capability.
"""

import contextlib
import io
import warnings
from typing import Any, Dict, Tuple

from execution_testing.base_types import Address, HexNumber
from execution_testing.forks import Amsterdam

from ..fuzzer_bridge import campaign as mod
from ..fuzzer_bridge.bal_reach import observer_spec
from ..fuzzer_bridge.density import axis_collapse_warnings, axis_coverage
from ..fuzzer_bridge.generator import (
    WITHDRAWAL_RECIPIENT_BASE,
    generate_fuzzer_output,
)
from ..fuzzer_bridge.models import FuzzerWithdrawalInput

GWEI = 10**9


def _fill_with(recipient: Address, amount: int) -> Tuple[Dict, Any]:
    """Fill a generated case whose block carries one chosen withdrawal."""
    mod._init_fill_worker("Amsterdam")
    fork, eels = mod._FILL["fork"], mod._FILL["eels"]
    eels.bal_reach = observer_spec(fork)
    eels.last_bal_observation = None
    case = generate_fuzzer_output(fork, 0).model_copy(
        update={
            "withdrawals": [
                FuzzerWithdrawalInput(
                    index=HexNumber(0),
                    validator_index=HexNumber(1),
                    address=recipient,
                    amount=HexNumber(amount),
                )
            ]
        }
    )
    with contextlib.redirect_stdout(io.StringIO()):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            fixture = mod.fill_case(case, fork, eels)
    return fixture, eels.last_bal_observation


def _bal_entry(fixture: Dict, address: Address) -> Dict:
    wanted = str(address).lower()
    (block,) = fixture["blocks"]
    return next(
        entry
        for entry in block["blockAccessList"]
        if entry["address"].lower() == wanted
    )


def _post_index(fixture: Dict) -> int:
    """The block access index withdrawals land at: after every tx."""
    (block,) = fixture["blocks"]
    return len(block["transactions"]) + 1


def test_a_withdrawal_credits_an_untouched_address_in_gwei() -> None:
    """
    The positive: the recipient's post-state balance is the amount in
    Gwei, and the list records one balance change at the post-execution
    index. The observer must then name `process_withdrawals` for it.
    """
    recipient = Address(WITHDRAWAL_RECIPIENT_BASE)
    fixture, observation = _fill_with(recipient, 3)

    post = {k.lower(): v for k, v in fixture["postState"].items()}
    assert int(post[str(recipient).lower()]["balance"], 16) == 3 * GWEI
    changes = _bal_entry(fixture, recipient)["balanceChanges"]
    assert [int(c["blockAccessIndex"], 16) for c in changes] == [
        _post_index(fixture)
    ]
    assert int(changes[0]["postBalance"], 16) == 3 * GWEI

    assert (
        "fork.process_withdrawals",
        "balance_change",
        "success",
    ) in observation.cells


def test_a_zero_withdrawal_is_touched_and_leaves_no_account() -> None:
    """
    The near-miss: a zero withdrawal to an address with no account
    touches it without changing it. The list must still carry the address
    with nothing changed, the empty account must not survive into the
    post-state, and the observer must not claim a balance change.
    """
    recipient = Address(WITHDRAWAL_RECIPIENT_BASE)
    fixture, observation = _fill_with(recipient, 0)

    post = {k.lower() for k in fixture["postState"]}
    assert str(recipient).lower() not in post
    entry = _bal_entry(fixture, recipient)
    for field in (
        "balanceChanges",
        "nonceChanges",
        "codeChanges",
        "storageChanges",
        "storageReads",
    ):
        assert entry[field] == []

    withdrawal_kinds = {
        kind
        for reason, kind, _ in observation.cells
        if reason == "fork.process_withdrawals"
    }
    assert withdrawal_kinds == {"touched_account"}


def test_a_withdrawal_to_a_request_contract_aliases_at_its_own_index() -> None:
    """
    Withdrawals share their index with the post-block request calls, so a
    system contract those calls run is entered twice at one index: the
    withdrawal's balance change and the request call's storage access.
    Which contracts run then is the fork's business, so every one it
    lists is tried, and each one the observer reports as aliased must show
    both effects in the list.
    """
    pair = (
        "fork.process_checked_system_transaction",
        "fork.process_withdrawals",
    )
    aliased = 0
    for contract in Amsterdam.system_contracts():
        fixture, observation = _fill_with(Address(contract), 5)
        if pair not in observation.aliases:
            continue
        aliased += 1
        entry = _bal_entry(fixture, Address(contract))
        indices = {
            int(change["blockAccessIndex"], 16)
            for change in entry["balanceChanges"]
        }
        assert _post_index(fixture) in indices
        assert entry["storageReads"] or entry["storageChanges"]
    assert aliased, "no system contract aliased with a withdrawal"


def test_every_withdrawal_axis_keeps_all_its_values() -> None:
    """Presence, recipient and amount each stay above the collapse floor."""
    coverage = axis_coverage(Amsterdam, range(0, 400))
    warnings_ = [
        w
        for w in axis_collapse_warnings(coverage)
        if w.startswith("withdrawal")
    ]
    assert warnings_ == []
