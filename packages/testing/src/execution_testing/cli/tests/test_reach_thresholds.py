"""
Charges that land exactly on a limit, witnessed by their effect.

A limit is checked by a comparison, and `>=` and `>` part ways only on
the one input equal to the limit. Each test sends a real generated case's
transaction to a helper built to hit that input, or miss it by one, and
reads the outcome from the fixture rather than from the draw.
"""

import contextlib
import io
import warnings
from typing import Any, Dict

import pytest

from execution_testing.base_types import Address, Bytes, HexNumber
from execution_testing.forks import Amsterdam
from execution_testing.vm import Opcodes as Op

from ..fuzzer_bridge import campaign as mod
from ..fuzzer_bridge.density import axis_collapse_warnings, axis_coverage
from ..fuzzer_bridge.generator import (
    EXACT_CHARGE_CHILD_ADDRESS,
    EXACT_CHARGE_TX_GAS,
    EXACT_CHARGER_ADDRESS,
    REJECTED_BY_STATE_GAS,
    STATE_FILLER_ADDRESS,
    exact_charge_child_code,
    generate_fuzzer_output,
)
from ..fuzzer_bridge.models import FuzzerOutput

CHARGER = Address(EXACT_CHARGER_ADDRESS)
CHILD = Address(EXACT_CHARGE_CHILD_ADDRESS)


def _fill(case: FuzzerOutput) -> Dict[str, Any]:
    mod._init_fill_worker("Amsterdam")
    fork, eels = mod._FILL["fork"], mod._FILL["eels"]
    with contextlib.redirect_stdout(io.StringIO()):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return mod.fill_case(case, fork, eels)


def _entry(fixture: Dict[str, Any], address: Address) -> Dict[str, Any]:
    (block,) = fixture["blocks"]
    return next(
        entry
        for entry in block["blockAccessList"]
        if entry["address"].lower() == str(address).lower()
    )


def _charge(margin: int) -> FuzzerOutput:
    """One transaction to the charger, its child given need + margin."""
    case = generate_fuzzer_output(Amsterdam, 0)
    child_gas = exact_charge_child_code().gas_cost(Amsterdam) + margin
    (first, *_) = case.transactions
    tx = first.model_copy(
        update={
            "to": CHARGER,
            "gas": HexNumber(EXACT_CHARGE_TX_GAS),
            "data": Bytes(child_gas.to_bytes(32, "big")),
            "value": HexNumber(0),
            "authorization_list": None,
            "gas_need_fraction": None,
            "block": 0,
        }
    )
    return case.model_copy(
        update={"transactions": [tx], "block_count": 1, "withdrawals": []}
    )


@pytest.mark.parametrize(
    "margin,stored",
    [
        pytest.param(0, True, id="exact"),
        pytest.param(-1, False, id="one_short"),
        pytest.param(1, True, id="one_over"),
    ],
)
def test_a_state_charge_equal_to_the_gas_left_is_paid(
    margin: int, stored: bool
) -> None:
    """
    The child's store leaves exactly its state cost after its execution
    cost; that charge is paid from execution gas and the slot is written.
    One gas less and the child runs out on the charge; one more and it is
    paid with gas to spare. The charger records the call's result plus
    one, so the parent's slot says which.
    """
    fixture = _fill(_charge(margin))
    (block,) = fixture["blocks"]
    (receipt,) = block["receipts"]
    assert receipt["status"]
    child = _entry(fixture, CHILD)
    charger = _entry(fixture, CHARGER)
    witness = {
        int(change["slot"], 16): int(
            change["slotChanges"][-1]["postValue"], 16
        )
        for change in charger["storageChanges"]
    }
    if stored:
        assert [int(c["slot"], 16) for c in child["storageChanges"]] == [1]
        assert witness == {0: 1, 1: 2}
    else:
        assert child["storageChanges"] == []
        assert [int(s, 16) for s in child["storageReads"]] == [1]
        assert witness == {0: 1, 1: 1}


def _near_full(margin: int, stores: int = 150) -> FuzzerOutput:
    """
    A block of a filler making ``stores`` fresh stores from its reservoir,
    then a transfer asking the block's state gas left plus ``margin``.
    """
    case = generate_fuzzer_output(Amsterdam, 0)
    cap = Amsterdam.transaction_gas_limit_cap()
    assert cap is not None
    store = Op.SSTORE(key_warm=False, original_value=0, new_value=1)
    state_used = stores * store.state_cost(Amsterdam)
    limit = int(case.env.gas_limit)
    (first, *_) = case.transactions
    sender = first.from_
    fields = {
        "value": HexNumber(0),
        "authorization_list": None,
        "gas_need_fraction": None,
        "block": 0,
    }
    filler = first.model_copy(
        update={
            **fields,
            "to": Address(STATE_FILLER_ADDRESS),
            "gas": HexNumber(cap + state_used),
            "nonce": HexNumber(0),
            "data": Bytes(stores.to_bytes(32, "big")),
        }
    )
    last = first.model_copy(
        update={
            **fields,
            "to": sender,
            "gas": HexNumber(limit - state_used + margin),
            "nonce": HexNumber(1),
            "data": Bytes(b""),
            "error": REJECTED_BY_STATE_GAS if margin > 0 else None,
        }
    )
    return case.model_copy(
        update={
            "transactions": [filler, last],
            "block_count": 1,
            "withdrawals": [],
        }
    )


def test_asking_exactly_the_state_gas_left_fits_the_block() -> None:
    """
    After the filler, a transaction whose gas is exactly the block's state
    gas left passes the capacity check and is included; the filler's
    stores are all changes.
    """
    fixture = _fill(_near_full(0))
    (block,) = fixture["blocks"]
    assert "expectException" not in block
    first, last = block["receipts"]
    assert first["status"] and last["status"]
    filler = _entry(fixture, Address(STATE_FILLER_ADDRESS))
    assert len(filler["storageChanges"]) == 150


def test_asking_one_more_than_the_state_gas_left_is_rejected() -> None:
    """The near miss: one more gas and the block is invalid."""
    fixture = _fill(_near_full(1))
    (block,) = fixture["blocks"]
    assert block["expectException"] == (
        f"TransactionException.{REJECTED_BY_STATE_GAS}"
    )


def test_every_exact_charge_axis_keeps_all_its_values() -> None:
    """Presence and every margin, the exact one above all, stay drawn."""
    coverage = axis_coverage(Amsterdam, range(0, 400))
    warnings_ = [
        w
        for w in axis_collapse_warnings(coverage)
        if w.startswith("exact_charge")
    ]
    assert warnings_ == []


def test_every_near_full_axis_keeps_all_its_values() -> None:
    """Presence, both filler sizes and both margins stay drawn."""
    coverage = axis_coverage(Amsterdam, range(0, 400))
    warnings_ = [
        w
        for w in axis_collapse_warnings(coverage)
        if w.startswith("near_full")
    ]
    assert warnings_ == []


def _max_nonce_case(nonces: "list[int]") -> FuzzerOutput:
    """A block of transfers, one from a fresh account at each nonce."""
    from execution_testing.test_types.account_types import EOA

    from ..fuzzer_bridge.generator import MAX_NONCE
    from ..fuzzer_bridge.models import FuzzerAccountInput

    case = generate_fuzzer_output(Amsterdam, 0)
    accounts = dict(case.accounts)
    (first, *_) = case.transactions
    transactions = []
    for i, nonce in enumerate(nonces):
        key = 0x1000 + i
        sender = Address(EOA(key=key))
        accounts[sender] = FuzzerAccountInput(
            balance=HexNumber(10**20),
            nonce=HexNumber(nonce),
            private_key=key,
        )
        transactions.append(
            first.model_copy(
                update={
                    "from_": sender,
                    "to": first.from_,
                    "gas": HexNumber(100_000),
                    "nonce": HexNumber(nonce),
                    "value": HexNumber(1),
                    "data": Bytes(b""),
                    "authorization_list": None,
                    "gas_need_fraction": None,
                    "block": 0,
                    "error": "NONCE_IS_MAX" if nonce == MAX_NONCE else None,
                }
            )
        )
    return case.model_copy(
        update={
            "accounts": accounts,
            "transactions": transactions,
            "block_count": 1,
            "withdrawals": [],
        }
    )


def test_one_below_the_highest_nonce_sends_and_reaches_it() -> None:
    """
    An account one below the highest nonce sends; its nonce is then the
    highest.
    """
    from ..fuzzer_bridge.generator import MAX_NONCE

    fixture = _fill(_max_nonce_case([MAX_NONCE - 1]))
    (block,) = fixture["blocks"]
    (receipt,) = block["receipts"]
    assert receipt["status"]
    nonces = [
        int(change["postNonce"], 16)
        for entry in block["blockAccessList"]
        for change in entry["nonceChanges"]
    ]
    assert nonces == [MAX_NONCE]


def test_an_account_at_the_highest_nonce_cannot_send() -> None:
    """The near miss: one more and the transaction is rejected."""
    from ..fuzzer_bridge.generator import MAX_NONCE

    fixture = _fill(_max_nonce_case([MAX_NONCE - 1, MAX_NONCE]))
    (block,) = fixture["blocks"]
    assert block["expectException"] == "TransactionException.NONCE_IS_MAX"


@pytest.mark.parametrize(
    "kind,deploys",
    [
        pytest.param("near_max_nonce", True, id="one_below_the_highest"),
        pytest.param("max_nonce", False, id="at_the_highest"),
    ],
)
def test_a_creator_at_the_highest_nonce_cannot_create(
    kind: str, deploys: bool
) -> None:
    """
    A creator one below the highest nonce deploys, and is then at it; one
    at the highest nonce pushes zero and keeps its nonce.
    """
    from ..fuzzer_bridge.generator import (
        DEPLOYER_ADDRESSES,
        DEPLOYER_TX_GAS,
        MAX_NONCE,
        deployer_initcode,
    )

    creator = Address(DEPLOYER_ADDRESSES[kind])
    case = generate_fuzzer_output(Amsterdam, 0)
    (first, *_) = case.transactions
    tx = first.model_copy(
        update={
            "to": creator,
            "gas": HexNumber(DEPLOYER_TX_GAS),
            "data": Bytes(deployer_initcode(1, 1)),
            "value": HexNumber(0),
            "authorization_list": None,
            "gas_need_fraction": None,
            "block": 0,
        }
    )
    fixture = _fill(
        case.model_copy(
            update={"transactions": [tx], "block_count": 1, "withdrawals": []}
        )
    )
    entry = _entry(fixture, creator)
    stored = {
        int(c["slot"], 16): int(c["slotChanges"][-1]["postValue"], 16)
        for c in entry["storageChanges"]
    }
    nonces = [int(c["postNonce"], 16) for c in entry["nonceChanges"]]
    if deploys:
        assert stored[1] != 0
        assert nonces == [MAX_NONCE]
    else:
        assert stored.get(1, 0) == 0
        assert nonces == []


def test_every_max_nonce_axis_keeps_all_its_values() -> None:
    """Presence, one below alone, and with the rejection stay drawn."""
    coverage = axis_coverage(Amsterdam, range(0, 400))
    warnings_ = [
        w
        for w in axis_collapse_warnings(coverage)
        if w.startswith("max_nonce")
    ]
    assert warnings_ == []
