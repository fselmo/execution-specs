"""
Creation transactions, witnessed by what lands at their address.

A creation deploys to an address fixed by its sender and nonce. What the
pre-state already holds there decides the outcome: code or a nonce is a
collision and the creation fails; a bare balance is not, and the account
is taken over without a new-account charge. Each test sends a real
generated case's transaction as a creation and reads the result from the
fixture.
"""

import contextlib
import io
import warnings
from typing import Any, Dict, Optional

import pytest

from execution_testing.base_types import Address, Bytes, HexNumber
from execution_testing.forks import Amsterdam
from execution_testing.test_types import compute_create_address

from ..fuzzer_bridge import campaign as mod
from ..fuzzer_bridge.density import axis_collapse_warnings, axis_coverage
from ..fuzzer_bridge.generator import (
    CREATION_TX_GAS,
    creation_initcode,
    creation_target_account,
    generate_fuzzer_output,
)
from ..fuzzer_bridge.models import FuzzerOutput


def _fill(case: FuzzerOutput) -> Dict[str, Any]:
    mod._init_fill_worker("Amsterdam")
    fork, eels = mod._FILL["fork"], mod._FILL["eels"]
    with contextlib.redirect_stdout(io.StringIO()):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return mod.fill_case(case, fork, eels)


def _create(kind: str) -> "tuple[FuzzerOutput, Address]":
    """One creation transaction onto an address holding ``kind``."""
    case = generate_fuzzer_output(Amsterdam, 0)
    (first, *_) = case.transactions
    tx = first.model_copy(
        update={
            "to": None,
            "gas": HexNumber(CREATION_TX_GAS),
            "data": Bytes(creation_initcode()),
            "value": HexNumber(0),
            "nonce": HexNumber(0),
            "authorization_list": None,
            "gas_need_fraction": None,
            "block": 0,
        }
    )
    target = compute_create_address(address=tx.from_, nonce=0)
    accounts = dict(case.accounts)
    occupant = creation_target_account(kind)
    if occupant is not None:
        accounts[target] = occupant
    case = case.model_copy(
        update={
            "accounts": accounts,
            "transactions": [tx],
            "block_count": 1,
            "withdrawals": [],
        }
    )
    return case, target


def _outcome(
    fixture: Dict[str, Any], target: Address
) -> "tuple[bool, int, Optional[Dict]]":
    (block,) = fixture["blocks"]
    (receipt,) = block["receipts"]
    entry = next(
        (
            e
            for e in block["blockAccessList"]
            if e["address"].lower() == str(target).lower()
        ),
        None,
    )
    return receipt["status"], int(receipt["cumulativeGasUsed"], 16), entry


@pytest.mark.parametrize("kind", ["fresh", "balance_only"])
def test_a_creation_onto_a_deployable_address_deploys(kind: str) -> None:
    """The code and the initcode's write land at the address."""
    case, target = _create(kind)
    succeeded, _, entry = _outcome(_fill(case), target)
    assert succeeded
    assert entry is not None and len(entry["codeChanges"]) == 1
    assert [int(c["slot"], 16) for c in entry["storageChanges"]] == [0]


@pytest.mark.parametrize("kind", ["nonce", "code"])
def test_a_creation_onto_code_or_a_nonce_collides(kind: str) -> None:
    """
    The creation fails and consumes its gas; nothing is written at the
    address, which is only touched.
    """
    case, target = _create(kind)
    succeeded, gas_used, entry = _outcome(_fill(case), target)
    assert not succeeded
    assert gas_used == CREATION_TX_GAS
    assert entry is not None
    assert entry["codeChanges"] == [] and entry["storageChanges"] == []


def test_an_existing_balance_spares_the_new_account_charge() -> None:
    """
    The near miss of a collision: an address holding only a balance takes
    the code, and costs one new account's state gas less than a fresh one.
    """
    fresh, fresh_target = _create("fresh")
    held, held_target = _create("balance_only")
    _, fresh_gas, _ = _outcome(_fill(fresh), fresh_target)
    _, held_gas, _ = _outcome(_fill(held), held_target)
    new_account = Amsterdam.transaction_top_frame_state_gas(
        contract_creation=True
    )
    assert fresh_gas - held_gas == new_account


CREATOR = Address(0xC4EA7)


def _create_then_burn(initcode_size: int) -> FuzzerOutput:
    """
    A contract that creates from ``initcode_size`` bytes of zeros, stores
    GAS right after, then forwards all its gas to a call that burns it.
    """
    from execution_testing.fuzzing.strategies import _gas_after_create
    from execution_testing.vm import Opcodes as Op

    from ..fuzzer_bridge.generator import BURNER_ADDRESS
    from ..fuzzer_bridge.models import FuzzerAccountInput

    code = (
        Op.MSTORE(64, 0)  # memory already spans both sizes
        + Op.POP(Op.CREATE(0, 0, initcode_size))
        + _gas_after_create(0)
        + Op.POP(Op.CALL(Op.GAS, BURNER_ADDRESS, 0, 0, 0, 0, 0))
    )
    case = generate_fuzzer_output(Amsterdam, 0)
    accounts = dict(case.accounts)
    accounts[CREATOR] = FuzzerAccountInput(
        balance=HexNumber(0), nonce=HexNumber(1), code=Bytes(bytes(code))
    )
    (first, *_) = case.transactions
    tx = first.model_copy(
        update={
            "to": CREATOR,
            "gas": HexNumber(CREATION_TX_GAS),
            "data": Bytes(b""),
            "value": HexNumber(0),
            "authorization_list": None,
            "gas_need_fraction": None,
            "block": 0,
        }
    )
    return case.model_copy(
        update={
            "accounts": accounts,
            "transactions": [tx],
            "block_count": 1,
            "withdrawals": [],
        }
    )


def _stored_gas(fixture: Dict[str, Any]) -> int:
    (block,) = fixture["blocks"]
    entry = next(
        e
        for e in block["blockAccessList"]
        if e["address"].lower() == str(CREATOR).lower()
    )
    (slot,) = entry["storageChanges"]
    return int(slot["slotChanges"][-1]["postValue"], 16)


def test_gas_stored_after_a_creation_shows_its_initcode_charge() -> None:
    """
    The frame then forwards all its gas to a call that burns it, so the
    gas used cannot tell two initcode sizes apart; the gas stored right
    after the creation differs by exactly one more initcode word's cost.
    """
    from execution_testing.vm import Opcodes as Op

    one_word = _stored_gas(_fill(_create_then_burn(32)))
    two_words = _stored_gas(_fill(_create_then_burn(64)))
    word = Op.CREATE(init_code_size=64).gas_cost(Amsterdam) - Op.CREATE(
        init_code_size=32
    ).gas_cost(Amsterdam)
    assert word > 0
    assert one_word - two_words == word


def test_every_creation_axis_keeps_all_its_values() -> None:
    """Presence and every target kind stay drawn."""
    coverage = axis_coverage(Amsterdam, range(0, 400))
    warnings_ = [
        w for w in axis_collapse_warnings(coverage) if w.startswith("creation")
    ]
    assert warnings_ == []
