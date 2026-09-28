"""
A SELFDESTRUCT that funds a dead account, witnessed by its gas.

Sending a non-zero balance to an account that is not alive creates it:
the SELFDESTRUCT pays the account-write surcharge in execution gas and
the new account in state gas. Each test sends a real generated case's
transaction to the graver and reads what it paid from the receipt.
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
    DEAD_BENEFICIARY_BASE,
    EMPTY_BENEFICIARY_ADDRESS,
    GRAVER_ADDRESS,
    GRAVER_TX_GAS,
    generate_fuzzer_output,
)
from ..fuzzer_bridge.models import FuzzerOutput

GRAVER = Address(GRAVER_ADDRESS)
NONEXISTENT = Address(DEAD_BENEFICIARY_BASE)
EMPTY = Address(EMPTY_BENEFICIARY_ADDRESS)
ALIVE = Address(0xA11CE)


def _fill(case: FuzzerOutput) -> Dict[str, Any]:
    mod._init_fill_worker("Amsterdam")
    fork, eels = mod._FILL["fork"], mod._FILL["eels"]
    with contextlib.redirect_stdout(io.StringIO()):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return mod.fill_case(case, fork, eels)


def _destruct(beneficiary: Address, value: int) -> FuzzerOutput:
    """One transaction to the graver, paying ``value`` to ``beneficiary``."""
    case = generate_fuzzer_output(Amsterdam, 0)
    accounts = dict(case.accounts)
    # A funded account with no code: alive, cold, and nobody's sender.
    alive = accounts[next(iter(accounts))].model_copy(
        update={"private_key": None, "nonce": HexNumber(0)}
    )
    accounts[ALIVE] = alive
    (first, *_) = case.transactions
    tx = first.model_copy(
        update={
            "to": GRAVER,
            "gas": HexNumber(GRAVER_TX_GAS),
            "data": Bytes(bytes(beneficiary).rjust(32, b"\0")),
            "value": HexNumber(value),
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


def _value_cost() -> int:
    """What sending a value adds to the intrinsic cost, whoever is paid."""
    intrinsic = Amsterdam.transaction_intrinsic_cost_calculator()
    data = bytes(NONEXISTENT).rjust(32, b"\0")
    return intrinsic(
        calldata=data,
        sends_value=True,
        return_cost_deducted_prior_execution=True,
    ) - intrinsic(calldata=data, return_cost_deducted_prior_execution=True)


def _gas_used(fixture: Dict[str, Any]) -> int:
    (block,) = fixture["blocks"]
    (receipt,) = block["receipts"]
    assert receipt["status"]
    return int(receipt["cumulativeGasUsed"], 16)


@pytest.mark.parametrize(
    "beneficiary",
    [
        pytest.param(NONEXISTENT, id="nonexistent"),
        pytest.param(EMPTY, id="empty"),
    ],
)
def test_funding_a_dead_beneficiary_pays_the_surcharge(
    beneficiary: Address,
) -> None:
    """
    A non-zero balance to a dead beneficiary costs the surcharge and the
    new account over the same SELFDESTRUCT with nothing to send, on top
    of what the transaction's value costs.
    """
    paid = _gas_used(_fill(_destruct(beneficiary, 1)))
    unpaid = _gas_used(_fill(_destruct(beneficiary, 0)))
    new = Op.SELFDESTRUCT(address_warm=False, account_new=True)
    old = Op.SELFDESTRUCT(address_warm=False, account_new=False)
    creation = new.gas_cost(Amsterdam) - old.gas_cost(Amsterdam)
    assert paid - unpaid == _value_cost() + creation


def test_funding_an_alive_beneficiary_pays_neither() -> None:
    """
    The near miss: paying an alive beneficiary costs only the value's
    intrinsic charge, the same as paying nobody would.
    """
    paid = _gas_used(_fill(_destruct(ALIVE, 1)))
    unpaid = _gas_used(_fill(_destruct(ALIVE, 0)))
    assert paid - unpaid == _value_cost()


def test_every_graver_axis_keeps_all_its_values() -> None:
    """Presence, every beneficiary kind and both values stay drawn."""
    coverage = axis_coverage(Amsterdam, range(0, 400))
    warnings_ = [
        w for w in axis_collapse_warnings(coverage) if w.startswith("graver")
    ]
    assert warnings_ == []
