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

from ..fuzzer_bridge import campaign as mod
from ..fuzzer_bridge.density import axis_collapse_warnings, axis_coverage
from ..fuzzer_bridge.generator import (
    EXACT_CHARGE_CHILD_ADDRESS,
    EXACT_CHARGE_TX_GAS,
    EXACT_CHARGER_ADDRESS,
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


def test_every_exact_charge_axis_keeps_all_its_values() -> None:
    """Presence and every margin, the exact one above all, stay drawn."""
    coverage = axis_coverage(Amsterdam, range(0, 400))
    warnings_ = [
        w
        for w in axis_collapse_warnings(coverage)
        if w.startswith("exact_charge")
    ]
    assert warnings_ == []
