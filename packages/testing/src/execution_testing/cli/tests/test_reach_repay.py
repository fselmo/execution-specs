"""
The EIP-8037 repayment at a successful child's merge (#3478), deciding a
post state.

The repayer spills a fresh store's state charge into execution gas, then
delegate-calls a restorer that undoes the store, crediting the child's
reservoir. Each test fills one transaction to it twice, with the spec's
repayment and with it switched off, and reads the gas the repayer stored
after the merge.
"""

import contextlib
import importlib
import io
import warnings
from typing import Tuple

import pytest

from execution_testing.base_types import Address, Bytes, HexNumber
from execution_testing.forks import Amsterdam
from execution_testing.vm import Opcodes as Op

from ..fuzzer_bridge import campaign as mod
from ..fuzzer_bridge.density import axis_collapse_warnings, axis_coverage
from ..fuzzer_bridge.generator import (
    REPAY_TX_GAS,
    REPAYER_ADDRESS,
    RESTORER_ADDRESS,
    REVERTING_RESTORER_ADDRESS,
)
from ..fuzzer_bridge.models import FuzzerOutput
from .template import template_case

REPAYER = Address(REPAYER_ADDRESS)
WITNESS_SLOT = 2**129 + 1
"""Where the repayer's first call stores its call's result and gas."""


def _case(restorer: int) -> FuzzerOutput:
    """One transaction to the repayer, delegate-calling ``restorer``."""
    case = template_case()
    (first, *_) = case.transactions
    tx = first.model_copy(
        update={
            "to": REPAYER,
            "gas": HexNumber(REPAY_TX_GAS),
            "data": Bytes(restorer.to_bytes(32, "big")),
            "value": HexNumber(0),
            "authorization_list": None,
            "access_list": None,
            "gas_need_fraction": None,
            "block": 0,
        }
    )
    return case.model_copy(
        update={"transactions": [tx], "block_count": 1, "withdrawals": []}
    )


def _witness(case: FuzzerOutput) -> Tuple[int, int]:
    """The restorer call's result and the gas left after its merge."""
    mod._init_fill_worker("Amsterdam")
    with contextlib.redirect_stdout(io.StringIO()):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            fixture = mod.fill_case(case, mod._FILL["fork"], mod._FILL["eels"])
    (block,) = fixture["blocks"]
    (entry,) = [
        e for e in block["blockAccessList"] if Address(e["address"]) == REPAYER
    ]
    (stored,) = [
        int(s["slotChanges"][-1]["postValue"], 16)
        for s in entry["storageChanges"]
        if int(s["slot"], 16) == WITNESS_SLOT
    ]
    return stored >> 128, stored & (2**128 - 1)


@pytest.mark.parametrize(
    "restorer,succeeded,repaid",
    [
        pytest.param(RESTORER_ADDRESS, 1, True, id="child_succeeds"),
        pytest.param(REVERTING_RESTORER_ADDRESS, 0, False, id="child_reverts"),
    ],
)
def test_the_repayment_reaches_the_state_root(
    monkeypatch: pytest.MonkeyPatch,
    restorer: int,
    succeeded: int,
    repaid: bool,
) -> None:
    """
    A child that succeeds after crediting its reservoir repays the
    parent's spill at the merge: the parent stores exactly one fresh
    store's state cost more gas than it does with the repayment switched
    off. A child that reverts repays nothing, so switching it off changes
    nothing.
    """
    case = _case(restorer)
    with_repayment = _witness(case)
    vm = importlib.import_module("ethereum.forks.amsterdam.vm")
    monkeypatch.setattr(vm, "repay_state_gas_spill", lambda _meter: None)
    without = _witness(case)
    assert with_repayment[0] == without[0] == succeeded
    store_state = Op.SSTORE(
        key_warm=False, original_value=0, new_value=1
    ).state_cost(Amsterdam)
    expected = store_state if repaid else 0
    assert with_repayment[1] - without[1] == expected


def test_every_repay_axis_keeps_all_its_values() -> None:
    """Presence, and a restorer that succeeds and one that reverts."""
    coverage = axis_coverage(Amsterdam, range(0, 800))
    warnings_ = [
        w for w in axis_collapse_warnings(coverage) if w.startswith("repay")
    ]
    assert warnings_ == []
