"""
Transactions sent straight to an account holding a delegation.

The delegated code runs as the transaction's own, and reaching it costs
an account access: warm when the transaction's access list holds the
delegated address, cold otherwise. Each test sends a real generated
case's transaction to the delegated account and reads the cost from the
receipt.
"""

import contextlib
import io
import warnings
from typing import Any, Dict

from execution_testing.base_types import AccessList, Address, HexNumber
from execution_testing.forks import Amsterdam
from execution_testing.vm import Opcodes as Op

from ..fuzzer_bridge import campaign as mod
from ..fuzzer_bridge.density import axis_collapse_warnings, axis_coverage
from ..fuzzer_bridge.generator import (
    DELEGATED_ACCOUNT_ADDRESS,
)
from ..fuzzer_bridge.models import FuzzerAccountInput
from .template import template_case

DELEGATED = Address(DELEGATED_ACCOUNT_ADDRESS)
DELEGATE = Address(0xDE1E6A7E)


def _gas_used(warm: bool) -> int:
    """Send a value-free call to the delegated account; its gas used."""
    case = template_case()
    accounts = dict(case.accounts)
    accounts[DELEGATE] = FuzzerAccountInput(
        balance=HexNumber(0), nonce=HexNumber(1), code=bytes(Op.STOP)
    )
    accounts[DELEGATED] = accounts[DELEGATED].model_copy(
        update={"code": b"\xef\x01\x00" + bytes(DELEGATE)}
    )
    (first, *_) = case.transactions
    tx = first.model_copy(
        update={
            "to": DELEGATED,
            "gas": HexNumber(100_000),
            "data": b"",
            "value": HexNumber(0),
            "authorization_list": None,
            "gas_need_fraction": None,
            "access_list": (
                [AccessList(address=DELEGATE, storage_keys=[])]
                if warm
                else None
            ),
            "block": 0,
        }
    )
    mod._init_fill_worker("Amsterdam")
    fork, eels = mod._FILL["fork"], mod._FILL["eels"]
    with contextlib.redirect_stdout(io.StringIO()):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            fixture: Dict[str, Any] = mod.fill_case(
                case.model_copy(
                    update={
                        "accounts": accounts,
                        "transactions": [tx],
                        "block_count": 1,
                        "withdrawals": [],
                    }
                ),
                fork,
                eels,
            )
    (block,) = fixture["blocks"]
    (receipt,) = block["receipts"]
    assert receipt["status"]
    return int(receipt["cumulativeGasUsed"], 16)


def test_a_warm_delegate_costs_a_warm_access() -> None:
    """
    Listing the delegated address costs its access-list entry up front and
    saves the difference between a cold and a warm account access at the
    dispatch; the receipts differ by exactly that.
    """
    intrinsic = Amsterdam.transaction_intrinsic_cost_calculator()
    listed = intrinsic(
        access_list=[AccessList(address=DELEGATE, storage_keys=[])],
        return_cost_deducted_prior_execution=True,
    ) - intrinsic(return_cost_deducted_prior_execution=True)
    saved = Op.BALANCE.with_metadata(address_warm=False).gas_cost(
        Amsterdam
    ) - Op.BALANCE.with_metadata(address_warm=True).gas_cost(Amsterdam)
    assert _gas_used(warm=False) - _gas_used(warm=True) == saved - listed


def test_every_delegated_call_axis_keeps_all_its_values() -> None:
    """Presence, and warm and cold delegates, stay drawn."""
    coverage = axis_coverage(Amsterdam, range(0, 400))
    warnings_ = [
        w
        for w in axis_collapse_warnings(coverage)
        if w.startswith("delegated")
    ]
    assert warnings_ == []
