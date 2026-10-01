"""
Requests queued through their system contracts, witnessed by the header.

A deposit, withdrawal request, consolidation, builder deposit or builder
exit reaches the block's requests hash only if its system contract took
it. Each test sends a real generated case's transaction to the contract
and reads the outcome from the fixture's receipt and requests hash.
"""

import contextlib
import io
import warnings
from typing import Any, Dict, Tuple

import pytest

from execution_testing.base_types import Bytes, HexNumber
from execution_testing.forks import Amsterdam

from ..fuzzer_bridge import campaign as mod
from ..fuzzer_bridge.density import axis_collapse_warnings, axis_coverage
from ..fuzzer_bridge.generator import (
    REQUEST_TX_GAS,
    request_call,
)
from .template import template_case

EMPTY_REQUESTS_HASH = (
    "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)
"""The requests hash of a block with no requests: SHA-256 of nothing."""


def _request(kind: int, valid: bool) -> Tuple[Dict[str, Any], Any]:
    """
    Fill one transaction sending a request of ``kind``; return the block
    and the sender.
    """
    case = template_case()
    to, value, data = request_call(Amsterdam, kind, 7, valid)
    (first, *_) = case.transactions
    tx = first.model_copy(
        update={
            "to": to,
            "gas": HexNumber(REQUEST_TX_GAS),
            "data": Bytes(data),
            "value": HexNumber(value),
            "authorization_list": None,
            "gas_need_fraction": None,
            "block": 0,
        }
    )
    mod._init_fill_worker("Amsterdam")
    fork, eels = mod._FILL["fork"], mod._FILL["eels"]
    with contextlib.redirect_stdout(io.StringIO()):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            fixture = mod.fill_case(
                case.model_copy(
                    update={
                        "transactions": [tx],
                        "block_count": 1,
                        "withdrawals": [],
                    }
                ),
                fork,
                eels,
            )
    (block,) = fixture["blocks"]
    return block, first.from_


KINDS = [
    pytest.param(c.type, id=c.__name__)
    for c in Amsterdam.system_contract_request_types()
]


@pytest.mark.parametrize("kind", KINDS)
def test_a_request_its_contract_takes_reaches_the_requests_hash(
    kind: int,
) -> None:
    """
    The call succeeds and the block's requests hash is the hash of exactly
    this request, as the framework serializes it with its sender.
    """
    from execution_testing.forks.requests import Requests

    block, sender = _request(kind, valid=True)
    (receipt,) = block["receipts"]
    assert receipt["status"]
    (cls,) = [
        c for c in Amsterdam.system_contract_request_types() if c.type == kind
    ]
    request = cls.from_index(7).with_source_address(sender)
    if "index" in type(request).model_fields:
        # A deposit records the contract's count before it: the first.
        request = request.model_copy(update={"index": 0})
    expected = Bytes(bytes(Requests(request))).hex()
    assert block["blockHeader"]["requestsHash"] == expected


@pytest.mark.parametrize("kind", KINDS)
def test_a_request_short_of_its_price_is_refused(kind: int) -> None:
    """
    The near miss: no fee, or a deposit a wei off a whole gwei, and the
    contract reverts; the block carries no request.
    """
    block, _ = _request(kind, valid=False)
    (receipt,) = block["receipts"]
    assert not receipt["status"]
    assert block["blockHeader"]["requestsHash"] == EMPTY_REQUESTS_HASH


def test_every_request_axis_keeps_all_its_values() -> None:
    """Presence, every request type and both validities stay drawn."""
    coverage = axis_coverage(Amsterdam, range(0, 400))
    warnings_ = [
        w for w in axis_collapse_warnings(coverage) if w.startswith("request")
    ]
    assert warnings_ == []
