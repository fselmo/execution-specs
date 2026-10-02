"""
Transactions breaking one validity rule, of every type, witnessed on EELS.

Each test builds the rejected transaction the generator builds, fills it
after a valid transfer, and imports the fixture through EELS's own block
import, which must refuse the block with the exception the fixture names.
Where the rule is a gas threshold, one gas more must be accepted.
"""

import contextlib
import io
import warnings
from typing import Any, Dict, Optional

import pytest

from execution_testing.base_types import Address, Bytes, Hash, HexNumber
from execution_testing.forks import Amsterdam

from ..fuzzer_bridge import campaign as mod
from ..fuzzer_bridge.density import axis_collapse_warnings, axis_coverage
from ..fuzzer_bridge.eels_import import import_fixture
from ..fuzzer_bridge.generator import (
    TX_VALIDITY_KINDS,
    TX_VALIDITY_TYPES,
    tx_validity_transaction,
)
from ..fuzzer_bridge.models import FuzzerOutput, FuzzerTransactionInput
from .template import template_case

ONE_MORE_IS_VALID = {"above_total_cap": -1, "intrinsic_short": 1}
"""The kinds whose rule is a gas threshold, and the step that crosses it
back: one gas under the total cap, one gas over the intrinsic cost. The
floor's is `floor_short`'s own gas plus one, checked apart."""


def _case(kind: str, tx_type: int, gas_step: int = 0) -> FuzzerOutput:
    """A transfer, then a ``kind`` transaction of ``tx_type``."""
    case = template_case()
    (first, *_) = case.transactions
    sender = first.from_
    to = next(a for a in case.accounts if case.accounts[a].private_key)
    to = to if to != sender else Address(0x2B000)
    fields = tx_validity_transaction(
        Amsterdam, kind, tx_type, to, Hash(0x1234567), to_self=False
    )
    fields["gas"] = HexNumber(int(fields["gas"]) + gas_step)
    if gas_step:
        # Back across the threshold the transaction is valid: no rule is
        # broken, so none is switched off for the fill.
        fields["error"] = None
        fields["disabled_rule"] = None
    # The block's base fee is at most the genesis one, which an empty
    # parent can only lower.
    base_fee = int(case.env.base_fee_per_gas or 0)
    fees: Dict[str, Any] = (
        {"gas_price": HexNumber(2 * base_fee)}
        if tx_type in (0, 1)
        else {
            "max_fee_per_gas": HexNumber(2 * base_fee),
            "max_priority_fee_per_gas": HexNumber(1),
        }
    )
    common = {
        "authorization_list": None,
        "access_list": None,
        "gas_need_fraction": None,
        "block": 0,
    }
    transfer = first.model_copy(
        update={
            **common,
            "to": to,
            "gas": HexNumber(100_000),
            "nonce": HexNumber(0),
            "value": HexNumber(1),
            "data": Bytes(b""),
        }
    )
    invalid = FuzzerTransactionInput(
        **{"from": sender},
        nonce=HexNumber(1),
        **{**common, **fields, **fees},
    )
    env = case.env
    if kind == "above_total_cap":
        cap = Amsterdam.transaction_total_gas_limit_cap()
        assert cap is not None
        env = env.model_copy(update={"gas_limit": 2 * cap})
    return case.model_copy(
        update={
            "transactions": [transfer, invalid],
            "block_count": 1,
            "withdrawals": [],
            "env": env,
            "negative": None,
            "bal_cap_offset": None,
        }
    )


def _fill(case: FuzzerOutput) -> Dict[str, Any]:
    mod._init_fill_worker("Amsterdam")
    with contextlib.redirect_stdout(io.StringIO()):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return mod.fill_case(case, mod._FILL["fork"], mod._FILL["eels"])


@pytest.mark.parametrize("tx_type", TX_VALIDITY_TYPES)
@pytest.mark.parametrize("kind", TX_VALIDITY_KINDS)
def test_a_transaction_breaking_a_validity_rule_is_refused(
    kind: str, tx_type: int
) -> None:
    """
    The block ending in the transaction is refused by EELS's import with
    the exception the fixture names, and where the rule is a gas
    threshold, the same transaction one step back across it is valid.
    """
    fixture = _fill(_case(kind, tx_type))
    expected: Optional[str] = fixture["blocks"][-1].get("expectException")
    assert expected is not None and "TransactionException" in expected
    result = import_fixture(fixture, "amsterdam")
    assert result.agreed, result.reason
    step = ONE_MORE_IS_VALID.get(kind)
    if kind == "floor_short":
        step = 1
    if step is not None:
        valid = _fill(_case(kind, tx_type, gas_step=step))
        assert "expectException" not in valid["blocks"][-1]
        assert import_fixture(valid, "amsterdam").agreed


def _accepted(fixture: Dict[str, Any]) -> Dict[str, Any]:
    """``fixture`` with its last block expected valid."""
    last = {
        k: v
        for k, v in fixture["blocks"][-1].items()
        if k != "expectException"
    }
    return {**fixture, "blocks": [*fixture["blocks"][:-1], last]}


@pytest.mark.parametrize("tx_type", TX_VALIDITY_TYPES)
@pytest.mark.parametrize(
    "kind,rule",
    [
        pytest.param("above_total_cap", "total_cap", id="total_cap"),
        pytest.param("floor_short", "floor", id="floor_short"),
        pytest.param("floor_above_cap", "floor", id="floor_above_cap"),
    ],
)
def test_a_rule_negative_is_the_block_where_the_transaction_executed(
    kind: str, rule: str, tx_type: int
) -> None:
    """
    Filled with its rule switched off, the block is the one where the
    transaction executed: EELS with the rule off imports it as valid, as
    a client lacking the rule would, and EELS with the rule on refuses it
    with exactly the rule's exception, so only the rule can reject it.
    """
    from ..fuzzer_bridge.disabled_rules import rules_disabled

    case = _case(kind, tx_type)
    (invalid,) = [tx for tx in case.transactions if tx.error]
    assert invalid.disabled_rule == rule
    fixture = _fill(case)
    assert "expectException" in fixture["blocks"][-1]
    result = import_fixture(fixture, "amsterdam")
    assert result.agreed, result.reason
    with rules_disabled("amsterdam", [rule]):
        lagging = import_fixture(_accepted(fixture), "amsterdam")
    assert lagging.agreed, lagging.reason
    assert not import_fixture(_accepted(fixture), "amsterdam").agreed


def test_an_intrinsic_shortfall_is_filled_with_its_rule_on() -> None:
    """
    Gas below the intrinsic cost leaves nothing to execute, so that case
    keeps its rule on: the block is filled without the transaction.
    """
    case = _case("intrinsic_short", 2)
    (invalid,) = [tx for tx in case.transactions if tx.error]
    assert invalid.disabled_rule is None
    assert import_fixture(_fill(case), "amsterdam").agreed


def test_every_tx_validity_axis_keeps_all_its_values() -> None:
    """Presence, every rule and every transaction type stay drawn."""
    coverage = axis_coverage(Amsterdam, range(0, 800))
    warnings_ = [
        w
        for w in axis_collapse_warnings(coverage)
        if w.startswith("tx_validity")
    ]
    assert warnings_ == []
