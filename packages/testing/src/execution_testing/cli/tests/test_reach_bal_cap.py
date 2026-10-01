"""
Cases at the block access list's size cap (EIP-7928), witnessed on EELS.

A drawn case is one block of transfers whose gas limit is derived from
the items its list measures: at the cap it imports, one gas under it the
list holds one item too many and the block is refused.
"""

import contextlib
import io
import warnings
from typing import Any, Dict

import pytest

from execution_testing.forks import Amsterdam

from ..fuzzer_bridge import campaign as mod
from ..fuzzer_bridge.density import axis_collapse_warnings, axis_coverage
from ..fuzzer_bridge.eels_import import import_fixture
from ..fuzzer_bridge.generator import generate_fuzzer_output
from ..fuzzer_bridge.measured_gas import bal_items
from ..fuzzer_bridge.models import FuzzerOutput


def _cap_case() -> FuzzerOutput:
    """The first generated case drawn at the size cap."""
    for seed in range(1000):
        case = generate_fuzzer_output(Amsterdam, seed)
        if case.bal_cap_offset is not None:
            return case
    raise AssertionError("no generated case is drawn at the size cap")


def _fill(case: FuzzerOutput, offset: int) -> Dict[str, Any]:
    mod._init_fill_worker("Amsterdam")
    with contextlib.redirect_stdout(io.StringIO()):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return mod.fill_case(
                case.model_copy(update={"bal_cap_offset": offset}),
                mod._FILL["fork"],
                mod._FILL["eels"],
            )


def _gas_limit(fixture: Dict[str, Any]) -> int:
    block = fixture["blocks"][-1]
    header = block.get("blockHeader") or block["rlp_decoded"]["blockHeader"]
    return int(header["gasLimit"], 16)


def test_a_block_at_the_cap_imports_and_one_gas_under_is_refused() -> None:
    """
    The same block of transfers: with its gas limit at its list's items
    times their cost it imports; one gas less and EELS refuses it for
    the list's size, as the fixture expects.
    """
    case = _cap_case()
    at_cap = _fill(case, 0)
    over = _fill(case, -1)
    item = Amsterdam.gas_costs().BLOCK_ACCESS_LIST_ITEM
    assert "expectException" not in at_cap["blocks"][-1]
    assert _gas_limit(at_cap) == bal_items(at_cap) * item
    assert _gas_limit(over) == _gas_limit(at_cap) - 1
    assert over["blocks"][-1]["expectException"] == (
        "BlockException.BLOCK_ACCESS_LIST_GAS_LIMIT_EXCEEDED"
    )
    for fixture in (at_cap, over):
        result = import_fixture(fixture, "amsterdam")
        assert result.agreed, result.reason


@pytest.mark.parametrize("offset", [0, -1], ids=["at_cap", "over_cap"])
def test_a_cap_case_fills_on_the_engine_path(offset: int) -> None:
    """The engine payload carries the derived limit and the expectation."""
    from execution_testing.fixtures import BlockchainEngineFixture

    mod._init_fill_worker("Amsterdam")
    with contextlib.redirect_stdout(io.StringIO()):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            fixture = mod.fill_case(
                _cap_case().model_copy(update={"bal_cap_offset": offset}),
                mod._FILL["fork"],
                mod._FILL["eels"],
                fixture_format=BlockchainEngineFixture,
            )
    payload = fixture["engineNewPayloads"][-1]
    assert bool(payload.get("validationError")) == (offset < 0)
    result = import_fixture(fixture, "amsterdam")
    assert result.agreed, result.reason


def test_every_bal_cap_axis_keeps_all_its_values() -> None:
    """Presence, and both sides of the cap, stay drawn."""
    coverage = axis_coverage(Amsterdam, range(0, 800))
    warnings_ = [
        w for w in axis_collapse_warnings(coverage) if w.startswith("bal_cap")
    ]
    assert warnings_ == []
