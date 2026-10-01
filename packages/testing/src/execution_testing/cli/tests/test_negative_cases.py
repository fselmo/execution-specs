"""
Negative cases: a filled block modified so every client must refuse it.

Each kind is witnessed on EELS: its engine fixture, imported as
`newPayload` receives it, must hash to its block hash and then be refused
with the exception it names. Each kind but the encodings, which a block's
RLP cannot carry, is also filled in the blockchain format, where the same
case unmodified imports and the two headers differ only where the kind
says.
"""

import contextlib
import io
import warnings
from typing import Any, Dict, Iterable, List, Optional, Type

import pytest

from execution_testing.fixtures import (
    BaseFixture,
    BlockchainEngineFixture,
    BlockchainFixture,
)
from execution_testing.forks import Amsterdam

from ..fuzzer_bridge import campaign as mod
from ..fuzzer_bridge.converter import blockchain_test_from_fuzzer
from ..fuzzer_bridge.density import axis_collapse_warnings, axis_coverage
from ..fuzzer_bridge.eels_import import import_fixture
from ..fuzzer_bridge.generator import generate_fuzzer_output
from ..fuzzer_bridge.measured_gas import measuring_filler, resolve_measured_gas
from ..fuzzer_bridge.models import FuzzerNegativeInput, FuzzerOutput
from ..fuzzer_bridge.negative import (
    LIST_FAMILIES,
    NEGATIVE_KINDS,
    last_block_overrides,
    modify_last_block,
)

SEED = 10
"""A one-block case every kind can modify: its list has a list of two
entries to reverse, and its execution gas, state gas and receipts total
three different numbers."""

HEADER_FIELD = {
    "number": "number",
    "timestamp": "timestamp",
    "gas_used": "gasUsed",
    "receipts_root": "receiptTrie",
    "requests": "requestsHash",
    "gas_used_sum": "gasUsed",
    "gas_used_receipts": "gasUsed",
}
"""The fixture header field each header kind changes."""


def _case(negative: Optional[FuzzerNegativeInput]) -> FuzzerOutput:
    case = generate_fuzzer_output(Amsterdam, SEED)
    return case.model_copy(update={"negative": negative})


def _fill(
    case: FuzzerOutput,
    fixture_format: Type[BaseFixture],
    overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Fill ``case`` with ``overrides`` on its last block."""
    mod._init_fill_worker("Amsterdam")
    case = resolve_measured_gas(case, Amsterdam, measuring_filler(Amsterdam))
    test = blockchain_test_from_fuzzer(case, Amsterdam)
    if overrides is not None:
        modify_last_block(test, overrides)
    with contextlib.redirect_stdout(io.StringIO()):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = test.generate(
                t8n=mod._FILL["eels"], fixture_format=fixture_format
            )
    return result.fixture.json_dict


@pytest.fixture(scope="module")
def clean() -> Dict[str, Any]:
    """The case unmodified, in the blockchain format."""
    return _fill(_case(None), BlockchainFixture)


def _header_diff(clean: Dict[str, Any], modified: Dict[str, Any]) -> set:
    before = clean["blocks"][-1]["blockHeader"]
    # A block expected rejected keeps its header under `rlp_decoded`.
    after = modified["blocks"][-1]["rlp_decoded"]["blockHeader"]
    return {f for f in before if f != "hash" and before[f] != after.get(f)}


def _draws(families: Iterable[str]) -> List[Any]:
    return [
        pytest.param({"family": family, "kind": kind}, id=f"{family}-{kind}")
        for family in families
        for kind in NEGATIVE_KINDS[family]
    ]


ALL_DRAWS = _draws(NEGATIVE_KINDS)


@pytest.mark.parametrize(
    "draw", _draws(f for f in NEGATIVE_KINDS if f != "encoding")
)
def test_a_modified_block_is_refused_by_eels(
    clean: Dict[str, Any], draw: Dict[str, Any]
) -> None:
    """
    EELS refuses the modified block, imports the same block unmodified,
    and the two headers differ only in the field the kind changes.
    """
    assert import_fixture(clean, "amsterdam").agreed
    negative = FuzzerNegativeInput(**draw, pick=0)
    overrides = last_block_overrides(negative.model_dump(), clean)
    assert overrides is not None
    modified = _fill(_case(negative), BlockchainFixture, overrides)
    assert "expectException" in modified["blocks"][-1]
    result = import_fixture(modified, "amsterdam")
    assert result.agreed, result.reason
    if draw["family"] == "header":
        expected = {HEADER_FIELD[draw["kind"]]}
    elif draw["family"] in LIST_FAMILIES:
        expected = {"blockAccessListHash"}
    else:
        raise ValueError(draw["family"])
    assert _header_diff(clean, modified) == expected


def _engine_negative(draw: Dict[str, Any]) -> Dict[str, Any]:
    negative = FuzzerNegativeInput(**draw, pick=0)
    return mod.fill_case(
        _case(negative),
        Amsterdam,
        mod._FILL["eels"],
        fixture_format=BlockchainEngineFixture,
    )


@pytest.mark.parametrize("draw", ALL_DRAWS)
def test_every_kind_is_refused_on_the_engine_path(
    draw: Dict[str, Any],
) -> None:
    """
    EELS rebuilds the header from the modified payload, finds it hashes to
    the payload's block hash, and refuses it with the exception it names:
    a refusal on the block hash would name no kind's exception.
    """
    mod._init_fill_worker("Amsterdam")
    fixture = _engine_negative(draw)
    assert fixture["_info"]["negative"]["applied"]
    assert fixture["engineNewPayloads"][-1]["validationError"]
    result = import_fixture(fixture, "amsterdam")
    assert result.agreed, result.reason


def test_a_refusal_for_another_reason_is_a_disagreement() -> None:
    """
    The witness's own teeth: a payload refused for its corrupted number
    disagrees with a fixture naming a different exception.
    """
    mod._init_fill_worker("Amsterdam")
    fixture = _engine_negative({"family": "header", "kind": "number"})
    fixture["engineNewPayloads"][-1]["validationError"] = (
        "BlockException.INVALID_RECEIPTS_ROOT"
    )
    result = import_fixture(fixture, "amsterdam")
    assert not result.agreed
    assert "refused as BlockException.INVALID_BLOCK_NUMBER" in result.reason


def test_negatives_are_drawn_only_where_no_block_is_rejected() -> None:
    """
    A case that already rejects a block is never drawn negative, and every
    family is drawn among the rest.
    """
    families = set()
    # The encoding family is about one case in seventy.
    for seed in range(1000):
        case = generate_fuzzer_output(Amsterdam, seed)
        if case.negative is not None:
            assert not any(tx.error for tx in case.transactions)
            families.add(case.negative.family)
    assert families == set(NEGATIVE_KINDS)


def test_every_negative_axis_keeps_all_its_values() -> None:
    """
    Presence, every family and every kind stay drawn.
    A tenth of cases split twenty-four ways needs more seeds than the other
    axes to see each kind: at 2000 seeds a content kind is drawn about ten
    times, and v38's seeds drew `add_untouched` twice.
    """
    coverage = axis_coverage(Amsterdam, range(0, 5000))
    warnings_ = [
        w for w in axis_collapse_warnings(coverage) if w.startswith("negative")
    ]
    assert warnings_ == []


def test_a_clean_case_is_not_modified_in_the_blockchain_format() -> None:
    """Only an engine-format fill applies the draw."""
    negative = FuzzerNegativeInput(family="header", kind="number", pick=0)
    fixture = mod.fill_case(_case(negative), Amsterdam, mod._FILL["eels"])
    assert "negative" not in fixture["_info"]
    assert "expectException" not in fixture["blocks"][-1]
