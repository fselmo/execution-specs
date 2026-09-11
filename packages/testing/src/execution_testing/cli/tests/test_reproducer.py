"""Tests for the state-test reproducer and its narrowing table."""

import json
from pathlib import Path
from typing import Any, Dict, List

from execution_testing.forks import Amsterdam

from ..fuzzer_bridge.converter import state_test_from_fuzzer
from ..fuzzer_bridge.generator import generate_fuzzer_output
from ..fuzzer_bridge.reproducer import (
    NarrowingRow,
    fill_state_test,
    narrowing_table,
    render_table,
    variants,
    write_reproducer,
)


def _single_tx_case(seed: int = 3) -> Any:
    """A generated case cut down to its first transaction."""
    case = generate_fuzzer_output(Amsterdam, seed)
    case.transactions = case.transactions[:1]
    return case


def test_a_single_transaction_case_fills_as_a_state_test() -> None:
    """The state test carries the block's environment and fills on EELS."""
    from execution_testing.client_clis.clis.execution_specs import (
        ExecutionSpecsTransitionTool,
    )

    case = _single_tx_case()
    test = state_test_from_fuzzer(case, Amsterdam)
    assert int(test.env.gas_limit) == int(case.env.gas_limit)
    assert int(test.env.number) == 1
    fixture = fill_state_test(case, Amsterdam, ExecutionSpecsTransitionTool())
    assert fixture["_info"]["fixture-format"] == "state_test"
    assert "Amsterdam" in fixture["post"]


def test_a_multi_transaction_case_is_refused() -> None:
    """A state test carries one transaction, and says so."""
    import pytest

    case = generate_fuzzer_output(Amsterdam, 3)
    assert len(case.transactions) > 1
    with pytest.raises(ValueError, match="one transaction"):
        state_test_from_fuzzer(case, Amsterdam)


def test_variants_change_one_axis_each() -> None:
    """Every row differs from "as found" in exactly the thing it names."""
    from execution_testing.base_types import HexNumber

    case = _single_tx_case()
    tx = case.transactions[0]
    tx.value = HexNumber(7)
    tx.max_fee_per_gas = HexNumber(10)
    tx.max_priority_fee_per_gas = HexNumber(1)
    tx.gas_price = None
    rows = {label: (c, f) for label, c, f in variants(case, Amsterdam)}
    assert rows["as found"][0] is case
    assert rows["on Osaka"][1].name() == "Osaka"
    assert int(rows["value 0"][0].transactions[0].value) == 0
    assert int(rows["gas halved"][0].transactions[0].gas) == int(tx.gas) // 2
    legacy = rows["legacy gas pricing"][0].transactions[0]
    assert legacy.max_fee_per_gas is None
    assert legacy.gas_price is not None and int(legacy.gas_price) == 10
    # The original is untouched by any variant.
    assert int(tx.value) == 7 and tx.max_fee_per_gas is not None


def test_narrowing_table_records_each_judgement(monkeypatch: Any) -> None:
    """A fill failure and an unjudged row are results, not errors."""
    from ..fuzzer_bridge import reproducer as mod

    def fake_fill(case: Any, fork: Any, *_: Any) -> Dict[str, Any]:
        if fork.name() == "Osaka":
            raise RuntimeError("no state gas before Amsterdam")
        return {"gas": int(case.transactions[0].gas)}

    monkeypatch.setattr(mod, "fill_state_test", fake_fill)
    case = _single_tx_case()
    gas = int(case.transactions[0].gas)

    def judge(fixture: Dict[str, Any]) -> Any:
        if fixture["gas"] == gas * 2:
            return None
        return fixture["gas"] >= gas

    rows = narrowing_table(case, Amsterdam, None, judge)
    by_label = {row.label: row.result for row in rows}
    assert by_label["as found"] == "diverges"
    assert by_label["on Osaka"] == "unfillable"
    assert by_label["gas halved"] == "agrees"
    assert by_label["gas doubled"] == "not judged"
    text = render_table(rows)
    assert text.splitlines()[0].startswith("Narrowing:")
    assert "  as found" in text and "diverges" in text


def test_reproducer_is_written_only_when_the_client_still_fails_it(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """
    Surviving the state-test framing is the check: a divergence the
    client only shows on a block stays a blockchain-fixture finding.
    """
    from ..fuzzer_bridge import reproducer as mod

    monkeypatch.setattr(mod, "fill_state_test", lambda *_: {"_info": {}})
    case = _single_tx_case()

    kept = write_reproducer(
        tmp_path / "a", case, Amsterdam, None, lambda _f: True
    )
    assert kept is not None and kept.name == "reproducer_state_test.json"
    written = json.loads(kept.read_text())["reproducer"]
    assert written["_info"]["comment"].startswith("Narrowing:")
    assert "still fails it" in (tmp_path / "a" / "reproducer.md").read_text()

    (tmp_path / "b").mkdir()
    assert (
        write_reproducer(
            tmp_path / "b", case, Amsterdam, None, lambda _f: False
        )
        is None
    )
    note = (tmp_path / "b" / "reproducer.md").read_text()
    assert "only the block carries" in note
    assert not (tmp_path / "b" / "reproducer_state_test.json").exists()

    (tmp_path / "c").mkdir()
    assert (
        write_reproducer(
            tmp_path / "c", case, Amsterdam, None, lambda _f: None
        )
        is not None
    )
    assert "not judged" in (tmp_path / "c" / "reproducer.md").read_text()

    (tmp_path / "d").mkdir()
    many = generate_fuzzer_output(Amsterdam, 3)
    assert (
        write_reproducer(
            tmp_path / "d", many, Amsterdam, None, lambda _f: True
        )
        is None
    )
    assert (
        "transactions; a state test carries one"
        in (tmp_path / "d" / "reproducer.md").read_text()
    )


def test_render_table_aligns_results() -> None:
    """Labels are padded so the results line up."""
    rows: List[NarrowingRow] = [
        NarrowingRow("as found", "diverges"),
        NarrowingRow("gas halved", "agrees"),
    ]
    lines = render_table(rows).splitlines()[1:]
    assert lines == ["  as found    diverges", "  gas halved  agrees"]
