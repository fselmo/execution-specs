"""Tests for the fork-aware gas accounting invariants."""

from types import SimpleNamespace
from typing import Any, List

from execution_testing.forks import Amsterdam, Osaka

from ..invariants import check_gas_accounting


def _result(gas_used: int, cumulative: List[int]) -> Any:
    receipts = [SimpleNamespace(cumulative_gas_used=c) for c in cumulative]
    return SimpleNamespace(gas_used=gas_used, receipts=receipts)


def _env() -> Any:
    return SimpleNamespace(
        gas_limit=30_000_000, withdrawals=None, base_fee_per_gas=7
    )


def test_receipts_must_equal_block_gas_without_state_gas() -> None:
    """Pre-EIP-8037, the last receipt equals the header's gas used."""
    violations = check_gas_accounting(Osaka, _result(500, [200, 700]), _env())
    assert [v.invariant for v in violations] == ["receipt_gas_totals"]
    assert check_gas_accounting(Osaka, _result(700, [200, 700]), _env()) == []


def test_receipts_may_exceed_block_gas_with_state_gas() -> None:
    """With state gas the header is max(execution, state); receipts sum."""
    assert (
        check_gas_accounting(Amsterdam, _result(500, [200, 700]), _env()) == []
    )
    violations = check_gas_accounting(
        Amsterdam, _result(900, [200, 700]), _env()
    )
    assert [v.invariant for v in violations] == ["receipt_gas_totals"]
