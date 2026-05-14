"""
Resource fixtures for the CALL family matrix driver.

The `expected` object is NOT a fixture — see Dimensions 3+4 of the design
plan. `expected_call(...)` is called directly from the test body because
later axes (BAL, EIP-7708 logs) require runtime-determined addresses that
don't exist before the body deploys them.

Only true resource fixtures (parameters mapped to concrete values
without runtime state) live here.
"""

import pytest


@pytest.fixture
def transfer_value(value_kind: str) -> int:
    """Wei sent with the *CALL when value_kind == 'nonzero'."""
    if value_kind == "zero":
        return 0
    if value_kind == "nonzero":
        return 1
    raise ValueError(f"unknown value_kind={value_kind!r}")
