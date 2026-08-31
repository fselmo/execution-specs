"""
Tests for the composition-density guard.

This is the instrument that would have caught the v6-v9 regression the
reach map was blind to, so it carries a witness that it can actually
detect one -- not just that it computes numbers.
"""

from execution_testing.cli.fuzzer_bridge.density import (
    DENSITY_FLOORS,
    composition_density,
    density_floor_warnings,
    density_record,
    render_density,
)
from execution_testing.forks import Amsterdam


def test_current_generator_clears_every_density_floor() -> None:
    """The guard: a density regression fails here, like a broken test."""
    density = composition_density(Amsterdam, range(120))
    assert density_floor_warnings(density) == []


def test_density_measures_the_besu_path() -> None:
    """
    The composition that matters is emitted, and most cases leave the
    precompiles unfunded so a value-bearing call to one pays the
    account-creation charge.
    """
    density = composition_density(Amsterdam, range(120))
    assert density["value_callcode_precompile_per_case"] > 0
    assert density["unfunded_precompile_pct"] > 50
    assert density["tx_into_contract_pct"] > 50


def test_floor_warnings_catch_a_collapsed_density() -> None:
    """
    A regression is reported, not silently averaged away. These are the
    v9 numbers that produced zero client divergences.
    """
    collapsed = {
        "tx_into_contract_pct": 27.6,
        "unfunded_precompile_pct": 0.0,
        "precompile_calls_per_case": 4.62,
        "value_precompile_calls_per_case": 1.62,
        "value_callcode_precompile_per_case": 0.84,
        "call_sites_per_case": 15.9,
    }
    warnings = density_floor_warnings(collapsed)
    assert any("tx_into_contract_pct" in w for w in warnings)
    assert any("unfunded_precompile_pct" in w for w in warnings)
    assert "below floor" in render_density(
        {
            "generator_version": 9,
            "fork": "Amsterdam",
            "seeds": 400,
            "density": collapsed,
        }
    )


def test_density_record_is_trendable() -> None:
    """The record names its kind and version and renders."""
    record = density_record(Amsterdam, range(20))
    assert record["kind"] == "composition-density"
    assert record["generator_version"] >= 10
    assert set(record["density"]) == set(DENSITY_FLOORS)
    assert "composition density" in render_density(record)
