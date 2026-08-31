"""
Tests for the composition-density guard.

This is the instrument that would have caught the v6-v9 regression the
reach map was blind to, so it carries a witness that it can actually
detect one -- not just that it computes numbers.
"""

from execution_testing.cli.fuzzer_bridge.density import (
    DENSITY_FLOORS,
    EXPECTED_AXIS_VALUES,
    axis_collapse_warnings,
    axis_coverage,
    composition_density,
    density_floor_warnings,
    density_record,
    rate_regressions,
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


def test_every_input_axis_still_shows_both_values() -> None:
    """
    The categorical-collapse guard: no input dimension has quietly
    become a constant. This is the check the v6 regression needed --
    it trips without knowing anything about any particular bug.
    """
    coverage = axis_coverage(Amsterdam, range(120))
    assert axis_collapse_warnings(coverage) == []
    assert set(coverage) >= set(EXPECTED_AXIS_VALUES)


def test_axis_guard_catches_a_collapsed_dimension() -> None:
    """
    A dimension reduced to one value is reported -- including the worst
    case, a value that vanished entirely rather than merely thinning.
    """
    collapsed = {
        "precompile_prestate": {"present": 1.0},  # v6: 'absent' vanished
        "call_value": {"zero": 0.97, "nonzero": 0.03},
    }
    warnings = axis_collapse_warnings(collapsed)
    assert any("precompile_prestate=absent 0.00%" in w for w in warnings)
    assert any("call_value=nonzero" in w for w in warnings)


def test_relative_regression_sees_what_an_absolute_floor_misses() -> None:
    """
    A rate more than halving between versions is a regression even while
    it stays far above any absolute floor -- the v9 call-entry-oog case.
    """
    previous = {"call-entry-oog": 297.0, "state-gas": 400.0}
    current = {"call-entry-oog": 133.0, "state-gas": 400.0}
    regressions = rate_regressions(previous, current)
    assert any("call-entry-oog" in r and "-55%" in r for r in regressions)
    assert not any("state-gas" in r for r in regressions)
    # A rise, or a drop inside tolerance, is not a regression.
    assert rate_regressions({"a": 100.0}, {"a": 140.0}) == []
    assert rate_regressions({"a": 100.0}, {"a": 70.0}) == []


def test_density_record_is_trendable() -> None:
    """The record names its kind and version and renders."""
    record = density_record(Amsterdam, range(20))
    assert record["kind"] == "composition-density"
    assert record["generator_version"] >= 10
    assert set(record["density"]) == set(DENSITY_FLOORS)
    assert "composition density" in render_density(record)
