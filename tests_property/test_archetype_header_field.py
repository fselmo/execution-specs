"""
Structural archetype: a new header field is absent before its fork, present
after.

This is the execution-presence oracle tier — write the property once, and
``with_each_change`` runs it for every ``feature_enabled`` change across every
fork transition (present and future). The check builds a real block at each
fork via the reference spec and inspects the header, so it confirms the field
flows through block construction end to end, not merely that the fork
predicate flipped.

Assumption-free: it asserts only presence/absence, never a value, so it cannot
encode a wrong expectation. ``feature_enabled`` changes that are not header
fields (e.g. ``state_gas_reservoir_enabled``) are not in the observable
registry and are covered by other archetypes.
"""

import pytest
from execution_testing.eip_properties import (
    HEADER_FIELD_FEATURES,
    Change,
    ChangeKind,
    built_header_at_fork,
    with_each_change,
)
from execution_testing.forks import Fork


@with_each_change(ChangeKind.FEATURE_ENABLED)
def test_new_header_field_absent_before_present_after(
    parent: Fork, child: Fork, change: Change
) -> None:
    """A header field a fork newly requires is absent at the parent fork."""
    field = HEADER_FIELD_FEATURES.get(change.name)
    if field is None:
        pytest.skip(f"{change.name} is not a registered header-field feature")

    parent_value = getattr(built_header_at_fork(parent), field, None)
    child_value = getattr(built_header_at_fork(child), field, None)

    assert parent_value is None, (
        f"{field} should be absent at {parent.name()} (before "
        f"{change.name} was required) but was {parent_value!r}"
    )
    assert child_value is not None, (
        f"{field} should be present at {child.name()} (after {change.name} "
        "became required) but was absent"
    )
