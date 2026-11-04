"""
Steer a Hypothesis search toward the edge of a rule.

Hypothesis's `target()` keeps the examples that score highest on a label
and mutates them further. Scoring how close a value is to the point where a
rule flips (a cap, a fee, the top of a 64-bit or 256-bit field) makes the
search spend its examples on both sides of that point.
"""

from hypothesis import target


def aim_at(value: int, edge: int, label: str) -> None:
    """Score `value` by how close it lands to `edge`."""
    target(-abs(value - edge), label=label)
