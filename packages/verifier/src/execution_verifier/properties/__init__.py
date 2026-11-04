"""
The library behind the spec property suite in `tests_property/`.

`strategies` draws inputs weighted toward protocol boundaries, `aim_at`
steers a search toward the edge of one rule, and `spec_api` bridges the
framework's objects to each fork's spec.
"""

from .targets import aim_at

__all__ = ("aim_at",)
