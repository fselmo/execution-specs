"""
Test-matrix metadata for the CALL family.

This module defines the **catalog** of test parameter axes and their
interaction rules as plain data (`AXES`, `CONSTRAINTS`), plus a small
decorator factory (`apply_matrix`) that converts the catalog into the
`pytest.mark.parametrize` + `filter_combinations` stack at collection time.

Design pattern: Specification Pattern (Eric Evans, *Domain-Driven Design*)
applied to test parameterization. The catalog lives in code as typed
dataclasses, not in docstrings — so it stays in sync with what the test
actually runs. Decision-table flavor (ISO 5806; Myers, *Art of Software
Testing*) for `Constraint` rules.

Adding a new axis:
    AXES.append(Axis(name="ret_layout",
                     values=["no-mem", "expand-32", "huge-offset-zero-size"],
                     semantics="Layout of the return-data buffer"))

Adding a new axis-interaction rule:
    CONSTRAINTS.append(Constraint(
        description="STATICCALL has no value argument",
        consequence="filter",
        predicate=lambda opcode, value_kind, **_:
            opcode is Op.STATICCALL and value_kind != "zero",
        related_axes=("opcode", "value_kind"),
    ))

The driver test function's parameter names must match the `Axis.name`
values; pytest enforces this at collection time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Optional

import pytest
from execution_testing import (
    BlockAccessListExpectation,
    Header,
    Op,
)


# Currently the PoC has only Op.CALL; later steps add CALLCODE,
# DELEGATECALL, STATICCALL with fork gates.
@dataclass(frozen=True)
class Axis:
    """
    One parameter dimension of the test matrix.

    Adding an axis: append an `Axis(...)` to `AXES` and add a
    matching kwarg to the driver test function.
    """

    name: str
    values: list[Any]
    semantics: str
    valid_from: dict[Any, str] = field(default_factory=dict)
    valid_until: dict[Any, str] = field(default_factory=dict)
    # If set, maps a value to a custom pytest id; otherwise the default
    # id is `f"{name}={value}"`.
    ids: Optional[dict[Any, str]] = None

    def pytest_id(self, value: Any) -> str:
        """Return the pytest parametrize id for a given value."""
        if self.ids is not None and value in self.ids:
            return self.ids[value]
        return f"{self.name}={value}"

    def marks_for(self, value: Any) -> list[pytest.MarkDecorator]:
        """Return per-value marks (valid_from / valid_until) for a value."""
        marks: list[pytest.MarkDecorator] = []
        if value in self.valid_from:
            marks.append(pytest.mark.valid_from(self.valid_from[value]))
        if value in self.valid_until:
            marks.append(pytest.mark.valid_until(self.valid_until[value]))
        return marks


@dataclass(frozen=True)
class Constraint:
    """
    A rule expressing how axes interact.

    `predicate` receives parameter values as keyword arguments and returns
    `True` when the constraint *triggers* (i.e., when this combination is
    structurally impossible or produces a runtime revert).

    `consequence` says what the framework does:
      - "filter": deselect the combination at collection time
                  (translated to `pytest.mark.filter_combinations`).
      - "revert": run the test but expect a runtime exception; the
                  driver reads this and sets `CallExpected.exception`.
                  (Wiring lands when the `exception` axis is added; for
                  now, "revert" constraints are present but unused.)
    """

    description: str
    consequence: Literal["filter", "revert"]
    predicate: Callable[..., bool]
    related_axes: tuple[str, ...] = ()


@dataclass
class CallExpected:
    """
    Aggregated expectation for a single `*CALL` invocation.

    Fields default to "no check" semantics: `block_access_list=None` and
    `header_verify=None` skip those framework hooks. Numeric fields are
    always set.
    """

    call_returns_one: bool
    measured_call_gas: int
    caller_balance_delta: int
    target_balance_delta: int
    block_access_list: Optional[BlockAccessListExpectation] = None
    header_verify: Optional[Header] = None
    extra_storage: dict[int, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Catalog: AXES and CONSTRAINTS.
# ---------------------------------------------------------------------------

AXES: list[Axis] = [
    Axis(
        name="opcode",
        values=[Op.CALL, Op.CALLCODE, Op.DELEGATECALL, Op.STATICCALL],
        semantics="Which *CALL opcode is under test",
        ids={
            Op.CALL: "CALL",
            Op.CALLCODE: "CALLCODE",
            Op.DELEGATECALL: "DELEGATECALL",
            Op.STATICCALL: "STATICCALL",
        },
        # CALL and CALLCODE: Frontier. DELEGATECALL: EIP-7 (Homestead).
        # STATICCALL: EIP-214 (Byzantium). Per-value fork gates would go
        # here, but the framework currently rejects stacking per-param
        # `valid_from` with a module-level `pytestmark = valid_from(...)`.
        # The module pytestmark already restricts to Berlin+ (above the
        # introduction fork of every sibling), so per-value gates are
        # redundant today. Re-enable them when the module-level gate
        # lifts (once the pre-Berlin framework bugs are fixed).
        # valid_from={
        #     Op.DELEGATECALL: "Homestead",
        #     Op.STATICCALL: "Byzantium",
        # },
    ),
    Axis(
        name="target_kind",
        values=["eoa", "contract", "precompile", "7702-delegated"],
        semantics="What account the *CALL targets",
        ids={
            "eoa": "target=eoa",
            "contract": "target=contract",
            # Step 9: one representative precompile (IDENTITY at 0x04).
            # Full precompile coverage is a follow-up interaction test
            # using @pytest.mark.with_all_precompiles.
            "precompile": "target=precompile",
            # Step 15: EIP-7702 delegated account. Skipped at runtime on
            # pre-Prague forks (pytest.skip inside the test body) since
            # we can't compose per-value valid_from with the module-
            # level pytestmark.valid_from("Berlin").
            "7702-delegated": "target=7702",
        },
    ),
    Axis(
        name="value_kind",
        values=["zero", "nonzero"],
        semantics="Wei sent with the call",
        ids={"zero": "value=zero", "nonzero": "value=nonzero"},
    ),
    # Wrapper axis. After the capsule+harness refactor (Step 10b), all
    # wrappers route through the same outer harness (which always
    # SSTOREs the capsule's RETURN data). The intermediate contract
    # (built per-wrapper) carries the wrapper-opcode semantics.
    # `direct`              — capsule reached without an intermediate.
    # `under-CALL`          — extra wrapping CALL (non-static).
    # `under-STATICCALL`    — extra wrapping STATICCALL; capsule runs
    #                         in static context; CALL × value>0 hits
    #                         WriteInStaticContext (line 374).
    # `under-CALLCODE` / `under-DELEGATECALL` / CREATE-init wrappers:
    # deferred; require additional driver work for balance/storage
    # attribution.
    Axis(
        name="wrapper",
        values=["direct", "under-CALL", "under-STATICCALL"],
        semantics="Execution context the opcode-under-test runs under",
        ids={
            "direct": "wrap=direct",
            "under-CALL": "wrap=under-CALL",
            "under-STATICCALL": "wrap=under-STATICCALL",
        },
    ),
    # Gas-variant axis. `sufficient` is the happy path. `insufficient-
    # balance` funds the caller with 0 wei so nonzero-value CALL/CALLCODE
    # fails the `sender_balance < value` check (spec lines 438-440 in
    # call) — CALL returns 0, value is NOT transferred, but the upfront
    # gas (warm/cold + value cost) is still paid.
    Axis(
        name="gas_variant",
        values=["sufficient", "insufficient-balance"],
        semantics="Whether the caller can afford the requested transfer",
        ids={
            "sufficient": "gas=sufficient",
            "insufficient-balance": "gas=insufficient-balance",
        },
    ),
]


CONSTRAINTS: list[Constraint] = [
    Constraint(
        description=(
            "STATICCALL and DELEGATECALL have no value argument; "
            "value_kind=nonzero is structurally impossible for them."
        ),
        consequence="filter",
        predicate=lambda opcode, value_kind, **_: (
            opcode in (Op.STATICCALL, Op.DELEGATECALL) and value_kind != "zero"
        ),
        related_axes=("opcode", "value_kind"),
    ),
    Constraint(
        description=(
            "gas_variant=insufficient-balance only meaningful when "
            "value > 0 — value=zero has nothing to transfer, so the "
            "balance check trivially passes."
        ),
        consequence="filter",
        predicate=lambda gas_variant, value_kind, **_: (
            gas_variant == "insufficient-balance" and value_kind == "zero"
        ),
        related_axes=("gas_variant", "value_kind"),
    ),
    Constraint(
        description=(
            "gas_variant=insufficient-balance only meaningful for "
            "value-carrying opcodes (CALL, CALLCODE). DELEGATECALL and "
            "STATICCALL never transfer balance."
        ),
        consequence="filter",
        predicate=lambda opcode, gas_variant, **_: (
            gas_variant == "insufficient-balance"
            and opcode in (Op.STATICCALL, Op.DELEGATECALL)
        ),
        related_axes=("opcode", "gas_variant"),
    ),
]


# ---------------------------------------------------------------------------
# Decorator factory: catalog → pytest decorators.
# ---------------------------------------------------------------------------


def apply_matrix(
    axes: list[Axis] = AXES,
    constraints: list[Constraint] = CONSTRAINTS,
) -> Callable:
    """
    Build the `pytest.mark.parametrize` + `filter_combinations` stack from
    the declarative catalog and apply it to a test function.

    Decorator order: axes are applied in reverse so the FIRST axis in
    `AXES` is the OUTERMOST in pytest's id concatenation. This matches
    pytest's convention of stacking decorators bottom-up.
    """

    def decorator(test_fn: Callable[..., Any]) -> Callable[..., Any]:
        # 1. Parametrize axes. Applied in forward order so AXES[0] becomes
        # the innermost decorator. Pytest concatenates parametrize ids with
        # the innermost decorator's value FIRST, so AXES[0]'s ids appear
        # first in the test node id.
        for axis in axes:
            params = [
                pytest.param(
                    v,
                    id=axis.pytest_id(v),
                    marks=axis.marks_for(v),
                )
                for v in axis.values
            ]
            test_fn = pytest.mark.parametrize(axis.name, params)(test_fn)

        # 2. Apply filter-consequence constraints. `filter_combinations`
        # expects a predicate that returns True to KEEP a combination, so
        # we negate the constraint's predicate (which returns True when
        # the constraint TRIGGERS). Default-arg `_p=c.predicate` binds
        # the predicate by VALUE so the closure captures each iteration's
        # predicate independently — avoiding the classic Python
        # "late-binding in loop" bug.
        for c in constraints:
            if c.consequence != "filter":
                continue
            test_fn = pytest.mark.filter_combinations(
                lambda _p=c.predicate, **kw: not _p(**kw),
                reason=c.description,
            )(test_fn)

        return test_fn

    return decorator
