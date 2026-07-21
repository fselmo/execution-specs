"""
Properties of the parent<->child frame gas lifecycle ([EIP-8037] +
[EIP-150]).

Frame-lifecycle gas machinery: how a parent frame forms a child's
two-dimensional gas grant (`calculate_message_call_gas`,
`max_message_call_gas`, `withhold_create_gas`,
`drain_state_gas_reservoir`), how a never-entered child's grant returns
(`restore_child_gas`), and how a returning child's leftovers reabsorb
(`incorporate_child` after the `interpreter.py` settlement). The meter
functions themselves (charge/commit/restore/refund) are covered by
`test_eip8037_state_gas.py`; this file only reuses them as valid child
activity.

Normative grounding, quoted:

    EIP-150: > Define "all but one 64th" of `N` as `N - floor(N / 64)`.

    EIP-150: > If a call asks for more gas than the maximum allowed
    > amount (i.e. the total amount of gas remaining in the parent
    > after subtracting the gas cost of the call and memory expansion),
    > do not return an OOG error; instead, if a call asks for more gas
    > than all but one 64th of the maximum allowed amount, call with
    > all but one 64th of the maximum allowed amount of gas ... CREATE
    > only provides all but one 64th of the parent gas to the child
    > call.

    EIP-150 (pseudocode): > submsg_gas = gas + opcodes.GSTIPEND *
    > (value > 0)

    EIP-8037: > When a child frame succeeds, its remaining `gas_left`
    > is returned to the parent and its `state_gas_from_gas_left` is
    > added to the parent's `state_gas_from_gas_left`.

    EIP-8037: > When a child frame reverts, all of its state changes
    > are rolled back and the state-gas charged within the frame is
    > refilled ... The child's resulting `gas_left` (including the
    > refilled portion) is then returned to the parent.

    EIP-8037: > When a child frame halts exceptionally, the same refill
    > is applied, but the child's `gas_left` is consumed (set to zero)
    > rather than returned. ... only the portion refilled to
    > `state_gas_reservoir` survives -- which is exactly the
    > reservoir's value at the start of the child frame.

    EIP-8037: > If the operation is unsuccessful before entering the
    > call frame (e.g., due to insufficient balance or due to the stack
    > depth) ... the charged state-gas is refilled in LIFO order.

Spec ambiguity (recorded, tested at docstring tier only): EIP-8037's
Specification never states how much of the `state_gas_reservoir` a
child frame receives. Only the rationale ("up to 63/64 of the parent's
*regular* gas is forwarded") and the security section ("all user
operations in a bundle share the transaction's reservoir") imply a
transaction-shared reservoir with no 63/64 withholding, and the
success rule quoted above returns `gas_left` and the spill but never
mentions the reservoir. The claim "A child frame receives the parent's
entire reservoir; there is no all-but-one-64th rule for state gas" is
EELS's `drain_state_gas_reservoir` docstring, not EIP prose.

Sequences follow the real caller contracts
(`vm/instructions/system.py`, `vm/interpreter.py`,
`vm/__init__.py::incorporate_child`): grants are formed mid-opcode
after the opcode's own charges; `restore_child_gas` fires only in
`generic_call`'s preflight with the child's `sub_call` and the drained
reservoir; a child frame enters with `baseline == state_gas_left ==
grant` and never commits; a failed child settles (`restore_state_gas`,
plus `forfeit_remaining_gas` on exceptional halts) before the parent
absorbs its meter unconditionally.

[EIP-150]: https://eips.ethereum.org/EIPS/eip-150
[EIP-8037]: https://eips.ethereum.org/EIPS/eip-8037
"""

import importlib
from types import ModuleType
from typing import Any, List, Set, Tuple

import pytest
from ethereum_types.numeric import U256, Uint
from hypothesis import given
from hypothesis import strategies as st

POOL_BOUND = 1 << 24
AMOUNT_BOUND = 1 << 22


@pytest.fixture(scope="session")
def gas(fork_name: str) -> ModuleType:
    """Gas module of the fork under test (EIP-8037 forks only)."""
    module = importlib.import_module(f"ethereum.forks.{fork_name}.vm.gas")
    if not hasattr(module, "drain_state_gas_reservoir"):
        pytest.skip(f"{fork_name} has no EIP-8037 frame-gas lifecycle")
    return module


@pytest.fixture(scope="session")
def vm(fork_name: str) -> ModuleType:
    """VM package of the fork under test, for `incorporate_child`."""
    return importlib.import_module(f"ethereum.forks.{fork_name}.vm")


@pytest.fixture(scope="session")
def vm_exceptions(fork_name: str) -> ModuleType:
    """VM exceptions of the fork under test, for `Revert`."""
    return importlib.import_module(f"ethereum.forks.{fork_name}.vm.exceptions")


class FrameStub:
    """
    Minimal `Evm` stand-in.

    The meter functions touch only `evm.gas_meter`; `incorporate_child`
    additionally reads `error` and, on success, merges `logs`,
    `accounts_to_delete` and the accessed sets.
    """

    def __init__(self, gas_meter: Any) -> None:
        self.gas_meter = gas_meter
        self.error: Any = None
        self.logs: Tuple[Any, ...] = ()
        self.accounts_to_delete: Set[Any] = set()
        self.accessed_addresses: Set[Any] = set()
        self.accessed_storage_keys: Set[Any] = set()


def fresh_frame(gas: ModuleType, gas_left: int, reservoir: int) -> FrameStub:
    """A frame-entry meter: baseline == state_gas_left == grant."""
    return FrameStub(
        gas.GasMeter(
            gas_left=Uint(gas_left),
            state_gas_left=Uint(reservoir),
            state_gas_baseline=Uint(reservoir),
        )
    )


def meter_fields(meter: Any) -> Tuple[int, int, int, int, int, int]:
    """All six meter fields as plain ints, for exact comparisons."""
    return (
        int(meter.gas_left),
        int(meter.state_gas_left),
        int(meter.state_gas_baseline),
        int(meter.refund_counter),
        int(meter.state_gas_spilled),
        int(meter.state_gas_committed_spill),
    )


def pools() -> st.SearchStrategy[int]:
    """Pool sizes, weighted towards empty and near-empty pools."""
    return st.one_of(
        st.sampled_from([0, 1, 2, 63, 64, 65, AMOUNT_BOUND]),
        st.integers(min_value=0, max_value=AMOUNT_BOUND),
        st.integers(min_value=0, max_value=POOL_BOUND),
    )


def amounts() -> st.SearchStrategy[int]:
    """Charge/refund amounts, boundary-weighted."""
    return st.one_of(
        st.sampled_from([0, 1, 2, AMOUNT_BOUND]),
        st.integers(min_value=0, max_value=AMOUNT_BOUND),
    )


def op_lists(
    kinds: Tuple[str, ...], max_size: int = 8
) -> st.SearchStrategy[List[Tuple[str, int]]]:
    """Sequences of (kind, amount) meter operations."""
    return st.lists(
        st.tuples(st.sampled_from(kinds), amounts()), max_size=max_size
    )


def apply_ops(
    gas: ModuleType, frame: FrameStub, ops: List[Tuple[str, int]]
) -> Tuple[int, int, int]:
    """
    Apply meter operations, skipping charges the pools cannot cover
    (real frames OOG there; the OOG path is settled separately).

    "spill" is a state charge sized past the current reservoir, so the
    reservoir-exhausted branch is reliably exercised.

    Return the applied totals: (regular charged, state charged, state
    refunded).
    """
    meter = frame.gas_meter
    regular = state = refunded = 0
    for kind, amount in ops:
        if kind == "regular":
            if int(meter.gas_left) < amount:
                continue
            gas.charge_gas(frame, Uint(amount))
            regular += amount
        elif kind == "spill":
            amount = int(meter.state_gas_left) + min(
                amount, int(meter.gas_left)
            )
            gas.charge_state_gas(frame, Uint(amount))
            state += amount
        elif kind == "state":
            if int(meter.gas_left) + int(meter.state_gas_left) < amount:
                continue
            gas.charge_state_gas(frame, Uint(amount))
            state += amount
        elif kind == "refund":
            gas.credit_state_gas_refund(meter, Uint(amount))
            refunded += amount
        else:
            raise ValueError(kind)
    return regular, state, refunded


def all_but_one_64th(n: int) -> int:
    """
    Transcribe EIP-150's definitional prose: 'Define "all but one
    64th" of `N` as `N - floor(N / 64)`.'.
    """
    return n - n // 64


@given(available=pools())
def test_max_message_call_gas_retains_exactly_the_64th(
    gas: ModuleType, available: int
) -> None:
    """
    The parent retains exactly `floor(available / 64)`; the rest is
    the forwardable maximum.

    Grounding (EIP-150 prose, normative): 'Define "all but one 64th"
    of `N` as `N - floor(N / 64)`.' Shape: invariant/conservation.
    Circularity: partial by necessity -- the prose is itself a
    formula. The test asserts the *retained* complement (`floor(N /
    64)`), not the implementation's `gas - gas // 64` expression, so
    it pins the rounding direction and conservation rather than
    re-deriving the subtraction.
    """
    forwarded = int(gas.max_message_call_gas(Uint(available)))
    retained = available - forwarded
    assert retained == available // 64


@given(
    gas_left=pools(),
    reservoir=pools(),
    prefix=op_lists(("regular", "state", "spill", "refund")),
)
def test_withhold_create_gas_splits_regular_gas_conservatively(
    gas: ModuleType,
    gas_left: int,
    reservoir: int,
    prefix: List[Tuple[str, int]],
) -> None:
    """
    Withholding for a `CREATE*` child moves regular gas without
    creating or destroying any: child grant + retained == prior
    `gas_left`, the retained share is exactly the one 64th, and no
    other meter field moves.

    Grounding (EIP-150 prose, normative): "CREATE only provides all
    but one 64th of the parent gas to the child call"; EIP-8037
    restates it: the account charge lands "before 63/64ths of the
    remaining gas is forwarded". Shape: invariant/conservation.
    Circularity: none for the conservation clause; the retained ==
    `floor(gas_left / 64)` clause inherits P1's partial-by-necessity
    grounding in EIP-150's definitional prose.
    """
    frame = fresh_frame(gas, gas_left, reservoir)
    apply_ops(gas, frame, prefix)
    meter = frame.gas_meter
    before = meter_fields(meter)

    child_gas = int(gas.withhold_create_gas(meter))

    assert child_gas + int(meter.gas_left) == before[0]
    assert int(meter.gas_left) == before[0] // 64
    assert meter_fields(meter)[1:] == before[1:]


@given(
    gas_left=pools(),
    reservoir=pools(),
    prefix=op_lists(("regular", "state", "spill", "refund")),
)
def test_drain_grants_the_entire_reservoir_and_empties_the_parent(
    gas: ModuleType,
    gas_left: int,
    reservoir: int,
    prefix: List[Tuple[str, int]],
) -> None:
    """
    Draining for a child grants the parent's entire reservoir --
    no 63/64 withholding -- leaves the parent's reservoir at zero,
    and touches nothing else (in particular not `gas_left` and not
    the baseline).

    Grounding (EELS docstring, self-descriptive): "A child frame
    receives the parent's entire reservoir; there is no
    all-but-one-64th rule for state gas." EIP-8037's Specification
    does not determine this; only its rationale ("up to 63/64 of the
    parent's *regular* gas is forwarded") and security section
    ("share the transaction's reservoir") point the same way -- see
    the module docstring's spec-ambiguity record. This property pins
    EELS's choice. Shape: invariant/conservation. Circularity: none;
    asserts a whole-pool transfer and the absence of any 63/64
    arithmetic on the state dimension.
    """
    frame = fresh_frame(gas, gas_left, reservoir)
    apply_ops(gas, frame, prefix)
    meter = frame.gas_meter
    before = meter_fields(meter)

    granted = int(gas.drain_state_gas_reservoir(meter))

    assert granted == before[1]
    assert int(meter.state_gas_left) == 0
    fields = meter_fields(meter)
    assert (fields[0],) + fields[2:] == (before[0],) + before[2:]


@given(
    gas_left=pools(),
    reservoir=pools(),
    prefix=op_lists(("regular", "state", "spill", "refund")),
)
def test_restore_child_gas_inverts_withhold_and_drain(
    gas: ModuleType,
    gas_left: int,
    reservoir: int,
    prefix: List[Tuple[str, int]],
) -> None:
    """
    Returning a never-entered child's grants restores the parent
    meter exactly: withhold + drain + restore is the identity on all
    six meter fields.

    Grounding (EELS docstring, self-descriptive): "the withheld
    regular gas and drained reservoir are returned untouched." Shape:
    round-trip/inverse. Circularity: none; only equality with the
    prior state is asserted. Note: this is a primitive-level inverse
    -- the real never-entered path (`generic_call` preflight, where
    the regular grant returned is `sub_call`, not the withheld
    amount) is exercised end-to-end below.
    """
    frame = fresh_frame(gas, gas_left, reservoir)
    apply_ops(gas, frame, prefix)
    meter = frame.gas_meter
    before = meter_fields(meter)

    child_gas = gas.withhold_create_gas(meter)
    child_reservoir = gas.drain_state_gas_reservoir(meter)
    gas.restore_child_gas(meter, child_gas, child_reservoir)

    assert meter_fields(meter) == before


@given(
    request=amounts(),
    gas_left=pools(),
    memory_cost=amounts(),
    extra_gas=amounts(),
    big_value=st.integers(min_value=2, max_value=1 << 63),
)
def test_value_changes_only_the_sub_call_gas_by_the_stipend(
    gas: ModuleType,
    request: int,
    gas_left: int,
    memory_cost: int,
    extra_gas: int,
    big_value: int,
) -> None:
    """
    For otherwise-identical inputs, a value-bearing call's `sub_call`
    exceeds the non-value call's by exactly the call stipend, the
    `cost` is identical, and the value's magnitude is irrelevant --
    in both the sufficient- and insufficient-gas branches.

    Grounding (EIP-150 pseudocode, restating the Yellow Paper's
    `G_callstipend`): "submsg_gas = gas + opcodes.GSTIPEND * (value >
    0)" -- the stipend enters the sub-message gas only, and only when
    value > 0; value never enters the charged cost (the value
    surcharge is `extra_gas` at the call sites). Shape: metamorphic.
    Circularity: none; the child's base grant is never recomputed,
    only the difference between two invocations is pinned.
    """
    stipend = int(gas.GasCosts.CALL_STIPEND)
    without_value, with_one, with_big = (
        gas.calculate_message_call_gas(
            U256(value),
            Uint(request),
            Uint(gas_left),
            Uint(memory_cost),
            Uint(extra_gas),
        )
        for value in (0, 1, big_value)
    )
    assert with_one.cost == without_value.cost
    assert int(with_one.sub_call) - int(without_value.sub_call) == stipend
    assert with_big == with_one


@given(
    remaining=pools(),
    memory_cost=amounts(),
    extra_gas=amounts(),
    value=st.sampled_from([0, 1]),
    data=st.data(),
)
def test_child_base_grant_is_the_request_capped_at_63_64(
    gas: ModuleType,
    remaining: int,
    memory_cost: int,
    extra_gas: int,
    value: int,
    data: st.DataObject,
) -> None:
    """
    With enough gas for the call's own costs, the child's base grant
    is the requested gas, capped at all but one 64th of what remains
    after memory and extra costs; the caller is charged that grant
    plus `extra_gas`, and the child receives it plus the stipend.

    Grounding (EIP-150 prose, normative): "if a call asks for more
    gas than all but one 64th of the maximum allowed amount, call
    with all but one 64th of the maximum allowed amount of gas" --
    the maximum allowed amount being "the total amount of gas
    remaining in the parent after subtracting the gas cost of the
    call and memory expansion"; a smaller request is granted as asked
    (the pre-EIP-150 default its pseudocode keeps: `gas = min(gas,
    max_call_gas(...))`). The cost/sub_call split is the
    `MessageCallGas` docstring: `cost` is what "the call opcode"
    requires, `sub_call` the "portion of gas available to sub-calls".
    Shape: invariant + conservation between charged and received.
    Circularity: partial -- the cap value comes from EIP-150's
    definitional formula (see P1); the min() and the grant/cost/
    sub_call relationships are the non-circular content.
    """
    gas_left = remaining + memory_cost + extra_gas
    cap = all_but_one_64th(remaining)
    request = data.draw(
        st.one_of(
            st.sampled_from(
                sorted({0, max(cap - 1, 0), cap, cap + 1, cap + 2})
            ),
            st.integers(min_value=0, max_value=2 * cap + 2),
        )
    )
    stipend = int(gas.GasCosts.CALL_STIPEND) if value else 0

    result = gas.calculate_message_call_gas(
        U256(value),
        Uint(request),
        Uint(gas_left),
        Uint(memory_cost),
        Uint(extra_gas),
    )

    base_grant = int(result.cost) - extra_gas
    assert base_grant == min(request, cap)
    assert int(result.sub_call) == base_grant + stipend


@given(
    reservoir=pools(),
    request=amounts(),
    memory_cost=amounts(),
    extra_gas=amounts(),
    value=st.sampled_from([0, 1]),
    delta=st.one_of(
        st.sampled_from([-2, -1, 0, 1, 2]),
        st.integers(min_value=-AMOUNT_BOUND, max_value=AMOUNT_BOUND),
    ),
)
def test_call_pricing_oogs_exactly_when_own_costs_are_unaffordable(
    gas: ModuleType,
    reservoir: int,
    request: int,
    memory_cost: int,
    extra_gas: int,
    value: int,
    delta: int,
) -> None:
    """
    The composed call pricing (`calculate_message_call_gas` then the
    caller's `charge_gas(cost + memory_cost)`) runs out of gas exactly
    when `gas_left` cannot cover the call's own costs (`extra_gas +
    memory_cost`); a large gas request alone never causes OOG, and
    when the charge succeeds the parent keeps at least its one 64th.
    `calculate_message_call_gas` itself never raises, and a failed
    charge leaves the meter untouched.

    Grounding (EIP-150, normative): "If a call asks for more gas than
    the maximum allowed amount ..., do not return an OOG error", and
    its pseudocode OOGs precisely on `compustate.gas < extra_gas`
    (memory expansion having been priced into the same charge at
    EELS's call sites, `system.py`). Shape: single-entry
    crash-freedom + boundary invariant. Circularity: none; the
    boundary and the retained floor are asserted from outside without
    recomputing the grant.
    """
    gas_left = max(extra_gas + memory_cost + delta, 0)
    frame = fresh_frame(gas, gas_left, reservoir)
    before = meter_fields(frame.gas_meter)

    result = gas.calculate_message_call_gas(
        U256(value),
        Uint(request),
        Uint(gas_left),
        Uint(memory_cost),
        Uint(extra_gas),
    )

    if gas_left < extra_gas + memory_cost:
        with pytest.raises(gas.OutOfGasError):
            gas.charge_gas(frame, result.cost + Uint(memory_cost))
        assert meter_fields(frame.gas_meter) == before
    else:
        gas.charge_gas(frame, result.cost + Uint(memory_cost))
        remaining = gas_left - memory_cost - extra_gas
        assert int(frame.gas_meter.gas_left) >= remaining // 64


@given(
    reservoir=pools(),
    headroom=amounts(),
    request=amounts(),
    warm=st.booleans(),
    value=st.sampled_from([0, 1]),
    folded=st.booleans(),
    creates_account=st.booleans(),
    memory_cost=amounts(),
)
def test_never_entered_call_returns_both_grants_and_refills_state(
    gas: ModuleType,
    reservoir: int,
    headroom: int,
    request: int,
    warm: bool,
    value: int,
    folded: bool,
    creates_account: bool,
    memory_cost: int,
) -> None:
    """
    A call whose child is never entered (depth or balance preflight
    failure) leaves the reservoir, spill, baseline and refund counter
    exactly at their pre-opcode values -- any account-creation state
    charge refills in full -- and its regular `gas_left` ends at the
    pre-opcode value minus the opcode's own costs, plus the stipend
    for a value-bearing call.

    The sequence is `call()`/`callcode()`/... verbatim: access +
    value surcharge (+ memory) charged, the conditional NEW_ACCOUNT
    state charge, grant formation, `drain_state_gas_reservoir`, then
    `generic_call`'s preflight `restore_child_gas(sub_call,
    reservoir)` and NEW_ACCOUNT refill.

    Grounding: state dimension (EIP-8037, normative): "If the
    operation is unsuccessful before entering the call frame (e.g.,
    due to insufficient balance or due to the stack depth) ... the
    charged state-gas is refilled in LIFO order". Regular dimension
    (EELS docstring + call-site contract, self-descriptive): the
    grant "returned untouched" is `sub_call`, which carries the
    stipend, so a failed value call nets `extra_gas - CALL_STIPEND`
    -- long-standing client behaviour for which no EIP prose was
    found (see report). Shape: round-trip with a known leak.
    Circularity: none; the post-state is expressed against pre-opcode
    values and independently summed costs.
    """
    costs = gas.GasCosts
    access = int(costs.WARM_ACCESS if warm else costs.COLD_ACCOUNT_ACCESS)
    extra_gas = access + (int(costs.CALL_VALUE) if value else 0)
    charges_new_account = creates_account and value == 1 and not folded
    state_charge = (
        int(gas.StateGasCosts.NEW_ACCOUNT) if charges_new_account else 0
    )
    gas_left = extra_gas + memory_cost + state_charge + headroom

    frame = fresh_frame(gas, gas_left, reservoir)
    meter = frame.gas_meter
    if folded:
        result = gas.calculate_message_call_gas(
            U256(value),
            Uint(request),
            Uint(int(meter.gas_left)),
            Uint(memory_cost),
            Uint(extra_gas),
        )
        gas.charge_gas(frame, result.cost + Uint(memory_cost))
    else:
        gas.charge_gas(frame, Uint(extra_gas + memory_cost))
        if charges_new_account:
            gas.charge_state_gas(frame, Uint(state_charge))
        result = gas.calculate_message_call_gas(
            U256(value),
            Uint(request),
            Uint(int(meter.gas_left)),
            Uint(0),
            Uint(0),
        )
        gas.charge_gas(frame, result.cost)
    child_reservoir = gas.drain_state_gas_reservoir(meter)

    gas.restore_child_gas(meter, result.sub_call, child_reservoir)
    if charges_new_account:
        gas.credit_state_gas_refund(meter, Uint(state_charge))

    stipend = int(costs.CALL_STIPEND) if value else 0
    assert int(meter.gas_left) == gas_left - extra_gas - memory_cost + stipend
    assert int(meter.state_gas_left) == reservoir
    assert int(meter.state_gas_spilled) == 0
    assert int(meter.state_gas_baseline) == reservoir
    assert int(meter.refund_counter) == 0


@given(
    gas_left=pools(),
    reservoir=pools(),
    parent_ops=op_lists(("regular", "state", "spill", "refund"), max_size=4),
    children=st.lists(
        st.tuples(
            st.sampled_from(["create", "call"]),
            amounts(),
            st.sampled_from([0, 1]),
            op_lists(("regular", "state", "spill", "refund"), max_size=6),
            st.integers(min_value=0, max_value=1 << 16),
            st.sampled_from(["success", "revert", "halt"]),
        ),
        max_size=3,
    ),
)
def test_child_round_trips_conserve_both_gas_dimensions(
    gas: ModuleType,
    vm: ModuleType,
    vm_exceptions: ModuleType,
    gas_left: int,
    reservoir: int,
    parent_ops: List[Tuple[str, int]],
    children: List[Tuple[str, int, int, List[Tuple[str, int]], int, str]],
) -> None:
    """
    Across full parent -> child -> return round trips (grant
    formation, real child meter activity, the `interpreter.py`
    settlement for the outcome, `incorporate_child`), the plumbing
    itself creates and destroys no gas in either dimension: only the
    child's independently ledgered consumption leaves the system.

    Per outcome, with `paid` the regular gas the formation charged
    the parent, `grant` the child's regular grant, `c_reg` /
    `net_state` the ledgered regular / net state consumption and
    `spill_out` the child's outstanding spill:

    - success: parent regular == before - paid + grant - c_reg -
      spill_out; parent reservoir == before - net_state + spill_out;
      parent spill grows by spill_out; the refund counter merges.
      (EIP-8037, normative: "its remaining `gas_left` is returned to
      the parent and its `state_gas_from_gas_left` is added to the
      parent's"; the reservoir clause is EELS's transaction-shared-
      reservoir choice, docstring tier -- see the ambiguity record.)
    - revert: only the child's regular charges are lost; every state
      charge refills and the full reservoir returns. (EIP-8037,
      normative: "The child's resulting `gas_left` (including the
      refilled portion) is then returned to the parent.")
    - halt: the entire forwarded regular grant burns; the reservoir
      returns whole. (EIP-8037, normative: "the child's `gas_left`
      is consumed (set to zero) ... only the portion refilled to
      `state_gas_reservoir` survives -- which is exactly the
      reservoir's value at the start of the child frame.")

    Shape: cross-frame conservation (metamorphic vs an independent
    ledger), sequenced over several children so parent spill and
    refunds accumulate. Circularity: none for the conservation
    identities -- the ledger is kept outside the meter; `spill_out`
    is read off the child meter, whose internal correctness is
    established independently by `test_eip8037_state_gas.py`.
    """
    parent = fresh_frame(gas, gas_left, reservoir)
    apply_ops(gas, parent, parent_ops)
    meter = parent.gas_meter

    for mode, request, value, child_ops, counter, outcome in children:
        pg, pr, _, pref, ps, _ = meter_fields(meter)

        if mode == "create":
            grant = int(gas.withhold_create_gas(meter))
            paid = grant
        elif mode == "call":
            result = gas.calculate_message_call_gas(
                U256(value), Uint(request), Uint(pg), Uint(0), Uint(0)
            )
            gas.charge_gas(parent, result.cost)
            paid = int(result.cost)
            grant = int(result.sub_call)
        else:
            raise ValueError(mode)
        child_reservoir = int(gas.drain_state_gas_reservoir(meter))
        assert child_reservoir == pr
        assert int(meter.state_gas_left) == 0

        child = fresh_frame(gas, grant, child_reservoir)
        c_reg, c_state, c_refunded = apply_ops(gas, child, child_ops)
        net_state = c_state - c_refunded
        child.gas_meter.refund_counter = counter
        spill_out = int(child.gas_meter.state_gas_spilled)

        if outcome == "success":
            pass
        elif outcome == "revert":
            gas.restore_state_gas(child.gas_meter)
            child.error = vm_exceptions.Revert()
        elif outcome == "halt":
            gas.restore_state_gas(child.gas_meter)
            gas.forfeit_remaining_gas(child.gas_meter)
            child.error = gas.OutOfGasError()
        else:
            raise ValueError(outcome)

        vm.incorporate_child(parent, child)

        if outcome == "success":
            assert int(meter.gas_left) == pg - paid + grant - c_reg - spill_out
            assert int(meter.state_gas_left) == pr - net_state + spill_out
            assert int(meter.state_gas_spilled) == ps + spill_out
            assert int(meter.refund_counter) == pref + counter
        elif outcome == "revert":
            assert int(meter.gas_left) == pg - paid + grant - c_reg
            assert int(meter.state_gas_left) == pr
            assert int(meter.state_gas_spilled) == ps
            assert int(meter.refund_counter) == pref
        elif outcome == "halt":
            assert int(meter.gas_left) == pg - paid
            assert int(meter.state_gas_left) == pr
            assert int(meter.state_gas_spilled) == ps
            assert int(meter.refund_counter) == pref
        else:
            raise ValueError(outcome)
