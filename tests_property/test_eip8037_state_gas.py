"""
Properties of the [EIP-8037] two-dimensional gas meter.

EIP-8037 splits execution gas into a regular pool (``gas_left``) and a
state gas reservoir, with normative counter rules:

    > State-gas charges deduct from `state_gas_reservoir` first. When
    > the reservoir is exhausted, the remainder deducts from `gas_left`
    > and increments `state_gas_from_gas_left` by that remainder.

    > It is credited to `gas_left` first (decrementing
    > `state_gas_from_gas_left` by the same amount) up to the current
    > value of `state_gas_from_gas_left`, and any remainder is credited
    > to `state_gas_reservoir`.

    > Undoing a state creation therefore restores the exact pools the
    > charge drew from, so the two pools never drift into one another --
    > `gas_left` is never inflated beyond `TX_MAX_GAS_LIMIT -
    > intrinsic_gas`, and regular gas is never permanently stranded in
    > the state-only reservoir.

    > refilling in LIFO order makes the reservoir whole automatically
    > [on an exceptional halt] ... only the portion refilled to
    > `state_gas_reservoir` survives -- which is exactly the reservoir's
    > value at the start of the child frame.

    > Exceeding the regular gas budget behaves identically to running
    > out of gas -- no special error is needed.

The commit/baseline machinery (``commit_state_gas``,
``restore_state_gas_to_entry``, ``GasMeter.state_gas_baseline``) has no
counterpart in EIP-8037 prose; those properties are grounded in the
EELS docstrings only (self-descriptive tier) and pin EELS's choice.

Sequences follow the real caller contracts (``vm/interpreter.py``,
``vm/instructions/storage.py``, ``vm/instructions/system.py``): a frame
meter starts with ``baseline == state_gas_left == grant``; before
dispatch only charges occur, then at most one commit; refunds (which
may exceed the frame's own charges -- a slot created by an ancestor
frame can be cleared here) and refund-counter bumps happen only after
dispatch; ``restore_state_gas_to_entry`` fires only pre-dispatch with a
zero refund counter; ``forfeit_remaining_gas`` only after a restore.

[EIP-8037]: https://eips.ethereum.org/EIPS/eip-8037
"""

import importlib
from types import ModuleType
from typing import Any, List, Tuple

import pytest
from ethereum_types.numeric import Uint
from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine,
    initialize,
    invariant,
    precondition,
    rule,
    run_state_machine_as_test,
)

POOL_BOUND = 1 << 24
AMOUNT_BOUND = 1 << 22


@pytest.fixture(scope="session")
def gas(fork_name: str) -> ModuleType:
    """Gas module of the fork under test (EIP-8037 forks only)."""
    module = importlib.import_module(f"ethereum.forks.{fork_name}.vm.gas")
    if not hasattr(module, "GasMeter"):
        pytest.skip(f"{fork_name} has no EIP-8037 GasMeter")
    return module


class EvmStub:
    """
    Minimal `Evm` stand-in for the meter functions.

    `check_gas`, `charge_gas` and `charge_state_gas` touch only
    `evm.gas_meter`; the tracing hook discards the object.
    """

    def __init__(self, gas_meter: Any) -> None:
        self.gas_meter = gas_meter


def fresh_evm(gas: ModuleType, gas_left: int, reservoir: int) -> EvmStub:
    """A frame-entry meter: baseline == state_gas_left == grant."""
    return EvmStub(
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
    """
    Pool sizes: empty and near-empty pools are weighted so reservoir
    exhaustion (and hence spill) is common, alongside the full range.
    """
    return st.one_of(
        st.sampled_from([0, 1, 2, AMOUNT_BOUND // 2, AMOUNT_BOUND]),
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
    kinds: Tuple[str, ...], max_size: int = 12
) -> st.SearchStrategy[List[Tuple[str, int]]]:
    """Sequences of (kind, amount) meter operations."""
    return st.lists(
        st.tuples(st.sampled_from(kinds), amounts()), max_size=max_size
    )


def apply_ops(
    gas: ModuleType, evm: EvmStub, ops: List[Tuple[str, int]]
) -> Tuple[int, int, int]:
    """
    Apply meter operations, skipping charges the pools cannot cover
    (real callers OOG there; the OOG path is tested separately).

    "spill" is a state charge sized past the current reservoir, so
    the reservoir-exhausted branch is reliably exercised in mixed
    sequences.

    Return the applied totals: (regular charged, state charged, state
    refunded).
    """
    meter = evm.gas_meter
    regular = state = refunded = 0
    for kind, amount in ops:
        if kind == "regular":
            if int(meter.gas_left) < amount:
                continue
            gas.charge_gas(evm, Uint(amount))
            regular += amount
        elif kind == "spill":
            amount = int(meter.state_gas_left) + min(
                amount, int(meter.gas_left)
            )
            gas.charge_state_gas(evm, Uint(amount))
            state += amount
        elif kind == "state":
            if int(meter.gas_left) + int(meter.state_gas_left) < amount:
                continue
            gas.charge_state_gas(evm, Uint(amount))
            state += amount
        elif kind == "refund":
            gas.credit_state_gas_refund(meter, Uint(amount))
            refunded += amount
        else:
            raise ValueError(kind)
    return regular, state, refunded


@given(gas_left=pools(), reservoir=pools(), data=st.data())
def test_state_charge_drains_reservoir_before_spilling(
    gas: ModuleType, gas_left: int, reservoir: int, data: st.DataObject
) -> None:
    """
    A state charge draws from the reservoir first and spills exactly
    the remainder.

    Grounding (EIP-8037, normative): "State-gas charges deduct from
    `state_gas_reservoir` first. When the reservoir is exhausted, the
    remainder deducts from `gas_left` and increments
    `state_gas_from_gas_left` by that remainder." Non-circular: the
    expected split is recomputed from the prose (max/min arithmetic),
    not from the implementation's branches.
    """
    total = gas_left + reservoir
    boundary = sorted({0, min(reservoir, total), min(reservoir + 1, total)})
    amount = data.draw(
        st.one_of(
            st.sampled_from(boundary),
            st.integers(min_value=0, max_value=total),
        )
    )
    evm = fresh_evm(gas, gas_left, reservoir)
    gas.charge_state_gas(evm, Uint(amount))
    spill = max(amount - reservoir, 0)
    meter = evm.gas_meter
    assert int(meter.state_gas_left) == max(reservoir - amount, 0)
    assert int(meter.gas_left) == gas_left - spill
    assert int(meter.state_gas_spilled) == spill
    assert int(meter.refund_counter) == 0
    assert int(meter.state_gas_baseline) == reservoir


@given(gas_left=pools(), reservoir=pools(), excess=amounts())
def test_state_charge_boundary_is_the_combined_pool(
    gas: ModuleType, gas_left: int, reservoir: int, excess: int
) -> None:
    """
    A state charge succeeds iff the two pools together cover it, and a
    failed charge leaves the meter untouched.

    Grounding (EIP-8037, normative): "State gas charges draw from the
    reservoir first, then from `gas_left` when the reservoir is empty
    ... Exceeding the regular gas budget behaves identically to running
    out of gas." Non-circular: pins the exact boundary (`gas_left +
    reservoir`) and OOG atomicity from the outside.
    """
    total = gas_left + reservoir

    evm = fresh_evm(gas, gas_left, reservoir)
    gas.charge_state_gas(evm, Uint(total))
    assert int(evm.gas_meter.gas_left) == 0
    assert int(evm.gas_meter.state_gas_left) == 0
    assert int(evm.gas_meter.state_gas_spilled) == gas_left

    evm = fresh_evm(gas, gas_left, reservoir)
    before = meter_fields(evm.gas_meter)
    with pytest.raises(gas.OutOfGasError):
        gas.charge_state_gas(evm, Uint(total + 1 + excess))
    assert meter_fields(evm.gas_meter) == before


@given(gas_left=pools(), reservoir=pools(), data=st.data())
def test_regular_gas_checks_ignore_the_reservoir(
    gas: ModuleType, gas_left: int, reservoir: int, data: st.DataObject
) -> None:
    """
    `check_gas` and `charge_gas` see only `gas_left`: a reservoir large
    enough to cover the amount does not save them, `check_gas` never
    mutates, and a failed `charge_gas` leaves the meter untouched.

    Grounding (EIP-8037, normative): regular-gas charges "deduct from
    `gas_left` only"; "The `GAS` opcode returns `gas_left` only
    (excluding the reservoir)"; the SSTORE stipend check "applies to
    `gas_left` only, excluding the `state_gas_reservoir`". `check_gas`
    docstring: "Checks if `amount` gas is available without charging
    it." Non-circular: asserts the reservoir's *absence* from a
    computation the reservoir could plausibly join.
    """
    amount = data.draw(
        st.one_of(
            st.sampled_from(
                sorted({0, gas_left, gas_left + 1, gas_left + reservoir})
            ),
            st.integers(min_value=0, max_value=gas_left + reservoir + 2),
        )
    )
    evm = fresh_evm(gas, gas_left, reservoir)
    before = meter_fields(evm.gas_meter)

    if amount > gas_left:
        with pytest.raises(gas.OutOfGasError):
            gas.check_gas(evm, Uint(amount))
        assert meter_fields(evm.gas_meter) == before
        with pytest.raises(gas.OutOfGasError):
            gas.charge_gas(evm, Uint(amount))
        assert meter_fields(evm.gas_meter) == before
    else:
        gas.check_gas(evm, Uint(amount))
        assert meter_fields(evm.gas_meter) == before
        gas.charge_gas(evm, Uint(amount))
        assert int(evm.gas_meter.gas_left) == gas_left - amount
        assert int(evm.gas_meter.state_gas_left) == reservoir
        assert int(evm.gas_meter.state_gas_spilled) == 0


@given(
    gas_left=pools(),
    reservoir=pools(),
    charges=op_lists(("state", "spill")),
    refund=amounts(),
    data=st.data(),
)
def test_refund_credits_the_last_charged_pool_first(
    gas: ModuleType,
    gas_left: int,
    reservoir: int,
    charges: List[Tuple[str, int]],
    refund: int,
    data: st.DataObject,
) -> None:
    """
    A refund routes `min(amount, spilled)` to `gas_left` and the
    remainder to the reservoir.

    Grounding (EIP-8037, normative): "It is credited to `gas_left`
    first (decrementing `state_gas_from_gas_left` by the same amount)
    up to the current value of `state_gas_from_gas_left`, and any
    remainder is credited to `state_gas_reservoir`." Refunds larger
    than the frame's own charges are valid caller inputs (clearing a
    slot an ancestor frame created, `storage.py`). Non-circular: the
    split is recomputed from the quoted rule after an arbitrary charge
    prefix.
    """
    evm = fresh_evm(gas, gas_left, reservoir)
    apply_ops(gas, evm, charges)
    meter = evm.gas_meter
    spilled = int(meter.state_gas_spilled)
    amount = data.draw(
        st.sampled_from(
            sorted({refund, spilled, spilled + 1, max(spilled - 1, 0)})
        )
    )
    before_gas_left = int(meter.gas_left)
    before_reservoir = int(meter.state_gas_left)

    gas.credit_state_gas_refund(meter, Uint(amount))

    from_gas_left = min(amount, spilled)
    assert int(meter.gas_left) == before_gas_left + from_gas_left
    assert int(meter.state_gas_spilled) == spilled - from_gas_left
    assert (
        int(meter.state_gas_left) == before_reservoir + amount - from_gas_left
    )


@given(
    gas_left=pools(),
    reservoir=pools(),
    charges=st.lists(amounts(), max_size=10),
)
def test_state_charges_then_lifo_refunds_round_trip_exactly(
    gas: ModuleType, gas_left: int, reservoir: int, charges: List[int]
) -> None:
    """
    Refunding every state charge in LIFO order restores `gas_left`,
    the reservoir, and the spill to their entry values exactly, and
    `gas_left` never exceeds its entry value along the way.

    Grounding (EIP-8037, normative): "Undoing a state creation
    therefore restores the exact pools the charge drew from, so the
    two pools never drift into one another -- `gas_left` is never
    inflated beyond `TX_MAX_GAS_LIMIT - intrinsic_gas`, and regular
    gas is never permanently stranded in the state-only reservoir."
    Restated by the `credit_state_gas_refund` docstring: "This
    restores the exact pools the charge drew from, so the two never
    drift." Shape: round-trip/inverse. Non-circular: only entry-state
    equality is asserted; no internal splits are recomputed.
    """
    evm = fresh_evm(gas, gas_left, reservoir)
    meter = evm.gas_meter
    applied = []
    for amount in charges:
        if int(meter.gas_left) + int(meter.state_gas_left) < amount:
            continue
        gas.charge_state_gas(evm, Uint(amount))
        applied.append(amount)

    for amount in reversed(applied):
        gas.credit_state_gas_refund(meter, Uint(amount))
        assert int(meter.gas_left) <= gas_left

    assert int(meter.gas_left) == gas_left
    assert int(meter.state_gas_left) == reservoir
    assert int(meter.state_gas_spilled) == 0


@given(
    gas_left=pools(),
    reservoir=pools(),
    charges=op_lists(("regular", "state", "spill")),
)
def test_commit_moves_the_baseline_without_touching_the_pools(
    gas: ModuleType,
    gas_left: int,
    reservoir: int,
    charges: List[Tuple[str, int]],
) -> None:
    """
    After a charges-only prefix (the caller contract: "Only charges
    precede a commit"), a commit folds the spill into the committed
    spill, lowers the baseline to the reservoir, and changes neither
    pool nor the settlement figure.

    Grounding (EELS docstring, self-descriptive -- EIP-8037 has no
    commit concept): "Move the baseline down to the current reservoir
    level and fold the spill into `state_gas_committed_spill`, so
    later refunds route to the reservoir instead of back into
    `gas_left`." Non-circular: asserts what commit must *preserve*
    (pools, `tx_state_gas_used`) alongside the documented moves.
    """
    evm = fresh_evm(gas, gas_left, reservoir)
    apply_ops(gas, evm, charges)
    meter = evm.gas_meter
    before = meter_fields(meter)
    settled_before = gas.tx_state_gas_used(meter, Uint(reservoir))

    gas.commit_state_gas(meter)

    assert int(meter.gas_left) == before[0]
    assert int(meter.state_gas_left) == before[1]
    assert int(meter.state_gas_baseline) == before[1]
    assert int(meter.state_gas_spilled) == 0
    assert int(meter.state_gas_committed_spill) == before[5] + before[4]
    assert gas.tx_state_gas_used(meter, Uint(reservoir)) == settled_before


@given(
    gas_left=pools(),
    reservoir=pools(),
    pre_charges=op_lists(("regular", "state", "spill"), max_size=6),
    commit=st.booleans(),
    post_ops=op_lists(("regular", "state", "spill", "refund")),
    refund_counter=st.integers(min_value=-(1 << 20), max_value=1 << 20),
)
def test_restore_rolls_back_to_the_baseline_only(
    gas: ModuleType,
    gas_left: int,
    reservoir: int,
    pre_charges: List[Tuple[str, int]],
    commit: bool,
    post_ops: List[Tuple[str, int]],
    refund_counter: int,
) -> None:
    """
    A frame rollback returns the outstanding spill to `gas_left`,
    refills the reservoir to the baseline, discards the refund
    counter, and leaves committed state gas charged -- so the
    settlement figure afterwards is exactly the committed draw.

    Grounding (EELS docstrings, restating EIP-8037's halts/reverts
    rule for the uncommitted part): "the [spill] returns to `gas_left`
    first, then the reservoir resets to the baseline. The refunds
    accrued on the undone changes are discarded with them. State gas
    committed as non-refillable stays charged." Sequence mirrors the
    top frame: charges, optional commit (`interpreter.py`), then
    dispatched execution. Non-circular: the settlement equality
    `tx_state_gas_used == (grant - baseline) + committed_spill` is a
    consequence the docstrings imply but the code never states.
    """
    evm = fresh_evm(gas, gas_left, reservoir)
    meter = evm.gas_meter
    apply_ops(gas, evm, pre_charges)
    if commit:
        gas.commit_state_gas(meter)
    apply_ops(gas, evm, post_ops)
    meter.refund_counter = refund_counter
    before = meter_fields(meter)

    gas.restore_state_gas(meter)

    assert int(meter.gas_left) == before[0] + before[4]
    assert int(meter.state_gas_spilled) == 0
    assert int(meter.state_gas_left) == before[2]
    assert int(meter.state_gas_baseline) == before[2]
    assert int(meter.refund_counter) == 0
    assert int(meter.state_gas_committed_spill) == before[5]
    assert (
        gas.tx_state_gas_used(meter, Uint(reservoir))
        == (reservoir - before[2]) + before[5]
    )


@given(
    gas_left=pools(),
    reservoir=pools(),
    ops=op_lists(("regular", "state", "spill", "refund")),
)
def test_halted_frame_leaves_the_reservoir_whole(
    gas: ModuleType,
    gas_left: int,
    reservoir: int,
    ops: List[Tuple[str, int]],
) -> None:
    """
    In an uncommitted frame, the exceptional-halt settlement (restore
    then forfeit) zeroes `gas_left` and leaves the reservoir at
    exactly its frame-entry value.

    Grounding (EIP-8037, normative): "refilling in LIFO order makes
    the reservoir whole automatically ... only the portion refilled to
    `state_gas_reservoir` survives -- which is exactly the reservoir's
    value at the start of the child frame." Settlement order mirrors
    `interpreter.py` (`restore_state_gas` then
    `forfeit_remaining_gas`). Non-circular: the surviving value is the
    externally known frame-entry grant, not a recomputed internal.
    """
    evm = fresh_evm(gas, gas_left, reservoir)
    apply_ops(gas, evm, ops)

    gas.restore_state_gas(evm.gas_meter)
    gas.forfeit_remaining_gas(evm.gas_meter)

    assert int(evm.gas_meter.gas_left) == 0
    assert int(evm.gas_meter.state_gas_left) == reservoir
    assert int(evm.gas_meter.state_gas_spilled) == 0


@given(
    gas_left=pools(),
    reservoir=pools(),
    first_charges=op_lists(("regular", "state", "spill"), max_size=6),
    commit=st.booleans(),
    second_charges=op_lists(("regular", "state", "spill"), max_size=6),
)
def test_restore_to_entry_undoes_the_commit(
    gas: ModuleType,
    gas_left: int,
    reservoir: int,
    first_charges: List[Tuple[str, int]],
    commit: bool,
    second_charges: List[Tuple[str, int]],
) -> None:
    """
    A pre-dispatch failure rolls the meter back to frame entry: every
    state charge refills (committed or not), only the regular charges
    stay paid, and the settlement figure is zero.

    Grounding (EELS docstring, self-descriptive -- EIP-8037 is silent
    on undoing pre-dispatch charges): "every state charge refills --
    all spill, committed or not, returns to `gas_left` -- and the
    baseline resets to the frame's [grant]." Sequence mirrors the
    only caller (`interpreter.py`): set-delegation charges, commit,
    dispatch-preparation charges, no refunds ("no refund accrues
    before dispatch"). Non-circular: the post-state is expressed
    against frame-entry values and the independently summed regular
    charges.
    """
    evm = fresh_evm(gas, gas_left, reservoir)
    meter = evm.gas_meter
    regular_first, _, _ = apply_ops(gas, evm, first_charges)
    if commit:
        gas.commit_state_gas(meter)
    regular_second, _, _ = apply_ops(gas, evm, second_charges)

    gas.restore_state_gas_to_entry(meter, Uint(reservoir))

    assert int(meter.gas_left) == gas_left - regular_first - regular_second
    assert int(meter.state_gas_left) == reservoir
    assert int(meter.state_gas_baseline) == reservoir
    assert int(meter.state_gas_spilled) == 0
    assert int(meter.state_gas_committed_spill) == 0
    assert gas.tx_state_gas_used(meter, Uint(reservoir)) == 0


@given(
    gas_left=pools(),
    reservoir=pools(),
    ops=op_lists(("regular", "state", "spill", "refund")),
)
def test_settlement_matches_an_independent_ledger(
    gas: ModuleType,
    gas_left: int,
    reservoir: int,
    ops: List[Tuple[str, int]],
) -> None:
    """
    `tx_state_gas_used` equals state charges minus state refunds,
    tracked independently while the ops run -- including negative
    nets.

    Grounding (EIP-8037, normative): "State-gas charges increment
    `execution_state_gas_used`" and "State-gas refills decrement
    `execution_state_gas_used`"; the docstring adds "May be negative
    when refunds exceed charges." Non-circular: the ledger is a plain
    running sum kept outside the meter, checked against the
    four-field formula.
    """
    evm = fresh_evm(gas, gas_left, reservoir)
    _, state_charged, refunded = apply_ops(gas, evm, ops)
    assert (
        gas.tx_state_gas_used(evm.gas_meter, Uint(reservoir))
        == state_charged - refunded
    )


class ReservoirModel:
    """
    Independent two-pool model, transcribed from EIP-8037's counter
    rules (charge/refill) and, for the commit that EIP-8037 lacks,
    from the `commit_state_gas` docstring.
    """

    def __init__(self, gas_left: int, reservoir: int) -> None:
        self.gas_left = gas_left
        self.reservoir = reservoir
        self.spilled = 0
        self.committed_spill = 0
        self.baseline = reservoir
        self.refund_counter = 0
        self.net_state = 0

    def charge_regular(self, amount: int) -> None:
        """Regular-gas charges "deduct from `gas_left` only"."""
        self.gas_left -= amount

    def charge_state(self, amount: int) -> None:
        """Deduct from the reservoir first, spill the remainder."""
        from_reservoir = min(amount, self.reservoir)
        remainder = amount - from_reservoir
        self.reservoir -= from_reservoir
        self.gas_left -= remainder
        self.spilled += remainder
        self.net_state += amount

    def credit_refund(self, amount: int) -> None:
        """Refill LIFO: `gas_left` up to the spill, then reservoir."""
        from_gas_left = min(amount, self.spilled)
        self.gas_left += from_gas_left
        self.spilled -= from_gas_left
        self.reservoir += amount - from_gas_left
        self.net_state -= amount

    def commit(self) -> None:
        """Fold spill into committed spill, baseline to reservoir."""
        self.committed_spill += self.spilled
        self.spilled = 0
        self.baseline = self.reservoir


class GasMeterMachine(RuleBasedStateMachine):
    """
    Drive a live frame's `GasMeter` against `ReservoirModel` through
    caller-shaped sequences: a pre-dispatch phase of charges with at
    most one commit, then a dispatched phase that adds refunds and
    refund-counter bumps. Frame settlement (`restore_state_gas` /
    `restore_state_gas_to_entry`) is terminal in real callers and is
    covered by the prefix-generating tests above.
    """

    gas: ModuleType  # set per fork by the factory below

    def __init__(self) -> None:
        super().__init__()
        self.model: ReservoirModel | None = None

    @initialize(gas_left=pools(), reservoir=pools())
    def start_frame(self, gas_left: int, reservoir: int) -> None:
        """Enter a frame: baseline == state_gas_left == grant."""
        self.evm = fresh_evm(self.gas, gas_left, reservoir)
        self.model = ReservoirModel(gas_left, reservoir)
        self.grant_gas = gas_left
        self.grant_state = reservoir
        self.regular_total = 0
        self.dispatched = False
        self.committed = False

    @rule(data=st.data())
    def charge_regular(self, data: st.DataObject) -> None:
        """An affordable regular charge."""
        assert self.model is not None
        avail = self.model.gas_left
        amount = data.draw(
            st.one_of(
                st.sampled_from(sorted({0, avail})),
                st.integers(min_value=0, max_value=avail),
            )
        )
        self.gas.charge_gas(self.evm, Uint(amount))
        self.model.charge_regular(amount)
        self.regular_total += amount

    @rule(data=st.data())
    def charge_state(self, data: st.DataObject) -> None:
        """
        An affordable state charge, boundary-weighted at the
        reservoir edge so both branches are exercised.
        """
        assert self.model is not None
        avail = self.model.gas_left + self.model.reservoir
        edges = {0, avail, min(self.model.reservoir, avail)}
        edges.add(min(self.model.reservoir + 1, avail))
        amount = data.draw(
            st.one_of(
                st.sampled_from(sorted(edges)),
                st.integers(min_value=0, max_value=avail),
            )
        )
        self.gas.charge_state_gas(self.evm, Uint(amount))
        self.model.charge_state(amount)

    @rule(excess=amounts())
    def overcharge_regular(self, excess: int) -> None:
        """An unaffordable regular charge raises and mutates nothing."""
        assert self.model is not None
        before = meter_fields(self.evm.gas_meter)
        amount = self.model.gas_left + 1 + excess
        with pytest.raises(self.gas.OutOfGasError):
            self.gas.charge_gas(self.evm, Uint(amount))
        assert meter_fields(self.evm.gas_meter) == before

    @rule(excess=amounts())
    def overcharge_state(self, excess: int) -> None:
        """An unaffordable state charge raises and mutates nothing."""
        assert self.model is not None
        before = meter_fields(self.evm.gas_meter)
        amount = self.model.gas_left + self.model.reservoir + 1 + excess
        with pytest.raises(self.gas.OutOfGasError):
            self.gas.charge_state_gas(self.evm, Uint(amount))
        assert meter_fields(self.evm.gas_meter) == before

    @precondition(lambda self: not self.dispatched and not self.committed)
    @rule()
    def commit(self) -> None:
        """The top frame's single pre-dispatch commit."""
        assert self.model is not None
        self.gas.commit_state_gas(self.evm.gas_meter)
        self.model.commit()
        self.committed = True

    @precondition(lambda self: not self.dispatched)
    @rule()
    def dispatch(self) -> None:
        """Enter dispatched execution; refunds become possible."""
        self.dispatched = True

    @precondition(lambda self: self.dispatched)
    @rule(data=st.data())
    def credit_refund(self, data: st.DataObject) -> None:
        """
        A refund, boundary-weighted around the current spill (and
        allowed to exceed this frame's own charges).
        """
        assert self.model is not None
        spilled = self.model.spilled
        edges = sorted({0, spilled, spilled + 1, max(spilled - 1, 0)})
        amount = data.draw(
            st.one_of(
                st.sampled_from(edges),
                st.integers(min_value=0, max_value=AMOUNT_BOUND),
            )
        )
        self.gas.credit_state_gas_refund(self.evm.gas_meter, Uint(amount))
        self.model.credit_refund(amount)

    @precondition(lambda self: self.dispatched)
    @rule(delta=st.integers(min_value=-(1 << 16), max_value=1 << 16))
    def bump_refund_counter(self, delta: int) -> None:
        """Opcodes adjust the refund counter directly (storage.py)."""
        assert self.model is not None
        self.evm.gas_meter.refund_counter += delta
        self.model.refund_counter += delta

    @invariant()
    def meter_matches_model(self) -> None:
        """Every meter field agrees with the EIP-transcribed model."""
        if self.model is None:
            return
        assert meter_fields(self.evm.gas_meter) == (
            self.model.gas_left,
            self.model.reservoir,
            self.model.baseline,
            self.model.refund_counter,
            self.model.spilled,
            self.model.committed_spill,
        )

    @invariant()
    def settlement_matches_net_ledger(self) -> None:
        """
        `tx_state_gas_used` equals the model's charges-minus-refills
        counter (`execution_state_gas_used`) at every step.
        """
        if self.model is None:
            return
        assert (
            self.gas.tx_state_gas_used(
                self.evm.gas_meter, Uint(self.grant_state)
            )
            == self.model.net_state
        )

    @invariant()
    def regular_gas_never_drifts(self) -> None:
        """
        EIP-8037: "`gas_left` is never inflated beyond
        `TX_MAX_GAS_LIMIT - intrinsic_gas`, and regular gas is never
        permanently stranded in the state-only reservoir": the regular
        grant is always exactly `gas_left` + spill (outstanding or
        committed) + regular charges.
        """
        if self.model is None:
            return
        meter = self.evm.gas_meter
        assert (
            int(meter.gas_left)
            + int(meter.state_gas_spilled)
            + int(meter.state_gas_committed_spill)
            + self.regular_total
            == self.grant_gas
        )
        assert int(meter.gas_left) <= self.grant_gas

    @invariant()
    def baseline_only_moves_down(self) -> None:
        """
        The baseline starts at the grant and only ever moves down
        (`tx_state_gas_used` precondition comment).
        """
        if self.model is None:
            return
        assert int(self.evm.gas_meter.state_gas_baseline) <= self.grant_state


PROPERTY_TEST_FORKS = ["osaka", "amsterdam"]


@pytest.mark.parametrize("fork_name", PROPERTY_TEST_FORKS)
def test_gas_meter_matches_model(fork_name: str) -> None:
    """The GasMeter matches the reference model across op sequences."""
    gas = importlib.import_module(f"ethereum.forks.{fork_name}.vm.gas")
    if not hasattr(gas, "GasMeter"):
        pytest.skip(f"{fork_name} has no EIP-8037 GasMeter")
    machine = type(
        f"GasMeterMachine_{fork_name}",
        (GasMeterMachine,),
        {"gas": gas},
    )
    run_state_machine_as_test(
        machine,
        settings=settings(max_examples=200, stateful_step_count=40),
    )
