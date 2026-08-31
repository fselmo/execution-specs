"""
Witness tests for the state-gas detectors: `child-state-gas-spill` and
`state-gas-from-reservoir`.

Same discipline as the call-entry-oog witnesses (design §8): a detector's
verdict never validates itself.

1. a positive on real EELS execution, cross-checked by a behavioral
   witness the tracer does not produce -- whether the child could
   *afford* its state charge, read off the parent's post-state success
   flag;
2. a near-miss that contains the confusable phenomenon -- the identical
   charge, served whole from a funded reservoir instead of spilled --
   which must not fire;
3. a kill check proving the near-miss discriminates.

The two detectors are each other's control. A charge either comes out of
the reservoir or spills into execution gas, never both, so exactly one of
the two events may fire on any given charge.
"""

from typing import Any, Dict, Tuple

from execution_testing.base_types import Address, Bytes, Hash, HexNumber
from execution_testing.cli.fuzzer_bridge.campaign import fill_case
from execution_testing.cli.fuzzer_bridge.models import (
    FuzzerAccountInput,
    FuzzerOutput,
    FuzzerTransactionInput,
)
from execution_testing.client_clis.clis.execution_specs import (
    ExecutionSpecsTransitionTool,
)
from execution_testing.evm_tools.t8n.evm_trace.signature import Signature
from execution_testing.forks import Amsterdam
from execution_testing.test_types import Environment
from execution_testing.test_types.account_types import EOA
from execution_testing.vm import Bytecode
from execution_testing.vm import Opcodes as Op

SENDER_KEY = Hash((2).to_bytes(32, "big"))
PARENT = 0x20000
CHILD = 0x30000
CHILD_SLOT = 0xC0
SUCCESS_SLOT = 0xD0

_COSTS = Amsterdam.gas_costs()
COLD_WRITE = _COSTS.COLD_STORAGE_ACCESS + _COSTS.STORAGE_SET
_CAP = Amsterdam.transaction_gas_limit_cap()
assert _CAP is not None, "Amsterdam caps transaction execution gas"
CAP = _CAP

# The child is granted enough execution gas to *run* its SSTORE but not
# to *pay* the state charge out of `gas_left`. Which side of the branch
# the charge takes is then the only thing that decides whether it
# survives -- the behavioral witness the tracer does not produce.
STARVED_CHILD_GAS = COLD_WRITE // 2
# Enough to pay the whole charge out of `gas_left`, so an empty
# reservoir spills rather than raising OutOfGasError.
AMPLE_CHILD_GAS = COLD_WRITE * 2


def _child() -> Bytecode:
    """Write a fresh slot, then stop. Costs one cold write of state gas."""
    return Op.PUSH1(1) + Op.PUSH2(CHILD_SLOT) + Op.SSTORE + Op.STOP


def _parent(child_gas: int) -> Bytecode:
    """Call the child, then record whether it succeeded."""
    code = Bytecode()
    for _ in range(4):
        code += Op.PUSH0
    code += Op.PUSH0  # value
    code += Op.PUSH20(CHILD)
    code += Op.PUSH3(child_gas)
    code += Op.CALL
    code += Op.PUSH2(SUCCESS_SLOT)
    code += Op.SSTORE
    return code + Op.STOP


def _fill(
    tx_gas: int, child_gas: int = STARVED_CHILD_GAS
) -> Tuple[Dict[str, Any], Signature]:
    """Fill the same one-tx case at `tx_gas`; return fixture + signature."""
    sender = Address(EOA(key=SENDER_KEY))
    case = FuzzerOutput(
        version="2.0",
        fork=Amsterdam,
        accounts={
            sender: FuzzerAccountInput(
                balance=HexNumber(10**18), private_key=SENDER_KEY
            ),
            Address(PARENT): FuzzerAccountInput(
                balance=HexNumber(0), code=Bytes(bytes(_parent(child_gas)))
            ),
            Address(CHILD): FuzzerAccountInput(
                balance=HexNumber(0), code=Bytes(bytes(_child()))
            ),
        },
        transactions=[
            FuzzerTransactionInput(
                **{"from": sender},
                to=Address(PARENT),
                gas=HexNumber(tx_gas),
                gas_price=HexNumber(10),
                nonce=HexNumber(0),
            )
        ],
        env=Environment(
            fee_recipient=Address(0xC0FFEE),
            gas_limit=60_000_000,
            number=1,
            timestamp=1000,
            prev_randao=Hash(0),
            base_fee_per_gas=7,
        ),
    )
    eels = ExecutionSpecsTransitionTool()
    eels.compute_signature = True
    eels.last_signature = None
    fixture = fill_case(case, Amsterdam, eels)
    assert eels.last_signature is not None
    return fixture, eels.last_signature


def _storage(fixture: Dict[str, Any], address: int) -> Dict[int, int]:
    """Post-state storage of `address` as int->int, format-agnostic."""
    for addr, account in fixture["postState"].items():
        if int(addr, 16) == address:
            return {
                int(key, 16): int(value, 16)
                for key, value in account.get("storage", {}).items()
            }
    return {}


def _success(fixture: Dict[str, Any]) -> int:
    """The parent's record of whether the child returned successfully."""
    return _storage(fixture, PARENT).get(SUCCESS_SLOT, 0)


def test_a_starved_child_cannot_afford_the_charge_without_a_reservoir() -> (
    None
):
    """
    The behavioral witness, established before any event is trusted.

    The child is granted half a cold write of execution gas. With an
    empty reservoir it cannot pay the state charge and dies; funded, the
    reservoir pays and it survives. Post-state alone tells them apart, so
    the tracer is never the evidence for which branch ran.
    """
    starved, _ = _fill(CAP)
    funded, _ = _fill(CAP + COLD_WRITE)
    assert _success(starved) == 0
    assert _storage(starved, CHILD).get(CHILD_SLOT, 0) == 0
    assert _success(funded) == 1
    assert _storage(funded, CHILD).get(CHILD_SLOT, 0) == 1


def test_from_reservoir_fires_only_when_a_user_reservoir_pays() -> None:
    """Positive, with the near-miss being the identical charge spilled."""
    funded, funded_sig = _fill(CAP + COLD_WRITE)
    assert _success(funded) == 1, "behavioral witness: reservoir paid"
    assert "state-gas-from-reservoir" in funded_sig.events

    # Near-miss: the same charge, same code, empty user reservoir. The
    # block's system transaction still carries a reservoir, so an
    # unscoped detector fires here -- that is the confusion under test.
    spilled, spilled_sig = _fill(CAP, child_gas=AMPLE_CHILD_GAS)
    assert _success(spilled) == 1, "the child paid out of execution gas"
    assert "state-gas-from-reservoir" not in spilled_sig.events


def test_spill_fires_only_when_the_reservoir_did_not_cover_the_charge() -> (
    None
):
    """Positive and near-miss for the spill detector, same charge both."""
    spilled, spilled_sig = _fill(CAP, child_gas=AMPLE_CHILD_GAS)
    assert _success(spilled) == 1
    assert "child-state-gas-spill" in spilled_sig.events

    # CD's near-miss: a reservoir that covers the child's state work, so
    # the charge is served whole and nothing spills.
    funded, funded_sig = _fill(CAP + COLD_WRITE, child_gas=AMPLE_CHILD_GAS)
    assert _success(funded) == 1
    assert "child-state-gas-spill" not in funded_sig.events


def test_the_events_are_mutually_exclusive_on_one_charge() -> None:
    """A charge is served from the reservoir or spilled, never both."""
    for tx_gas in (CAP, CAP + COLD_WRITE):
        _, sig = _fill(tx_gas, child_gas=AMPLE_CHILD_GAS)
        both = {"state-gas-from-reservoir", "child-state-gas-spill"}
        assert len(both & sig.events) == 1


def test_dropping_the_user_transaction_scope_turns_the_near_miss_red(
    monkeypatch: Any,
) -> None:
    """
    Kill check: the near-miss discriminates only because the detector
    ignores the system transaction's standing reservoir. Restore the
    unscoped read and the empty-reservoir case fires.
    """
    from execution_testing.evm_tools.t8n.evm_trace import signature as mod

    def unscoped(evm: object) -> int:
        tx_env = getattr(evm, "tx_env", None)
        grant = getattr(tx_env, "state_gas_reservoir", None)
        return int(grant) if grant is not None else 0

    monkeypatch.setattr(mod, "_reservoir_grant", unscoped)
    _, sig = _fill(CAP, child_gas=AMPLE_CHILD_GAS)
    assert "state-gas-from-reservoir" in sig.events, (
        "the broken detector must fire on the empty-reservoir case, "
        "or the near-miss proves nothing"
    )


def test_a_funded_but_untapped_reservoir_does_not_fire_from_reservoir() -> (
    None
):
    """
    The near-miss that occurs naturally in the seed sweep: a transaction
    funds a reservoir and never draws on it. `cap + 1` grants exactly one
    unit, which no charge can cover, so the grant event must fire and the
    draw event must not -- and the charge spills instead.
    """
    fixture, signature = _fill(CAP + 1, child_gas=AMPLE_CHILD_GAS)
    assert _success(fixture) == 1
    assert "state-gas-reservoir" in signature.events
    assert "state-gas-from-reservoir" not in signature.events
    assert "child-state-gas-spill" in signature.events


# The reproducer from nethermind#12965's own regression test, byte for
# byte. A detector aimed at a known client bug is witnessed against that
# bug's reproducer; a construction of ours can only confirm our model of
# it, which is how the previous spill detector passed three witnesses
# while being blind to the shape it was built for.
NETHERMIND_12965_REPRODUCER = bytes.fromhex(
    "5f5f600b5419600b8181553681813030f4833333f1"
)


def _fill_code(code: bytes, tx_gas: int) -> Tuple[Dict[str, Any], Signature]:
    """Fill a one-tx case whose only contract runs `code`."""
    sender = Address(EOA(key=SENDER_KEY))
    case = FuzzerOutput(
        version="2.0",
        fork=Amsterdam,
        accounts={
            sender: FuzzerAccountInput(
                balance=HexNumber(10**18), private_key=SENDER_KEY
            ),
            Address(PARENT): FuzzerAccountInput(
                balance=HexNumber(0), code=Bytes(code)
            ),
        },
        transactions=[
            FuzzerTransactionInput(
                **{"from": sender},
                to=Address(PARENT),
                gas=HexNumber(tx_gas),
                gas_price=HexNumber(10),
                nonce=HexNumber(0),
            )
        ],
        env=Environment(
            fee_recipient=Address(0xC0FFEE),
            gas_limit=60_000_000,
            number=1,
            timestamp=1000,
            prev_randao=Hash(0),
            base_fee_per_gas=7,
        ),
    )
    eels = ExecutionSpecsTransitionTool()
    eels.compute_signature = True
    eels.last_signature = None
    fixture = fill_case(case, Amsterdam, eels)
    assert eels.last_signature is not None
    return fixture, eels.last_signature


def test_the_interleave_fires_on_the_real_reproducer() -> None:
    """
    Positive witness: the client bug's own regression contract.

    It must fire, and it must name the depths -- a spill at one frame
    credited back one frame deeper is the whole claim.
    """
    _, signature = _fill_code(NETHERMIND_12965_REPRODUCER, 200_000)
    assert "state-gas-interleave" in signature.events
    assert (0, 1) in signature.interleavings


def test_a_spill_that_is_never_credited_back_does_not_interleave() -> None:
    """
    Near-miss: a child that spills and halts, with no restoration below
    it. This is exactly what the older `child-state-gas-spill` detector
    fires on, so it is the case that proves the two are different
    claims rather than one event under two names.
    """
    _, signature = _fill(CAP, child_gas=AMPLE_CHILD_GAS)
    assert "child-state-gas-spill" in signature.events
    assert "state-gas-interleave" not in signature.events
    assert not signature.interleavings


def test_dropping_the_depth_pairing_turns_the_near_miss_red(
    monkeypatch: Any,
) -> None:
    """
    Kill check: the near-miss discriminates only because the credit has
    to land one frame below a spill. Accept any credit and the
    spill-then-halt case fires too.
    """
    from execution_testing.evm_tools.t8n.evm_trace import signature as mod

    def unpaired(self: Any, evm: object, depth: int) -> None:
        meter = getattr(evm, "gas_meter", None)
        left = getattr(meter, "state_gas_left", None)
        if left is None:
            return
        previous = self._reservoir_at.get(depth)
        if previous is not None and int(left) > previous:
            self._events.add("state-gas-interleave")
        self._reservoir_at[depth] = int(left)

    monkeypatch.setattr(mod.SignatureTracer, "_fold_state_gas", unpaired)
    _, signature = _fill(CAP, child_gas=AMPLE_CHILD_GAS)
    assert "state-gas-interleave" in signature.events, (
        "the unpaired detector must fire on the near-miss, or the "
        "depth pairing is not what makes it discriminate"
    )
