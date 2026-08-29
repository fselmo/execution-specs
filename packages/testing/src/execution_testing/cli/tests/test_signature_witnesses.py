"""
Witness tests for the call-entry-oog detector: the fail-proof template.

The discipline (design §8): a detector's own verdict never validates
itself. Each claim carries three witnesses, none trusting the detector's
output:

1. a positive on real EELS execution, cross-checked by a behavioral
   witness the tracer does not produce -- post-state storage that reverts
   iff the parent frame really died at the call;
2. near-misses that *contain* the confusable phenomenon (a child OOG, a
   precompile-internal OOG -- asserted present via the frame cells) and
   must not fire;
3. a kill check proving the near-miss discriminates: the broken predicate
   (any OOG, window dropped) turns it red.
"""

from typing import Any, Dict, Optional, Tuple

import pytest

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

SENDER_KEY = Hash((1).to_bytes(32, "big"))
PARENT = 0x20000
CHILD = 0x30000
BEFORE_SLOT = 0xA0
AFTER_SLOT = 0xB0
# Generous: two fresh-slot writes under state-creation pricing plus a
# cold call, yet six orders below the positive case's 2**30 expansion.
TX_GAS = 1_000_000


def _fill(
    parent_code: Bytecode, child_code: Optional[Bytecode] = None
) -> Tuple[Dict[str, Any], Signature]:
    """Fill a one-tx case through real EELS; return fixture + signature."""
    if child_code is None:
        child_code = Bytecode()
    sender = Address(EOA(key=SENDER_KEY))
    accounts = {
        sender: FuzzerAccountInput(
            balance=HexNumber(10**18), private_key=SENDER_KEY
        ),
        Address(PARENT): FuzzerAccountInput(
            balance=HexNumber(0), code=Bytes(bytes(parent_code))
        ),
        Address(CHILD): FuzzerAccountInput(
            balance=HexNumber(0), code=Bytes(bytes(child_code))
        ),
    }
    case = FuzzerOutput(
        version="2.0",
        fork=Amsterdam,
        accounts=accounts,
        transactions=[
            FuzzerTransactionInput(
                **{"from": sender},
                to=Address(PARENT),
                gas=HexNumber(TX_GAS),
                gas_price=HexNumber(10),
                nonce=HexNumber(0),
            )
        ],
        env=Environment(
            fee_recipient=Address(0xC0FFEE),
            gas_limit=30_000_000,
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
    """Post-state storage of ``address`` as int->int, format-agnostic."""
    for addr, account in fixture["postState"].items():
        if int(addr, 16) == address:
            return {
                int(key, 16): int(value, 16)
                for key, value in account.get("storage", {}).items()
            }
    return {}


def _store_before() -> Bytecode:
    return Op.PUSH1(1) + Op.PUSH2(BEFORE_SLOT) + Op.SSTORE


def _store_after() -> Bytecode:
    return Op.PUSH1(1) + Op.PUSH2(AFTER_SLOT) + Op.SSTORE


def _entry_oog_parent() -> Bytecode:
    """Store a witness, then die charging a CALL's memory expansion."""
    code = _store_before()
    code += Op.PUSH32(2**30)  # retSize: expansion cost dwarfs the tx gas
    code += Op.PUSH0  # retOffset
    code += Op.PUSH0  # argsSize
    code += Op.PUSH0  # argsOffset
    code += Op.PUSH0  # value
    code += Op.PUSH20(CHILD)
    code += Op.PUSH3(50_000)  # the grant is irrelevant: the charge dies
    code += Op.CALL
    return code + _store_after() + Op.STOP


def _child_oog_case() -> Tuple[Bytecode, Bytecode]:
    """A call that enters a child which then OOGs on its own SSTORE."""
    costs = Amsterdam.gas_costs()
    child = Op.PUSH1(1) + Op.PUSH1(1) + Op.SSTORE + Op.STOP
    parent = _store_before()
    for _ in range(5):
        parent += Op.PUSH0
    parent += Op.PUSH20(CHILD)
    # A zero-value call grants exactly the stipend: the child's SSTORE is
    # then forbidden (EIP-2200) and the child, not the caller, OOGs.
    parent += Op.PUSH2(costs.CALL_STIPEND)
    parent += Op.CALL + Op.POP
    return parent + _store_after() + Op.STOP, child


def test_call_entry_oog_fires_with_the_reverted_frame_as_witness() -> None:
    """
    Positive: the pre-call write is absent from the post-state (the frame
    really died at the call) -- the behavioral witness -- and the tracer's
    verdict agrees.
    """
    fixture, signature = _fill(_entry_oog_parent())
    stored = _storage(fixture, PARENT)
    assert BEFORE_SLOT not in stored and AFTER_SLOT not in stored
    assert (0, "halt", "OutOfGasError") in signature.frames
    assert "call-entry-oog" in signature.events


def test_child_oog_is_not_call_entry_oog() -> None:
    """
    Near-miss: the child OOGs (asserted via its frame cell, so the test
    cannot pass vacuously) while the caller survives -- both post-state
    witnesses commit -- and the event must not fire.
    """
    parent, child = _child_oog_case()
    fixture, signature = _fill(parent, child)
    assert (1, "halt", "OutOfGasError") in signature.frames
    assert "call-entry-oog" not in signature.events
    stored = _storage(fixture, PARENT)
    assert stored.get(BEFORE_SLOT) == 1 and stored.get(AFTER_SLOT) == 1


def test_precompile_internal_oog_is_not_call_entry_oog() -> None:
    """
    Near-miss: a precompile OOGs on its own base cost after the call
    entered it; the caller survives and the event must not fire.
    """
    costs = Amsterdam.gas_costs()
    parent = _store_before()
    parent += Op.PUSH0 + Op.PUSH0 + Op.PUSH1(32) + Op.PUSH0
    parent += Op.PUSH20(2)  # SHA256
    parent += Op.PUSH2(costs.PRECOMPILE_SHA256_BASE - 1)
    parent += Op.STATICCALL + Op.POP
    parent += _store_after() + Op.STOP
    fixture, signature = _fill(parent)
    assert "precompile" in signature.events
    assert (1, "halt", "OutOfGasError") in signature.frames
    assert "call-entry-oog" not in signature.events
    assert _storage(fixture, PARENT).get(AFTER_SLOT) == 1


def test_the_near_miss_catches_a_broken_any_oog_detector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Kill check: drop the pending window (fire on any OutOfGasError) and
    the child-OOG near-miss must go red -- proof the witnesses have teeth.
    """
    from execution_testing.evm_tools.t8n.evm_trace import signature as mod

    class BrokenTracer(mod.SignatureTracer):
        def _entry_oog(self, error_kind: str) -> bool:
            return error_kind == "OutOfGasError"

    monkeypatch.setattr(mod, "SignatureTracer", BrokenTracer)
    parent, child = _child_oog_case()
    _, signature = _fill(parent, child)
    assert "call-entry-oog" in signature.events  # the near-miss would fail
