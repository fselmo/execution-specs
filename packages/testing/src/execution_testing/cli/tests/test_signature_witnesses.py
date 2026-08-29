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


# ---- Boundary-halt motifs (design §3.6(e)) --------------------------------
#
# Each motif's claim is "this crafted frame halts with error X". The
# behavioral witness is a pre-halt SSTORE that reverts iff the frame really
# halted; the near-miss is the exact-boundary variant that must survive.

RDC = Op.RETURNDATACOPY
IDENTITY = 4  # the identity precompile echoes its input as returndata


def _identity_returndata(size: int) -> Bytecode:
    """Call identity with ``size`` bytes so returndata is exactly that."""
    code = Op.PUSH0 + Op.PUSH0 + Op.MSTORE  # zero a word of args
    code += Op.PUSH0  # retSize (read via RETURNDATASIZE, not memory)
    code += Op.PUSH0  # retOffset
    code += Op.PUSH1(size)  # argsSize
    code += Op.PUSH0  # argsOffset
    code += Op.PUSH20(IDENTITY)
    code += Op.GAS
    return code + Op.STATICCALL + Op.POP


def _returndatacopy_at(offset_past: int) -> Bytecode:
    """RETURNDATACOPY of RETURNDATASIZE + ``offset_past`` bytes."""
    code = Bytecode() + Op.RETURNDATASIZE
    if offset_past:
        code += Op.PUSH1(offset_past) + Op.ADD
    code += Op.PUSH0 + Op.PUSH0 + RDC
    return code


def test_returndata_overread_halts_one_past_the_boundary() -> None:
    """
    Positive + near-miss in one: copy exactly to the returndata boundary
    survives (its post-write commits); one byte past halts the frame
    (its pre-write reverts). The tracer records the OutOfBoundsRead.
    """
    exact = _store_before() + _identity_returndata(32)
    exact += _returndatacopy_at(0) + _store_after() + Op.STOP
    fixture, signature = _fill(exact)
    stored = _storage(fixture, PARENT)
    assert stored.get(BEFORE_SLOT) == 1 and stored.get(AFTER_SLOT) == 1

    over = _store_before() + _identity_returndata(32)
    over += _returndatacopy_at(1) + _store_after() + Op.STOP
    fixture, signature = _fill(over)
    stored = _storage(fixture, PARENT)
    assert BEFORE_SLOT not in stored and AFTER_SLOT not in stored
    assert (0, "halt", "OutOfBoundsRead") in signature.frames


def _create_ef(prefix_at: int) -> Bytecode:
    """
    CREATE initcode returning code with 0xEF at byte ``prefix_at``.

    ``prefix_at == 0`` is rejected (InvalidContractPrefix); byte 1 (a
    0x00 0xEF body) deploys, the near-miss.
    """
    if prefix_at == 0:
        body = Op.PUSH1(0xEF) + Op.PUSH0 + Op.MSTORE8 + Op.PUSH1(1)
    else:
        body = Op.PUSH1(0xEF) + Op.PUSH1(1) + Op.MSTORE8 + Op.PUSH1(2)
    initcode = body + Op.PUSH0 + Op.RETURN
    # Deploy the initcode: store it left-aligned, CREATE over its length.
    packed = int.from_bytes(bytes(initcode).ljust(32, b"\x00"), "big")
    code = Op.PUSH32(packed) + Op.PUSH0 + Op.MSTORE
    code += Op.PUSH1(len(bytes(initcode)))  # size
    code += Op.PUSH0  # offset
    code += Op.PUSH0  # value
    code += Op.CREATE
    code += Op.PUSH2(0xC0) + Op.SSTORE  # store the CREATE result
    return code


def test_initcode_ef_prefix_is_rejected_at_byte_zero_only() -> None:
    """
    Near-miss at byte 1: 0xEF one byte in deploys (CREATE returns an
    address); 0xEF at byte 0 is rejected (CREATE returns 0, no code).

    The claim is behavioral only: the spec raises InvalidContractPrefix
    in process_create_message's finalization, which -- unlike the
    execute_code loop -- emits no OpException, so the tracer cannot see
    it (see unreachable_on_fork). The witness is CREATE's own result.
    """
    fixture, _ = _fill(_create_ef(prefix_at=1) + Op.STOP)
    assert _storage(fixture, PARENT).get(0xC0, 0) != 0  # deployed

    fixture, _ = _fill(_create_ef(prefix_at=0) + Op.STOP)
    assert _storage(fixture, PARENT).get(0xC0, 0) == 0  # rejected, no address


def _pushes(count: int) -> Bytecode:
    code = Bytecode()
    for _ in range(count):
        code += Op.PUSH0
    return code


def test_stack_bomb_overflows_at_1025_not_1024() -> None:
    """
    Near-miss at exactly the ceiling: 1024 pushes survive (post-write
    commits); 1025 overflow the frame (pre-write reverts). Analytic
    witness: the halting body carries exactly 1025 PUSH0 opcodes.
    """
    # 1024 pushes leave the stack exactly full, so nothing may push after;
    # reaching STOP proves the ceiling was not crossed.
    full = _store_before() + _pushes(1024) + Op.STOP
    fixture, _ = _fill(full)
    assert _storage(fixture, PARENT).get(BEFORE_SLOT) == 1

    bomb_body = _pushes(1025)
    assert bytes(bomb_body).count(0x5F) == 1025  # analytic witness
    over = _store_before() + bomb_body
    fixture, signature = _fill(over)
    assert BEFORE_SLOT not in _storage(fixture, PARENT)
    assert (0, "halt", "StackOverflowError") in signature.frames
