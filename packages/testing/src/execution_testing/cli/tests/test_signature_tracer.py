"""Tests for the layered execution-signature tracer."""

from types import SimpleNamespace
from typing import Optional

from ethereum.forks.amsterdam.vm.instructions import Ops
from ethereum.trace import (
    EvmStop,
    OpException,
    OpStart,
    PrecompileStart,
    TransactionEnd,
)

from execution_testing.evm_tools.t8n.evm_trace.signature import (
    EMPTY_SIGNATURE,
    SignatureTracer,
    merge_signatures,
)


def _evm(
    depth: int,
    *,
    gas_left: Optional[int] = None,
    refund: int = 0,
    state_gas_left: int = 0,
    gas_limit: Optional[int] = None,
) -> SimpleNamespace:
    evm = SimpleNamespace(depth=depth)
    if gas_left is not None:
        evm.gas_meter = SimpleNamespace(
            gas_left=gas_left,
            refund_counter=refund,
            state_gas_left=state_gas_left,
        )
    if gas_limit is not None:
        evm.tx_env = SimpleNamespace(gas_limit=gas_limit)
    return evm


def test_records_bigrams_frames_and_events() -> None:
    """A CALL into a reverting child yields frames, a bigram, and events."""
    tracer = SignatureTracer()
    tracer(_evm(0), OpStart(op=Ops.PUSH1))
    tracer(_evm(0), OpStart(op=Ops.CALL))
    tracer(_evm(1), OpStart(op=Ops.SSTORE))
    tracer(_evm(1), EvmStop(op=Ops.REVERT))
    tracer(_evm(0), EvmStop(op=Ops.STOP))
    sig = tracer.signature()
    assert ("PUSH1", "CALL") in sig.bigrams
    assert (0, "call", "CALL") in sig.frames
    assert (1, "halt", "REVERT") in sig.frames
    assert (0, "halt", "STOP") in sig.frames
    assert "revert" in sig.events and "child-revert" in sig.events


def test_op_exception_at_depth_is_a_child_exception() -> None:
    """An OpException below the top frame is a child exception."""
    tracer = SignatureTracer()
    tracer(_evm(2), OpException(error=ValueError("oog")))
    sig = tracer.signature()
    assert (2, "halt", "ValueError") in sig.frames
    assert "child-exception" in sig.events


def test_create_and_precompile_events() -> None:
    """CREATE2 and a precompile call register their L1 tags."""
    tracer = SignatureTracer()
    tracer(_evm(0), OpStart(op=Ops.CREATE2))
    tracer(_evm(1), PrecompileStart(address=b"\x04"))
    events = tracer.signature().events
    assert "create" in events and "precompile" in events


def test_depth_is_bucketed_and_max_depth_is_raw() -> None:
    """L0 buckets depth to >=3 but max_depth keeps the raw reach."""
    tracer = SignatureTracer()
    tracer(_evm(0), OpStart(op=Ops.CALL))
    tracer(_evm(5), EvmStop(op=Ops.STOP))
    sig = tracer.signature()
    assert (3, "halt", "STOP") in sig.frames
    assert sig.max_depth == 5


def test_sstore_stipend_fires_at_the_boundary_not_a_near_miss() -> None:
    """SSTORE at the 2300 stipend fires; one gas above does not."""
    fires = SignatureTracer()
    fires(_evm(0, gas_left=2300), OpStart(op=Ops.SSTORE))
    assert "sstore-stipend" in fires.signature().events
    miss = SignatureTracer()
    miss(_evm(0, gas_left=2301), OpStart(op=Ops.SSTORE))
    assert "sstore-stipend" not in miss.signature().events


def test_refund_clamp_fires_above_the_fifth_not_at_it() -> None:
    """The refund clamp fires when refund exceeds gas_used // 5, not at it."""
    end = TransactionEnd(gas_used=100, output=b"", error=None)
    # gas_used_before_refund = gas_limit - gas_left - state_gas_left = 100
    fires = SignatureTracer()
    fires(_evm(0, gas_left=900, refund=21, gas_limit=1000), end)
    assert "refund-clamp" in fires.signature().events
    miss = SignatureTracer()
    miss(_evm(0, gas_left=900, refund=20, gas_limit=1000), end)
    assert "refund-clamp" not in miss.signature().events


def test_call_depth_limit_fires_at_the_ceiling_not_below() -> None:
    """A call at depth 1024 hits the ceiling; at 1023 it does not."""
    fires = SignatureTracer()
    fires(_evm(1024), OpStart(op=Ops.CALL))
    assert "call-depth-limit" in fires.signature().events
    miss = SignatureTracer()
    miss(_evm(1023), OpStart(op=Ops.CALL))
    assert "call-depth-limit" not in miss.signature().events


def test_merge_unions_layers_and_empty_is_empty() -> None:
    """Merging unions each layer; the empty signature reports empty."""
    assert EMPTY_SIGNATURE.is_empty()
    first = SignatureTracer()
    first(_evm(0), OpStart(op=Ops.ADD))
    first(_evm(0), OpStart(op=Ops.MUL))
    second = SignatureTracer()
    second(_evm(0), OpStart(op=Ops.PUSH1))
    second(_evm(0), OpStart(op=Ops.SSTORE))
    merged = merge_signatures(first.signature(), second.signature())
    assert ("ADD", "MUL") in merged.bigrams
    assert ("PUSH1", "SSTORE") in merged.bigrams
