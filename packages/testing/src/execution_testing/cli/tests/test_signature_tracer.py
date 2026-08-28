"""Tests for the layered execution-signature tracer."""

from types import SimpleNamespace

from ethereum.forks.amsterdam.vm.instructions import Ops
from ethereum.trace import EvmStop, OpException, OpStart, PrecompileStart

from execution_testing.evm_tools.t8n.evm_trace.signature import (
    EMPTY_SIGNATURE,
    SignatureTracer,
    merge_signatures,
)


def _evm(depth: int) -> SimpleNamespace:
    return SimpleNamespace(depth=depth)


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
