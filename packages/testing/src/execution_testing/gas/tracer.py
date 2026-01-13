"""Gas tracer for capturing per-opcode gas costs during EVM execution."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from ethereum.trace import GasAndRefund, OpEnd, OpStart, TraceEvent


@dataclass
class OpcodeGasRecord:
    """Gas record for a single opcode execution."""

    opcode: Enum
    """The opcode that was executed."""

    gas_cost: int
    """Total gas charged for this opcode."""

    pc: int
    """Program counter at the time of execution."""


@dataclass
class GasTracer:
    """
    Tracer that captures gas costs per opcode using the spec's trace API.

    This tracer implements the EvmTracer protocol and can be installed via
    set_evm_trace() to capture gas charges during EVM execution.

    The trace API emits events in this order per opcode:
    1. OpStart(op) - carries the opcode enum
    2. GasAndRefund(gas_cost) - emitted by charge_gas()
    3. OpEnd() - marks completion
    """

    records: List[OpcodeGasRecord] = field(default_factory=list)
    """Per-opcode gas records."""

    _current_op: Optional[Enum] = field(default=None, repr=False)
    _current_pc: int = field(default=0, repr=False)
    _current_gas: int = field(default=0, repr=False)
    _total_gas: int = field(default=0, repr=False)

    def __call__(self, evm: object, event: TraceEvent) -> None:
        """
        Handle trace events from EVM execution.

        Args:
            evm: The EVM instance (fork-specific type)
            event: The trace event being emitted
        """
        if isinstance(event, OpStart):
            # Record the opcode and current PC
            self._current_op = event.op
            self._current_pc = getattr(evm, "pc", 0)
            self._current_gas = 0

        elif isinstance(event, GasAndRefund):
            # Accumulate gas for current opcode
            self._current_gas += event.gas_cost
            self._total_gas += event.gas_cost

        elif isinstance(event, OpEnd):
            # Finalize the opcode record
            if self._current_op is not None:
                self.records.append(
                    OpcodeGasRecord(
                        opcode=self._current_op,
                        gas_cost=self._current_gas,
                        pc=self._current_pc,
                    )
                )
            self._current_op = None

    @property
    def total_gas(self) -> int:
        """Total gas charged across all traced opcodes."""
        return self._total_gas

    def gas_by_opcode(self) -> Dict[str, int]:
        """
        Aggregate gas costs by opcode name.

        Returns:
            Dictionary mapping opcode names to total gas charged.
        """
        result: Dict[str, int] = {}
        for record in self.records:
            name = record.opcode.name
            result[name] = result.get(name, 0) + record.gas_cost
        return result

    def reset(self) -> None:
        """Reset the tracer state for reuse."""
        self.records.clear()
        self._current_op = None
        self._current_pc = 0
        self._current_gas = 0
        self._total_gas = 0
