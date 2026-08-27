"""
Named shape mutants: hand-written models of real bug classes.

An operator-swap mutant asks "would the suite notice a random slip?". A
shape asks a sharper question: "would the generator *reach* this class of
bug?" Each shape is a small, reviewed edit to the spec that reproduces the
mechanism of a bug a client actually shipped -- reads dropped when a child
frame reverts, a failed value-bearing call into a precompile refunded, state
gas credited back along a halt chain -- applied to EELS so that a clean
client plays the correct side and the differential harness must catch the
spec being wrong. The kill rate per shape is the generator's reach for that
class, measured before and after every generator change.

Anchors are exact source text; when the spec moves, the shape fails loudly
rather than silently modelling nothing.
"""

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, Optional, Tuple

from .source import restore_on_signal


@dataclass(frozen=True)
class Edit:
    """One exact-text substitution in a repository file."""

    module: str
    find: str
    replace: str


@dataclass(frozen=True)
class Shape:
    """A named, multi-file bug model."""

    name: str
    description: str
    edits: Tuple[Edit, ...]


class ShapeMismatchError(Exception):
    """A shape's anchor no longer occurs exactly once in its module."""


def repo_root() -> Path:
    """Return the repository root (the nearest ancestor holding `.git`)."""
    for directory in Path(__file__).resolve().parents:
        if (directory / ".git").exists():
            return directory
    raise FileNotFoundError("not inside a git repository")


@contextmanager
def applied(shape: Shape, root: Optional[Path] = None) -> Iterator[None]:
    """
    Apply ``shape`` to the sources under ``root`` for the duration of the
    block, restoring every file afterwards -- on error and on SIGTERM too.
    """
    root = root or repo_root()
    originals: Dict[Path, str] = {}
    try:
        for edit in shape.edits:
            path = root / edit.module
            text = path.read_text()
            originals.setdefault(path, text)
            if text.count(edit.find) != 1:
                raise ShapeMismatchError(
                    f"{shape.name}: anchor occurs "
                    f"{text.count(edit.find)} times in {edit.module}"
                )
            path.write_text(text.replace(edit.find, edit.replace))
        with restore_on_signal(originals):
            yield
    finally:
        for path, text in originals.items():
            path.write_text(text)


_AMSTERDAM = "src/ethereum/forks/amsterdam"

SHAPES: Dict[str, Shape] = {
    "child-read-rollback": Shape(
        name="child-read-rollback",
        description=(
            "Storage reads made in a child frame are rolled back with the "
            "frame when it reverts or halts, so they vanish from the block "
            "access list (erigon, EIP-7928)."
        ),
        edits=(
            Edit(
                module=f"{_AMSTERDAM}/state_tracker.py",
                find="        storage_reads=tx_state.storage_reads,\n",
                replace="        storage_reads=set(tx_state.storage_reads),\n",
            ),
            Edit(
                module=f"{_AMSTERDAM}/vm/interpreter.py",
                find=(
                    "    if evm.error:\n"
                    "        restore_tx_state(tx_state, snapshot)\n"
                    "    return evm\n"
                ),
                replace=(
                    "    if evm.error:\n"
                    "        restore_tx_state(tx_state, snapshot)\n"
                    "        if int(evm.depth) > 0:\n"
                    "            tx_state.storage_reads.clear()\n"
                    "            tx_state.storage_reads.update("
                    "snapshot.storage_reads)\n"
                    "    return evm\n"
                ),
            ),
        ),
    ),
    "child-spill-credit": Shape(
        name="child-spill-credit",
        description=(
            "State gas a child frame spilled into execution gas is credited "
            "back to the parent's reservoir when the child halts, instead of "
            "being consumed (nethermind, EIP-8037)."
        ),
        edits=(
            Edit(
                module=f"{_AMSTERDAM}/vm/interpreter.py",
                find=(
                    "        # the frame gives back, so parents absorb "
                    "unconditionally.\n"
                    "        restore_state_gas(evm.gas_meter)\n"
                    "        forfeit_remaining_gas(evm.gas_meter)\n"
                ),
                replace=(
                    "        # the frame gives back, so parents absorb "
                    "unconditionally.\n"
                    "        spill = evm.gas_meter.state_gas_spilled\n"
                    "        restore_state_gas(evm.gas_meter)\n"
                    "        if int(evm.depth) > 0:\n"
                    "            evm.gas_meter.state_gas_left = StateGas(\n"
                    "                evm.gas_meter.state_gas_left + spill\n"
                    "            )\n"
                    "        forfeit_remaining_gas(evm.gas_meter)\n"
                ),
            ),
            Edit(
                module=f"{_AMSTERDAM}/vm/__init__.py",
                find=(
                    "        assert child_meter.state_gas_left == "
                    "child_meter.state_gas_baseline\n"
                ),
                replace="        pass\n",
            ),
        ),
    ),
    "precompile-value-callcode-refund": Shape(
        name="precompile-value-callcode-refund",
        description=(
            "A value-bearing CALLCODE into a precompile that fails is not "
            "charged: the forwarded gas grant is refunded to the caller "
            "(besu, Amsterdam call pricing)."
        ),
        edits=(
            Edit(
                module=f"{_AMSTERDAM}/vm/instructions/system.py",
                find=(
                    "    incorporate_child(evm, child_evm)\n"
                    "    evm.return_data = child_evm.output\n"
                ),
                replace=(
                    "    incorporate_child(evm, child_evm)\n"
                    "    from ..precompiled_contracts.mapping import ("
                    "PRE_COMPILED_CONTRACTS as _PC)\n"
                    "    if (\n"
                    "        child_evm.error is not None\n"
                    "        and params.value > U256(0)\n"
                    "        and params.to != params.code_address\n"
                    "        and params.code_address in _PC\n"
                    "    ):\n"
                    "        evm.gas_meter.gas_left += params.gas\n"
                    "    evm.return_data = child_evm.output\n"
                ),
            ),
        ),
    ),
}
