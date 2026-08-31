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
    models_client_bug: bool = True
    """Whether this shape is a faithful model of the client bug it names.

    A shape set `False` is a **reach probe**: it exercises the mechanism
    but over-approximates the defect, so its kill rate is not coverage of
    that bug and must never be cited as such. Structured rather than
    prose because the calibration column reads it: a probe records "no
    faithful mutant constructible" in place of a number.

    A faithful mutant is not always constructible. Where the client's
    defect has no counterpart in the spec's structure -- nethermind#12965
    was a reservoir snapshot captured at the wrong moment, and the spec
    holds no equivalent variable to mis-time -- every mutation of the
    centralised machinery fires on each frame that touches it. The
    coverage evidence is then the bug's reproducer test, not a rate.
    """


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
            "REACH PROBE, NOT A CLIENT MODEL. State gas a child frame "
            "spilled into execution gas is credited back to the parent's "
            "reservoir when the child halts, instead of being consumed "
            "(EIP-8037). Calibrated against a nethermind build verified "
            "pre-fix at symbol granularity: 35% in-spec kill against 0 "
            "divergences in 2,000 cases, a gap of at least 233x. It "
            "exercises the settlement path but is not the defect of "
            "nethermind#12965, so its rate is not coverage of it -- the "
            "reproducer test in `test_state_gas_witnesses.py` is."
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
        # Calibrated against a nethermind build verified pre-fix at symbol
        # granularity: 35% in-spec kill against 0 divergences in 2,000
        # cases, a gap of at least 233x. It exercises the settlement path
        # but is not the defect, so its rate is not coverage.
        models_client_bug=False,
    ),
    "halt-spill-to-reservoir": Shape(
        name="halt-spill-to-reservoir",
        description=(
            "REACH PROBE, NOT A CLIENT MODEL. On rollback the outstanding "
            "spill is credited to the state gas reservoir instead of "
            "`gas_left`, so it survives the forfeit that burns a halted "
            "frame's gas and flows back to the parent. Kills 83% of cases "
            "at generator v13 (seeds 9000-9059), which is not coverage of "
            "the spill/credit path and must never be quoted as such: it "
            "is not a model of nethermind#12965. That bug was a reservoir "
            "snapshot captured at the wrong moment, and the spec holds no "
            "equivalent variable to mis-time, so no faithful mutant is "
            "constructible here -- the reproducer test in "
            "`test_state_gas_witnesses.py` is the coverage evidence. Its "
            "one sound use is containment: every case firing "
            "`state-gas-interleave` is killed by it (17/17, none "
            "detected-and-not-killed), so the tag never fires on "
            "something this does not break."
        ),
        edits=(
            Edit(
                module=f"{_AMSTERDAM}/vm/gas.py",
                find=(
                    "    gas_meter.gas_left = ExecutionGas(\n"
                    "        gas_meter.gas_left + "
                    "Uint(gas_meter.state_gas_spilled)\n"
                    "    )\n"
                    "    gas_meter.state_gas_spilled = StateGas(Uint(0))\n"
                    "    gas_meter.state_gas_left = "
                    "gas_meter.state_gas_baseline\n"
                ),
                replace=(
                    "    gas_meter.state_gas_left = StateGas(\n"
                    "        gas_meter.state_gas_baseline\n"
                    "        + gas_meter.state_gas_spilled\n"
                    "    )\n"
                    "    gas_meter.state_gas_spilled = StateGas(Uint(0))\n"
                ),
            ),
        ),
        models_client_bug=False,
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
