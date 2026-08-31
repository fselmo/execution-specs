"""
Distribution arms for the pre-registered strategy experiment.

The four arms are weight/config overlays on the *same* v9 generator (weights
are data), so the only variable between them is the distribution, never the
harness. Each arm is a frozen, inspectable ``ValueDomains`` so the server run
records exactly which weights produced which number.

- (a) naive floor -- every walk action off (pure palette) and every value
  drawn full-width uniform; the stack model and the observation epilogue stay
  on (they are the harness/oracle, not a strategy, so dropping them would
  confound "strategies off" with "oracle weakened").
- (b) fixed pools -- exact boundary edges only, no distribution tail; the v9
  walk actions kept.
- (c) goevmlab weights on our actions -- an APPROXIMATION. goevmlab's mixture
  constants transplant cleanly (see the frequency witness), but its walk
  actions do not map one-to-one onto ours (its "call" is zero-value no-data,
  its "create" carries recursive runtime, its "ops" burst is ten random
  well-formed bytes); the action mapping below is a documented approximation,
  the mixture is faithful.
- (d) mixture + boundary -- the v9 default.
"""

from dataclasses import replace
from typing import TYPE_CHECKING

from .domains import (
    MixtureWeights,
    ValueDomains,
    WalkWeights,
    fork_domains,
)

if TYPE_CHECKING:
    from execution_testing.forks import Fork

ARMS = ("a", "b", "c", "d")

BOUNDARY_ONLY = MixtureWeights(zero=0.0, boundary=1.0, small=0.0, full=0.0)
FULL_ONLY = MixtureWeights(zero=0.0, boundary=0.0, small=0.0, full=1.0)

# Arm (a): no walk action fires, so every step falls through to a palette op.
NAIVE_WALK = WalkWeights(
    precompile_call=0.0,
    message_call=0.0,
    halting_child=0.0,
    create2_self_copy=0.0,
    destructor_call=0.0,
    raw_byte=0.0,
    terminator=0.0,
    returndata_overread=0.0,
    initcode_ef_prefix=0.0,
    stack_bomb=0.0,
    bad_jump=0.0,
)


def _goevmlab_mixture(chance_zero: int, chance_small: int) -> MixtureWeights:
    """
    Convert goevmlab's ``randInt(chanceOfZero, chanceOfSmall)`` to a mixture.

    Its two independent bytes give ``p_zero = chance_zero/256`` and
    ``p_small = (1 - p_zero) * chance_small/256``; there is no boundary mode.
    ``full`` closes the distribution exactly.
    """
    zero = chance_zero / 256
    small = (1 - zero) * (chance_small / 256)
    return MixtureWeights(
        zero=zero, boundary=0.0, small=small, full=1 - zero - small
    )


# The verified randInt constants (storage.go / randgen.go): gas favours
# full-width, value favours small, mem offsets/sizes favour zero.
GAS_C = _goevmlab_mixture(0x02, 0x0F)
VALUE_C = _goevmlab_mixture(0x0F, 0xEF)
SIZE_C = _goevmlab_mixture(0x70, 0xEF)

# goevmlab has no separate PUSH-operand distribution; its pushed values are the
# same full-width randInt draws, so operand tracks the gas mixture here.
OPERAND_C = GAS_C

# randCall2200 action weights mapped onto our actions. The unmapped remainder
# (its 10% SSTORE + 10% SLOAD + 30% op-burst = ~50%) is our palette fall-
# through. Our v9-only motifs (halting-child, returndata-overread, initcode-
# ef, stack-bomb, bad-jump, precompile injection) have no goevmlab generic-walk
# equivalent, so they are off.
WALK_C = WalkWeights(
    precompile_call=0.0,
    message_call=0.20,  # ~ their 20% zero-value call
    halting_child=0.0,
    create2_self_copy=0.10,  # ~ their 10% CREATE/CREATE2
    destructor_call=0.05,  # ~ their 5% SELFDESTRUCT
    raw_byte=0.10,  # ~ their 10% raw opcode
    terminator=0.06,  # ~ their ~6% RETURN/REVERT
    returndata_overread=0.0,
    initcode_ef_prefix=0.0,
    stack_bomb=0.0,
    bad_jump=0.0,
)


def arm_domains(fork: "Fork", arm: str) -> ValueDomains:
    """
    Return the frozen ``ValueDomains`` for one arm over ``fork``.

    Arm (d) is the fork default; the rest overlay weights onto it, so the
    fork-derived boundary sets and state domains are identical across arms.
    """
    base = fork_domains(fork)
    if arm == "a":
        return replace(
            base,
            walk=NAIVE_WALK,
            gas_weights=FULL_ONLY,
            value_weights=FULL_ONLY,
            size_weights=FULL_ONLY,
            operand_weights=FULL_ONLY,
        )
    if arm == "b":
        return replace(
            base,
            gas_weights=BOUNDARY_ONLY,
            value_weights=BOUNDARY_ONLY,
            size_weights=BOUNDARY_ONLY,
            operand_weights=BOUNDARY_ONLY,
        )
    if arm == "c":
        return replace(
            base,
            walk=WALK_C,
            gas_weights=GAS_C,
            value_weights=VALUE_C,
            size_weights=SIZE_C,
            operand_weights=OPERAND_C,
        )
    if arm == "d":
        return base
    raise ValueError(f"unknown arm {arm!r}; expected one of {ARMS}")
