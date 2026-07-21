"""
Seeded input strategies shared by the generator and by fuzz-test authors.

The bytecode strategy is *stack-aware*: it tracks a virtual stack height and
pushes operands before each opcode, so generated programs execute real logic
instead of reverting on a stack underflow. Dynamic jumps are excluded because,
without a control-flow model, they almost always land on an invalid
destination and abort.

When a fork's precompile addresses are supplied, the strategy also injects
``STATICCALL``s into precompiles with fuzzed input. Precompiles are a dense
source of cross-client divergence (input parsing, gas schedules, boundary of
the precompile address range), and a bytecode that only runs arithmetic never
reaches them. Each call stores its success flag and returndata size to
storage, so a divergence in either surfaces in the post-state diff (gas
divergence is already caught globally by the transition tool).
"""

import random
from typing import Optional, Sequence

from execution_testing.vm import Bytecode
from execution_testing.vm import Opcodes as Op

_ARITHMETIC = [
    Op.ADD,
    Op.MUL,
    Op.SUB,
    Op.DIV,
    Op.MOD,
    Op.EXP,
    Op.LT,
    Op.GT,
    Op.EQ,
    Op.ISZERO,
    Op.AND,
    Op.OR,
    Op.XOR,
    Op.NOT,
    Op.SHL,
    Op.SHR,
    Op.SAR,
    Op.BYTE,
    Op.SIGNEXTEND,
]
_MEMORY = [Op.MSTORE, Op.MSTORE8, Op.MLOAD, Op.MSIZE]
_STORAGE = [Op.SSTORE, Op.SLOAD]
_ENV = [
    Op.ADDRESS,
    Op.CALLER,
    Op.CALLVALUE,
    Op.ORIGIN,
    Op.GASPRICE,
    Op.NUMBER,
    Op.TIMESTAMP,
    Op.GASLIMIT,
    Op.CHAINID,
    Op.SELFBALANCE,
    Op.CALLDATASIZE,
    Op.CODESIZE,
    Op.GAS,
    Op.BASEFEE,
]
_KECCAK = [Op.SHA3]
_STACK_SHUFFLE = [Op.DUP1, Op.DUP2, Op.SWAP1, Op.SWAP2, Op.POP]

# Weighted so execution biases toward arithmetic/state work over stack churn.
PALETTE = (
    _ARITHMETIC * 3
    + _MEMORY * 2
    + _STORAGE * 2
    + _ENV * 2
    + _KECCAK
    + _STACK_SHUFFLE * 2
)


def _precompile_call(
    rng: random.Random, precompiles: Sequence[int], slot: int
) -> Bytecode:
    """
    Draw a stack-neutral ``STATICCALL`` into a precompile with fuzzed input.

    The call's success flag and returndata size are written to ``slot`` and
    ``slot + 1`` as post-state witnesses. With small probability the target is
    one past the highest precompile, probing the address-range boundary. The
    snippet's net stack effect is zero, so it composes with the caller's
    stack-height tracking.
    """
    if rng.random() < 0.85:
        address = rng.choice(precompiles)
    else:
        address = max(precompiles) + 1

    size = rng.choice(
        [rng.randint(0, 32), rng.randint(0, 96), rng.randint(0, 256)]
    )
    data = rng.randbytes(size)

    code = Bytecode()
    for offset in range(0, size, 32):
        word = data[offset : offset + 32].ljust(32, b"\x00")
        code += Op.PUSH32(int.from_bytes(word, "big"))
        code += Op.PUSH2(offset)
        code += Op.MSTORE

    # STATICCALL(gas, addr, argsOffset, argsSize, retOffset, retSize); push
    # the arguments so gas ends up on top. retSize is 0 (returndata is read
    # via RETURNDATASIZE, avoiding a memory-return revert).
    code += Op.PUSH1(0)
    code += Op.PUSH1(0)
    code += Op.PUSH2(size)
    code += Op.PUSH1(0)
    code += Op.PUSH20(address)
    code += Op.GAS
    code += Op.STATICCALL

    code += Op.PUSH2(slot)
    code += Op.SSTORE

    code += Op.RETURNDATASIZE
    code += Op.PUSH2(slot + 1)
    code += Op.SSTORE

    return code


def fuzzed_bytecode(
    rng: random.Random,
    *,
    max_ops: int = 40,
    precompiles: Optional[Sequence[int]] = None,
) -> Bytecode:
    """
    Draw a stack-safe contract body ending in a clean terminator.

    Operands are pushed as needed so most instructions run rather than
    underflow. When ``precompiles`` is given, ``STATICCALL``s into precompiles
    are injected (and at least one is guaranteed). Fully determined by ``rng``.
    """
    code: Bytecode = Bytecode() + Op.JUMPDEST  # harmless leading anchor
    stack_height = 0
    num_ops = rng.randint(1, max_ops)
    witness_slot = 0
    emitted_precompile_call = False

    for _ in range(num_ops):
        if precompiles and rng.random() < 0.15:
            code += _precompile_call(rng, precompiles, witness_slot)
            witness_slot += 2
            emitted_precompile_call = True
            continue
        op = rng.choice(PALETTE)
        while stack_height < op.min_stack_height:
            code += Op.PUSH32(rng.getrandbits(256))
            stack_height += 1
        code += op
        stack_height += op.pushed_stack_items - op.popped_stack_items
        if stack_height > 900:
            code += Op.POP
            stack_height -= 1

    if precompiles and not emitted_precompile_call:
        code += _precompile_call(rng, precompiles, witness_slot)

    terminator = rng.choice([Op.STOP, Op.RETURN, Op.REVERT])
    if terminator in (Op.RETURN, Op.REVERT):
        while stack_height < 2:
            code += Op.PUSH1(0)
            stack_height += 1
        code += terminator
    else:
        code += Op.STOP

    return code


def fuzzed_calldata(rng: random.Random, *, max_size: int = 64) -> bytes:
    """Draw a random calldata payload of up to ``max_size`` bytes."""
    return rng.randbytes(rng.randint(0, max_size))
