"""
Seeded input strategies shared by the generator and by fuzz-test authors.

The bytecode strategy is *stack-aware*: it tracks a virtual stack height and
pushes operands before each opcode, so generated programs execute real logic
instead of reverting on a stack underflow. Dynamic jumps are excluded because,
without a control-flow model, they almost always land on an invalid
destination and abort.
"""

import random

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


def fuzzed_bytecode(rng: random.Random, *, max_ops: int = 40) -> Bytecode:
    """
    Draw a stack-safe contract body ending in a clean terminator.

    Operands are pushed as needed so most instructions run rather than
    underflow. Fully determined by ``rng``.
    """
    code: Bytecode = Bytecode() + Op.JUMPDEST  # harmless leading anchor
    stack_height = 0
    num_ops = rng.randint(1, max_ops)

    for _ in range(num_ops):
        op = rng.choice(PALETTE)
        while stack_height < op.min_stack_height:
            code += Op.PUSH32(rng.getrandbits(256))
            stack_height += 1
        code += op
        stack_height += op.pushed_stack_items - op.popped_stack_items
        if stack_height > 900:
            code += Op.POP
            stack_height -= 1

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
