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
_TRANSIENT = [Op.TLOAD, Op.TSTORE]
_ACCOUNT_INSPECTION = [
    Op.EXTCODESIZE,
    Op.EXTCODEHASH,
    Op.EXTCODECOPY,
    Op.BALANCE,
]
_LOGS = [Op.LOG0, Op.LOG1]
_CREATION = [Op.CREATE, Op.CREATE2]
_MISC = [Op.BLOBHASH, Op.MCOPY]

# Weighted so execution biases toward arithmetic/state work over stack churn.
PALETTE = (
    _ARITHMETIC * 3
    + _MEMORY * 2
    + _STORAGE * 2
    + _ENV * 2
    + _KECCAK
    + _STACK_SHUFFLE * 2
    + _TRANSIENT
    + _ACCOUNT_INSPECTION
    + _LOGS
    + _CREATION
    + _MISC
)

_PRECOMPILE_SLOT_BASE = 0x000
_CALL_SLOT_BASE = 0x100
_EPILOGUE_SLOT = 0x200
_CHARGE_SLOT = 0x300
_WITNESS_RANGE = 0x100  # each witness range spans this many slots


_CALL_KINDS = (Op.CALL, Op.CALLCODE, Op.DELEGATECALL, Op.STATICCALL)
# Weighted toward STATICCALL: value-bearing calls into precompiles are a
# distinct, rarer client code path and one call kind per snippet suffices.
_PRECOMPILE_CALL_KINDS = (Op.STATICCALL, Op.STATICCALL, Op.CALL, Op.CALLCODE)


def _message_call(
    rng: random.Random, target: Optional[int], kind: Op, slot: int
) -> Bytecode:
    """
    Draw a stack-neutral message call of ``kind`` with fuzzed gas, value
    and calldata; ``target`` None means the contract calls itself.

    Gas is drawn from a set that straddles the stipend and typical
    precompile costs, so calls fail about as often as they succeed, and
    value stays small so a transfer only bounces when the caller is really
    unfunded. The success flag and returndata size are written to ``slot``
    and ``slot + 1`` as post-state witnesses.
    """
    size = rng.choice([0, rng.randint(0, 64), rng.randint(0, 256)])
    data = rng.randbytes(size)

    code = Bytecode()
    for offset in range(0, size, 32):
        word = data[offset : offset + 32].ljust(32, b"\x00")
        code += Op.PUSH32(int.from_bytes(word, "big"))
        code += Op.PUSH2(offset)
        code += Op.MSTORE

    # Arguments are pushed so gas ends up on top. retSize is 0 (returndata
    # is read via RETURNDATASIZE, avoiding a memory-return revert).
    code += Op.PUSH1(0)
    code += Op.PUSH1(0)
    code += Op.PUSH2(size)
    code += Op.PUSH1(0)
    if kind in (Op.CALL, Op.CALLCODE):
        code += Op.PUSH2(rng.choice([0, 1, 8, 1000]))
    code += Op.ADDRESS if target is None else Op.PUSH20(target)
    gas = rng.choice([0, 2300, 50_000, None])
    code += Op.GAS if gas is None else Op.PUSH3(gas)
    code += kind

    code += Op.PUSH2(slot)
    code += Op.SSTORE

    code += Op.RETURNDATASIZE
    code += Op.PUSH2(slot + 1)
    code += Op.SSTORE

    return code


def _precompile_call(
    rng: random.Random, precompiles: Sequence[int], slot: int
) -> Bytecode:
    """
    Draw a message call into a precompile with fuzzed input.

    With small probability the target is one past the highest precompile,
    probing the address-range boundary.
    """
    if rng.random() < 0.85:
        address = rng.choice(precompiles)
    else:
        address = max(precompiles) + 1
    return _message_call(
        rng, address, rng.choice(_PRECOMPILE_CALL_KINDS), slot
    )


def _create2_self_copy(rng: random.Random, slot: int) -> Bytecode:
    """
    Write a gas-keyed storage slot, then deploy a copy of this contract's
    own code with ``CREATE2``.

    The copy's initcode is this code, so each deployment recurses until the
    63/64 rule starves it and the deepest frames fail -- many independent
    reverting frames, each having read and written a fresh account's
    storage, in one transaction. The created address is a witness.
    """
    code = Bytecode()
    code += Op.PUSH1(rng.choice([1, 2, 0xFF]))
    code += Op.GAS
    code += Op.SSTORE
    code += Op.CODESIZE
    code += Op.PUSH0
    code += Op.PUSH0
    code += Op.CODECOPY
    code += Op.PUSH2(rng.randrange(0, 0x10000))
    code += Op.CODESIZE
    code += Op.PUSH0
    code += Op.SELFBALANCE if rng.random() < 0.5 else Op.PUSH0
    code += Op.CREATE2
    code += Op.PUSH2(slot)
    code += Op.SSTORE
    return code


def _call_into_destructor(
    rng: random.Random, destructor: int, slot: int
) -> Bytecode:
    """
    Call a helper whose code is ``ORIGIN SELFDESTRUCT``.

    Under ``CALLCODE``/``DELEGATECALL`` the helper's code runs in *this*
    frame's context, so the caller schedules its own destruction; under
    ``CALL`` the helper destroys itself. The success flag is a witness.
    """
    kind = rng.choice([Op.CALLCODE, Op.DELEGATECALL, Op.CALL])
    code = Bytecode()
    code += Op.PUSH0
    code += Op.PUSH0
    code += Op.PUSH0
    code += Op.PUSH0
    if kind in (Op.CALL, Op.CALLCODE):
        code += Op.PUSH0
    code += Op.PUSH20(destructor)
    code += Op.GAS
    code += kind
    code += Op.PUSH2(slot)
    code += Op.SSTORE
    return code


def _halting_child_then_state_charge(
    rng: random.Random, target: int, slot: int
) -> Bytecode:
    """
    Call ``target`` with too little gas for any state work, so the child
    halts, then pay a cold state charge in this frame: a fresh storage
    slot, and a value transfer that creates a fresh account.

    A halted child settled wrongly (state gas credited back instead of
    consumed) only becomes visible when the parent *spends* afterwards.
    """
    code = Bytecode()
    for _ in range(5):
        code += Op.PUSH0
    code += Op.PUSH20(target)
    code += Op.PUSH2(rng.choice([0, 700, 2300]))
    code += Op.CALL
    code += Op.PUSH2(slot)
    code += Op.SSTORE
    code += Op.PUSH1(1)
    code += Op.PUSH2(_CHARGE_SLOT + rng.randrange(0, 0x100))
    code += Op.SSTORE
    for _ in range(4):
        code += Op.PUSH0
    code += Op.PUSH1(1)
    code += Op.PUSH20(0xFEED0000 + rng.randrange(0, 0x1000))
    code += Op.PUSH3(50_000)
    code += Op.CALL
    code += Op.PUSH2(slot + 1)
    code += Op.SSTORE
    return code


def _epilogue() -> Bytecode:
    """
    Record what the frame has left before it ends.

    Every internal gas or return-data divergence then shows in the
    post-state, not only in the block's gas used.
    """
    code = Bytecode()
    code += Op.GAS
    code += Op.PUSH2(_EPILOGUE_SLOT)
    code += Op.SSTORE
    code += Op.RETURNDATASIZE
    code += Op.PUSH2(_EPILOGUE_SLOT + 1)
    code += Op.SSTORE
    code += Op.SELFBALANCE
    code += Op.PUSH2(_EPILOGUE_SLOT + 2)
    code += Op.SSTORE
    return code


def fuzzed_bytecode(
    rng: random.Random,
    *,
    max_ops: int = 40,
    precompiles: Optional[Sequence[int]] = None,
    call_targets: Optional[Sequence[int]] = None,
    selfdestructor: Optional[int] = None,
) -> Bytecode:
    """
    Draw a stack-safe contract body ending in a clean terminator.

    Operands are pushed as needed so most instructions run rather than
    underflow. When ``precompiles`` is given, calls into precompiles are
    injected (and at least one is guaranteed). When ``call_targets`` is
    given, message calls of every kind into those addresses -- and into
    the contract itself, which is how recursion arises -- are injected,
    along with the shapes real consensus bugs have taken: a halting child
    followed by a cold state charge, and ``CREATE2`` self-replication.
    ``selfdestructor`` names a helper whose code is ``ORIGIN SELFDESTRUCT``
    for calls that destroy the caller or the callee. Every body ends with an
    epilogue that stores remaining gas, return-data size and balance.
    Fully determined by ``rng``.
    """
    if 2 * max_ops > _WITNESS_RANGE:
        raise ValueError(
            f"max_ops={max_ops} overflows the witness-slot range: "
            f"2*max_ops must be <= {_WITNESS_RANGE:#x} to keep precompile "
            f"witnesses below the call range (0x100) and call witnesses "
            f"below the epilogue (0x200)"
        )
    code: Bytecode = Bytecode() + Op.JUMPDEST  # harmless leading anchor
    stack_height = 0
    num_ops = rng.randint(1, max_ops)
    witness_slot = _PRECOMPILE_SLOT_BASE
    call_slot = _CALL_SLOT_BASE
    emitted_precompile_call = False

    for _ in range(num_ops):
        if precompiles and rng.random() < 0.15:
            code += _precompile_call(rng, precompiles, witness_slot)
            witness_slot += 2
            emitted_precompile_call = True
            continue
        if call_targets and rng.random() < 0.15:
            target = rng.choice([None, *call_targets])
            code += _message_call(
                rng, target, rng.choice(_CALL_KINDS), call_slot
            )
            call_slot += 2
            continue
        if call_targets and rng.random() < 0.1:
            code += _halting_child_then_state_charge(
                rng, rng.choice(call_targets), call_slot
            )
            call_slot += 2
            continue
        if call_targets and rng.random() < 0.08:
            code += _create2_self_copy(rng, call_slot)
            call_slot += 2
            continue
        if selfdestructor is not None and rng.random() < 0.06:
            code += _call_into_destructor(rng, selfdestructor, call_slot)
            call_slot += 2
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

    code += _epilogue()

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
