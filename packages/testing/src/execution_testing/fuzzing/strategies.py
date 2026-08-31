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

from .domains import GENERIC_DOMAINS, ValueDomains

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
    rng: random.Random,
    domains: ValueDomains,
    target: Optional[int],
    kind: Op,
    slot: int,
) -> Bytecode:
    """
    Draw a stack-neutral message call of ``kind`` with fuzzed gas, value
    and calldata; ``target`` None means the contract calls itself.

    Gas, value and calldata size come from ``domains``: four-mode
    mixtures over the fork's own boundary sets, so calls fail about as
    often as they succeed and the edges move with a reprice. The success
    flag and returndata size are written to ``slot`` and ``slot + 1`` as
    post-state witnesses.
    """
    size = domains.byte_size(rng)
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
        code += Op.PUSH32(domains.call_value(rng))
    code += Op.ADDRESS if target is None else Op.PUSH20(target)
    gas = domains.call_gas(rng)
    code += Op.GAS if gas is None else Op.PUSH32(gas)
    code += kind

    code += Op.PUSH2(slot)
    code += Op.SSTORE

    code += Op.RETURNDATASIZE
    code += Op.PUSH2(slot + 1)
    code += Op.SSTORE

    return code


def _precompile_call(
    rng: random.Random,
    domains: ValueDomains,
    precompiles: Sequence[int],
    slot: int,
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
        rng, domains, address, rng.choice(_PRECOMPILE_CALL_KINDS), slot
    )


def _create2_self_copy(
    rng: random.Random, domains: ValueDomains, slot: int
) -> Bytecode:
    """
    Write a gas-keyed storage slot, then deploy a copy of this contract's
    own code with ``CREATE2``.

    The copy's initcode is this code, so each deployment recurses until the
    63/64 rule starves it and the deepest frames fail -- many independent
    reverting frames, each having read and written a fresh account's
    storage, in one transaction. The created address is a witness. The
    salt comes from a tiny domain, so repeated deployments collide by
    construction.
    """
    code = Bytecode()
    code += Op.PUSH1(rng.choice([1, 2, 0xFF]))
    code += Op.GAS
    code += Op.SSTORE
    code += Op.CODESIZE
    code += Op.PUSH0
    code += Op.PUSH0
    code += Op.CODECOPY
    code += Op.PUSH2(rng.choice(domains.salt_domain))
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
    rng: random.Random,
    domains: ValueDomains,
    spiller: int,
    slot: int,
) -> Bytecode:
    """
    Call a helper that charges state gas and *then* halts exceptionally,
    and pay a cold state charge in this frame afterwards.

    The child must be able to *afford* its state charge: a charge that
    the frame cannot cover raises `OutOfGasError` before any spill is
    recorded, and a frame that never spilled cannot witness the
    settlement rule at all. So the call is funded generously -- the
    opposite of starving it -- and the helper (`SPILLER_CODE`) does one
    SSTORE before running onto an undefined byte.

    The halt must be exceptional, not a REVERT: only the exceptional
    path forfeits the frame's gas, and the rule under test is that the
    spill is consumed there rather than handed back to the parent. A
    wrongly-settled child only becomes visible when the parent *spends*
    afterwards, so a fresh storage slot and an account-creating value
    transfer follow the call.
    """
    code = Bytecode()
    for _ in range(5):
        code += Op.PUSH0
    code += Op.PUSH20(spiller)
    code += Op.PUSH3(rng.choice(domains.spill_gas))
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


def interleaving_spill_code(rng: random.Random) -> bytes:
    """
    Body of the interleaving helper: flip one slot, recurse, then halt.

    Shaped after nethermind#12965's regression reproducer. `ADDRESS`
    supplies the gas operand, which is far more than the frame holds, so
    the recursion runs until gas is exhausted rather than to a fixed
    depth. The trailing `CALL` reuses the all-ones value as a memory-size
    operand, so its expansion overflows and the frame halts exceptionally
    on unwind -- the settlement the rule under test governs.

    Only the slot varies. The stack discipline is what makes the
    alternation land, so the shape stays fixed until the motif is shown
    to fire.
    """
    slot = rng.choice((0x0B, 0x17, 0x2F, 0x41))
    code = Bytecode()
    code += Op.PUSH0
    code += Op.PUSH0
    code += Op.PUSH1(slot)
    code += Op.SLOAD
    code += Op.NOT
    code += Op.PUSH1(slot)
    code += Op.DUP2
    code += Op.DUP2
    code += Op.SSTORE
    code += Op.CALLDATASIZE
    code += Op.DUP2
    code += Op.DUP2
    code += Op.ADDRESS
    code += Op.ADDRESS
    code += Op.DELEGATECALL
    code += Op.DUP4
    code += Op.CALLER
    code += Op.CALLER
    code += Op.CALL
    return bytes(code)


def _alternating_spill_chain(
    rng: random.Random, domains: ValueDomains, interleaver: int, slot: int
) -> Bytecode:
    """Call the interleaving helper, then witness that it returned."""
    code = Bytecode()
    for _ in range(4):
        code += Op.PUSH0
    code += Op.PUSH0
    code += Op.PUSH20(interleaver)
    code += Op.PUSH3(rng.choice(domains.spill_gas))
    code += Op.CALL
    code += Op.PUSH2(slot)
    code += Op.SSTORE
    return code


_TERMINATOR_KINDS = (Op.RETURN, Op.REVERT, Op.INVALID, Op.SELFDESTRUCT)

# A raw walk byte is a deliberately unconditioned opcode: undefined bytes
# (InvalidOpcode), defined ops over a thin stack (StackUnderflow), a bare
# JUMP onto garbage (InvalidJumpDest). PUSH opcodes are excluded so the
# byte never swallows the epilogue witnesses that follow as immediate data.
_RAW_WALK_BYTES = tuple(b for b in range(256) if not 0x60 <= b <= 0x7F)


def _early_terminator(
    rng: random.Random,
    domains: ValueDomains,
    call_targets: Optional[Sequence[int]],
) -> Bytecode:
    """
    End the frame mid-walk: RETURN/REVERT over a drawn span, INVALID, or
    SELFDESTRUCT to a pool address (the contract itself without a pool).
    """
    kind = rng.choice(_TERMINATOR_KINDS)
    code = Bytecode()
    if kind in (Op.RETURN, Op.REVERT):
        code += Op.PUSH2(domains.byte_size(rng))
        code += Op.PUSH0
        code += kind
    elif kind == Op.INVALID:
        code += Op.INVALID
    elif call_targets:
        code += Op.PUSH20(rng.choice(call_targets))
        code += Op.SELFDESTRUCT
    else:
        code += Op.ADDRESS
        code += Op.SELFDESTRUCT
    return code


_EF_INITCODE = 0x60EF5F5360015FF3
"""``PUSH1 0xEF; PUSH0; MSTORE8; PUSH1 1; PUSH0; RETURN`` -- initcode that
returns the single byte 0xEF, the EOF-reserved prefix a deploy must reject."""

_STACK_LIMIT = 1024  # EIP-3860 era stack ceiling; the 1025th push overflows


def _returndata_overread(slot: int) -> Bytecode:
    """
    Copy one byte past the current returndata, halting the frame.

    ``RETURNDATASIZE + 1`` is exactly one past whatever the last call
    returned (empty when none has), so the boundary check fails by one --
    the edge the historical splits lived at, not a deep overrun. The
    pre-copy witness rolls back, proving the frame halted here.
    """
    code = Bytecode()
    code += Op.PUSH1(1)
    code += Op.PUSH2(slot)
    code += Op.SSTORE  # a marker that survives iff the copy does not halt
    code += Op.RETURNDATASIZE
    code += Op.PUSH1(1)
    code += Op.ADD  # size = returndatasize + 1
    code += Op.PUSH0  # offset into returndata
    code += Op.PUSH0  # destination in memory
    code += Op.RETURNDATACOPY
    return code


def _initcode_ef_prefix(slot: int) -> Bytecode:
    """
    ``CREATE`` initcode that returns 0xEF-prefixed code -- rejected.

    ``CREATE`` pushes zero and no code is deployed; the caller survives,
    so the stored result is the behavioral witness (0 on rejection). The
    signature cannot witness the rejection -- the spec raises
    InvalidContractPrefix in create finalization, off the trace stream --
    so this motif earns its keep in the client differential, where the
    0xEF-initcode path has historically split implementations.
    """
    code = Bytecode()
    code += Op.PUSH8(_EF_INITCODE)
    code += Op.PUSH0
    code += Op.MSTORE  # initcode right-aligned in mem[0..32): bytes [24, 32)
    code += Op.PUSH1(8)  # size
    code += Op.PUSH1(24)  # offset
    code += Op.PUSH0  # value
    code += Op.CREATE
    code += Op.PUSH2(slot)
    code += Op.SSTORE
    return code


def _stack_bomb(slot: int) -> Bytecode:
    """
    Push past the 1024 stack ceiling, halting the frame on overflow.

    Exactly ``_STACK_LIMIT + 1`` pushes overflow from any starting height;
    the pre-bomb witness rolls back, proving the frame halted. The push
    count is fixed, so a test can assert it analytically.
    """
    code = Bytecode()
    code += Op.PUSH1(1)
    code += Op.PUSH2(slot)
    code += Op.SSTORE
    for _ in range(_STACK_LIMIT + 1):
        code += Op.PUSH0
    return code


def _bad_jump(slot: int) -> Bytecode:
    """
    ``JUMP`` onto a 0x5B byte that sits inside PUSH data -- rejected.

    A real JUMPDEST (a 0x5B *opcode*) is a valid target; a 0x5B that is a
    PUSH immediate is not, and jumpdest-analysis bugs have split clients
    at exactly that distinction. ``PC`` makes the target position-
    independent: from the ``PC`` opcode at offset X the layout is
    ``PC, PUSH1 6, ADD, JUMP, PUSH1 0x5B``, so the jump targets X+6 -- the
    0x5B held as PUSH data. The pre-jump witness rolls back on the halt.
    """
    code = Bytecode()
    code += Op.PUSH1(1)
    code += Op.PUSH2(slot)
    code += Op.SSTORE
    code += Op.PC
    code += Op.PUSH1(6)
    code += Op.ADD
    code += Op.JUMP
    code += Op.PUSH1(0x5B)
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
    spiller: Optional[int] = None,
    interleaver: Optional[int] = None,
    domains: Optional[ValueDomains] = None,
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
    for calls that destroy the caller or the callee. ``spiller`` names a
    helper that charges state gas and then halts exceptionally, so a
    child frame settles a halt with an outstanding spill. ``domains`` supplies
    the value mixtures, fork-derived boundary sets and walk-action
    weights (fork-free generic defaults when omitted). Halt kind is a
    first-class action: a body may end early in RETURN, REVERT, INVALID
    or SELFDESTRUCT -- skipping the epilogue, the early halt being the
    observation -- and a low-weight raw byte emits one unconditioned
    opcode: undefined bytes and stack underflows on purpose. Every body
    that runs its full walk ends with an epilogue that stores remaining
    gas, return-data size and balance. Fully determined by ``rng``.
    """
    if 2 * max_ops > _WITNESS_RANGE:
        raise ValueError(
            f"max_ops={max_ops} overflows the witness-slot range: "
            f"2*max_ops must be <= {_WITNESS_RANGE:#x} to keep precompile "
            f"witnesses below the call range (0x100) and call witnesses "
            f"below the epilogue (0x200)"
        )
    if domains is None:
        domains = GENERIC_DOMAINS
    code: Bytecode = Bytecode() + Op.JUMPDEST  # harmless leading anchor
    stack_height = 0
    num_ops = rng.randint(1, max_ops)
    witness_slot = _PRECOMPILE_SLOT_BASE
    call_slot = _CALL_SLOT_BASE
    emitted_precompile_call = False
    terminated = False
    walk = domains.walk

    for _ in range(num_ops):
        if precompiles and rng.random() < walk.precompile_call:
            code += _precompile_call(rng, domains, precompiles, witness_slot)
            witness_slot += 2
            emitted_precompile_call = True
            continue
        if call_targets and rng.random() < walk.message_call:
            target = (
                None
                if rng.random() < walk.self_call
                else rng.choice(call_targets)
            )
            code += _message_call(
                rng, domains, target, rng.choice(_CALL_KINDS), call_slot
            )
            call_slot += 2
            continue
        if spiller is not None and rng.random() < walk.halting_child:
            code += _halting_child_then_state_charge(
                rng, domains, spiller, call_slot
            )
            call_slot += 2
            continue
        if call_targets and rng.random() < walk.create2_self_copy:
            code += _create2_self_copy(rng, domains, call_slot)
            call_slot += 2
            continue
        if selfdestructor is not None and rng.random() < walk.destructor_call:
            code += _call_into_destructor(rng, selfdestructor, call_slot)
            call_slot += 2
            continue
        if rng.random() < walk.raw_byte:
            code += bytes([rng.choice(_RAW_WALK_BYTES)])
            continue
        if rng.random() < walk.terminator:
            code += _early_terminator(rng, domains, call_targets)
            terminated = True
            break
        if call_targets and rng.random() < walk.returndata_overread:
            code += _returndata_overread(call_slot)
            call_slot += 1
            terminated = True
            break
        if call_targets and rng.random() < walk.initcode_ef_prefix:
            code += _initcode_ef_prefix(call_slot)
            call_slot += 1
            continue
        if call_targets and rng.random() < walk.stack_bomb:
            code += _stack_bomb(call_slot)
            call_slot += 1
            terminated = True
            break
        if call_targets and rng.random() < walk.bad_jump:
            code += _bad_jump(call_slot)
            call_slot += 1
            terminated = True
            break
        if interleaver is not None and rng.random() < walk.spill_interleave:
            code += _alternating_spill_chain(
                rng, domains, interleaver, call_slot
            )
            call_slot += 2
            continue
        op = rng.choice(PALETTE)
        while stack_height < op.min_stack_height:
            code += Op.PUSH32(domains.operand(rng))
            stack_height += 1
        code += op
        stack_height += op.pushed_stack_items - op.popped_stack_items
        if stack_height > 900:
            code += Op.POP
            stack_height -= 1

    if terminated:
        return code

    # Guarantee one precompile call per body -- but only when the walk was
    # meant to make them (weight > 0); an arm that zeroes the weight wants
    # none, so the fallback must honour that rather than force one.
    if (
        precompiles
        and walk.precompile_call > 0
        and not emitted_precompile_call
    ):
        code += _precompile_call(rng, domains, precompiles, witness_slot)

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


def fuzzed_calldata(
    rng: random.Random,
    *,
    max_size: int = 64,
    domains: Optional[ValueDomains] = None,
) -> bytes:
    """
    Draw a calldata payload of up to ``max_size`` bytes, with sizes
    weighted toward the 32-byte word edges that price calldata.
    """
    if domains is None:
        domains = GENERIC_DOMAINS
    return rng.randbytes(domains.byte_size(rng, cap=max_size))
