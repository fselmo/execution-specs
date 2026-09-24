"""
Seeded, reproducible generator of ``FuzzerOutput`` cases.

Every case is fully determined by ``(fork, GENERATOR_VERSION, seed)``, so a
seed alone reproduces a case exactly. Bump ``GENERATOR_VERSION`` whenever the
generation logic changes, so old seeds are never silently reinterpreted.

The bytecode generator is *stack-aware*: it tracks a virtual stack height and
only emits an opcode once enough items are present (pushing operands first
when needed). This keeps generated programs executing real logic instead of
reverting immediately on a stack underflow, which is what makes the corpus
worth running.
"""

import random
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from execution_testing.base_types import (
    Address,
    Bytes,
    Hash,
    HexNumber,
)
from execution_testing.eip_properties import fuzz_precompile_targets
from execution_testing.forks import Fork
from execution_testing.fuzzing import (
    AddressPool,
    ValueDomains,
    fork_domains,
    fuzzed_bytecode,
    fuzzed_calldata,
    interleaving_spill_code,
    mixed_address_pool,
)
from execution_testing.test_types import Environment
from execution_testing.test_types.account_types import EOA
from execution_testing.vm import Bytecode
from execution_testing.vm import Opcodes as Op

from .models import (
    FuzzerAccountInput,
    FuzzerAuthorizationInput,
    FuzzerOutput,
    FuzzerTransactionInput,
    FuzzerWithdrawalInput,
)

# Contract bodies and calldata come from the shared strategy library
# (`execution_testing.fuzzing`), the same helpers test authors use. Bump
# this whenever generation logic changes so old seeds are not silently
# reinterpreted.
GENERATOR_VERSION = 20

AUTHORITY_ACCOUNTS = 3
"""Accounts that exist only to sign EIP-7702 authorizations."""

GENERATED_TX_TYPES: FrozenSet[int] = frozenset({0, 2, 4})
"""EIP-2718 transaction types this generator can emit. The reach map
derives its `no-tx-type` bucket as the fork's types minus this set, so
a type the generator cannot produce is reported as generator-blind with
that reason, rather than silently absent. Widen it in the same commit
that widens generation."""

DESTRUCTOR_ADDRESS = 0x1FFFF
"""Helper contract whose code is `ORIGIN SELFDESTRUCT`."""

INTERLEAVER_ADDRESS = 0x1FFFD
"""Helper whose code recurses into itself through `DELEGATECALL`, flipping
one storage slot between zero and all-ones at every level, and halts
exceptionally on the way out.

Byte-shaped after the reproducer in nethermind#12965's own regression
test, because a detector aimed at a known client bug earns its keep
against that bug's reproducer, not against a construction of ours. The
fresh set at one depth spills its state charge into execution gas; the
restoration one frame deeper credits the reservoir back. A frame then
settles a halt holding state gas it was never charged -- the shape a
spill-in-a-child motif cannot reach, because the restoration refills the
reservoir before the deeper frame ever charges.

It is called, not delegated into: `ADDRESS ADDRESS DELEGATECALL` only
recurses into *this* helper when it runs in its own context.
"""

SPILLER_ADDRESS = 0x1FFFE
"""Helper contract that charges state gas and then halts exceptionally.

It writes a fresh storage slot -- keyed on `GAS`, so repeat calls in one
block keep paying the full set cost rather than rewriting one slot -- and
then runs onto an undefined byte. A frame that charges state gas it could
afford has spilled (the reservoir is empty for any transaction under the
execution-gas cap), and halting exceptionally is the only path that
forfeits the frame's gas: together they are the precondition for the
halt-chain settlement rule of EIP-8037.
"""

FAILER_ADDRESS = 0x1FFFC
"""Helper a transaction targets to fail on purpose.

It reads slots of its own storage, writes other slots of it, and then
REVERTs or runs onto an undefined byte. Every slot is seeded nonzero, so
no write pays state gas and the smallest drawn gas limit usually reaches
the end. Not always: a set-code transaction's authorizations can spend
most of that limit before the failer runs (1 of 104 failer transactions
at v18 ran out of gas that way). Nothing else calls it, so every access
to its storage belongs to a transaction that failed.
"""

FAILER_MAX_PAIRS = 3
"""Most read-then-write pairs the failer runs before it fails."""


def failer_code(
    rng: random.Random, domains: ValueDomains
) -> Tuple[bytes, Dict[HexNumber, HexNumber]]:
    """
    Draw the failer's code and seeded storage.

    Slot `i` is read and slot `pairs + i` is written with the value read
    plus one, for each of the drawn pairs, then the drawn failure ends it.
    """
    pairs = rng.randint(1, FAILER_MAX_PAIRS)
    code = Bytecode()
    for i in range(pairs):
        code += Op.SSTORE(pairs + i, Op.ADD(Op.SLOAD(i), 1))
    outcomes, shares = zip(*domains.failing_tx_outcome_shares, strict=True)
    outcome = rng.choices(outcomes, weights=shares)[0]
    if outcome == "revert":
        code += Op.REVERT(0, 0)
    elif outcome == "exceptional_halt":
        code += Op.INVALID
    else:
        raise ValueError(f"unknown failer outcome {outcome!r}")
    storage = {
        HexNumber(slot): HexNumber(rng.randrange(1, 2**16))
        for slot in range(2 * pairs)
    }
    return bytes(code), storage


TOUCHER_ADDRESS = 0x1FFFB
"""Helper a transaction targets to fail after touching shared accounts.

Where the failer touches only its own storage, the toucher reads and
calls into addresses other transactions in the block send from or to, so
a failed transaction's accesses land in entries other transactions also
produce, at other indices. Its storage touches are its own: SLOAD and
SSTORE act only on the executing contract. Its code is drawn after the
transactions, so it knows whom they touch.
"""


def _toucher_target(
    rng: random.Random,
    domains: ValueDomains,
    pool: List[int],
    others: List[int],
) -> int:
    """Draw one account-level touch's target by its class."""
    classes, shares = zip(*domains.toucher_target_shares, strict=True)
    kind = rng.choices(classes, weights=shares)[0]
    if kind == "self":
        return TOUCHER_ADDRESS
    elif kind == "pool":
        return rng.choice(pool)
    elif kind == "other_tx":
        # With no other transaction in the block, a pool address stands
        # in; the guard's axis counts what was drawn, not what was asked.
        return rng.choice(others or pool)
    raise ValueError(f"unknown toucher target class {kind!r}")


def toucher_code(
    rng: random.Random,
    domains: ValueDomains,
    pool: List[int],
    others: List[int],
) -> Tuple[bytes, Dict[HexNumber, HexNumber]]:
    """
    Draw the toucher's code and seeded storage.

    Each touch pushes its target as a full 20-byte immediate, so the
    guard can read the targets back from the code. Its own slots are
    seeded nonzero, so no write pays state gas.
    """
    code = Bytecode()
    slots = domains.toucher_max_touches
    for _ in range(rng.randint(1, domains.toucher_max_touches)):
        kind = rng.choice(domains.toucher_touch_kinds)
        if kind == "sload":
            code += Op.POP(Op.SLOAD(rng.randrange(slots)))
        elif kind == "sstore":
            code += Op.SSTORE(rng.randrange(slots), rng.randrange(1, 2**16))
        else:
            target = Op.PUSH20(_toucher_target(rng, domains, pool, others))
            if kind == "balance":
                code += Op.POP(Op.BALANCE(target))
            elif kind == "extcodesize":
                code += Op.POP(Op.EXTCODESIZE(target))
            elif kind == "extcodehash":
                code += Op.POP(Op.EXTCODEHASH(target))
            elif kind == "extcodecopy":
                code += Op.EXTCODECOPY(target, 0, 0, 32)
            elif kind == "value_call":
                code += Op.POP(
                    Op.CALL(domains.toucher_call_gas, target, 1, 0, 0, 0, 0)
                )
            else:
                raise ValueError(f"unknown toucher touch {kind!r}")
    outcomes, shares = zip(*domains.failing_tx_outcome_shares, strict=True)
    outcome = rng.choices(outcomes, weights=shares)[0]
    if outcome == "revert":
        code += Op.REVERT(0, 0)
    elif outcome == "exceptional_halt":
        code += Op.INVALID
    else:
        raise ValueError(f"unknown toucher outcome {outcome!r}")
    storage = {
        HexNumber(slot): HexNumber(rng.randrange(1, 2**16))
        for slot in range(slots)
    }
    return bytes(code), storage


STATE_EXHAUSTER_ADDRESS = 0x1FFFA
"""Helper that runs a reservoir-funded transaction out of gas on a state
charge.

Three phases. It writes as many fresh slots as its calldata asks, which
the generator sizes to empty the reservoir, so later state charges spill
into execution gas. It then burns execution gas in bounded calls to
`BURNER_ADDRESS` until `GAS` falls below `STATE_EXHAUST_THRESHOLD`, and
writes one more fresh slot. At that point the store's execution cost is
always affordable and its state cost never is, so the transaction runs
out of gas on the state charge by construction rather than by measuring
or predicting its need.
"""

BURNER_ADDRESS = 0x1FFF9
"""Helper whose code is a single undefined byte: a call to it consumes
exactly the gas forwarded."""

STATE_EXHAUST_BURN = 80_000
"""Gas each burner call forwards."""

STATE_EXHAUST_THRESHOLD = 105_000
"""The burner loop stops once `GAS` is below this. The last burn leaves
between this less one burn and this, which covers the final store's
execution cost and falls short of its state cost."""


def state_exhauster_code() -> bytes:
    """
    The exhauster's code; its first phase's length comes from calldata.

    Phase one writes slots 1..n, n from calldata word 0; phase two calls
    the burner while `GAS` is at least the threshold; phase three writes
    a slot no phase touched.
    """

    def assemble(fill_loop: int, fill_done: int, burn_loop: int) -> Bytecode:
        return (
            Op.PUSH0
            + Op.JUMPDEST  # fill_loop, stack: [i]
            + Op.DUP1
            + Op.CALLDATALOAD(0)
            + Op.GT
            + Op.ISZERO
            + Op.PUSH2(fill_done)
            + Op.JUMPI
            # The counter sits under the value and the addend: DUP3.
            + Op.SSTORE(Op.ADD(Op.DUP3, 1), 1)
            + Op.PUSH1(1)
            + Op.ADD
            + Op.PUSH2(fill_loop)
            + Op.JUMP
            + Op.JUMPDEST  # fill_done
            + Op.POP
            + Op.JUMPDEST  # burn_loop
            + Op.PUSH3(STATE_EXHAUST_THRESHOLD)
            + Op.GAS
            + Op.LT
            + Op.PUSH2(0)  # patched: the final store
            + Op.JUMPI
            + Op.POP(
                Op.CALL(
                    STATE_EXHAUST_BURN,
                    Op.PUSH20(BURNER_ADDRESS),
                    0,
                    0,
                    0,
                    0,
                    0,
                )
            )
            + Op.PUSH2(burn_loop)
            + Op.JUMP
        )

    probe = bytes(assemble(0, 0, 0))
    fill_loop = 1
    fill_done = probe.index(bytes(Op.JUMPDEST + Op.POP + Op.JUMPDEST))
    burn_loop = fill_done + 2
    body = bytes(assemble(fill_loop, fill_done, burn_loop))
    final = len(body)
    # The only PUSH2 0x0000 left is the burn loop's exit target.
    exit_push = bytes(Op.PUSH2(0))
    assert body.count(exit_push) == 1
    body = body.replace(exit_push, bytes(Op.PUSH2(final)))
    return body + bytes(Op.JUMPDEST + Op.SSTORE(2**255, 1))


RESERVOIR_TX_RATE = 0.35
"""Fraction of transactions drawn above the execution-gas cap, so the
transaction carries a non-empty state gas reservoir.

`validate_transaction` caps the intrinsic cost against
`TX_MAX_GAS_LIMIT`, never `tx.gas`, so gas above the cap is valid and
becomes the reservoir (EIP-8037). Drawing only at or below the cap left
the reservoir empty in every case, which made every state charge spill
and left the branch that serves a charge *from* the reservoir dark.
"""

DISCARDED_DRAWS: Dict[str, int] = {}
"""Per-domain count of drawn values the gas budget could not accept.

A domain value that never fits is dead weight in the mixture, and
dropping it quietly reads downstream as a mysteriously low event rate
rather than as a narrowed domain. Counting it makes the narrowing a
number. Reset by `reset_discarded_draws` before a measured run.
"""


def reset_discarded_draws() -> None:
    """Clear the discarded-draw counters before a measured run."""
    DISCARDED_DRAWS.clear()


PRECOMPILE_FUNDING_RATE = 0.25
FIXED_COINBASE = 0xC0FFEE
"""The fee recipient when the coinbase draw aliases it with nothing."""
"""Fraction of cases that seed the precompiles into the pre-state. The
majority leave them absent, so a value-bearing call to one pays the
account-creation charge -- the historically bug-productive path."""


def _derive_key(rng: random.Random) -> Hash:
    """Draw a valid secp256k1 private key deterministically."""
    # secp256k1 order; any value in [1, n-1] is a valid key.
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    return Hash((rng.randrange(1, n)).to_bytes(32, "big"))


def _fee_market_fields(rng: random.Random, base: int) -> Dict[str, Any]:
    """
    Fee-market fields bracketing the base fee.

    The priority fee includes the exact max-fee boundary on purpose:
    `max_fee < priority` is the rejection, so priority equal to max fee
    is the last accepted value and the one a flipped comparison would
    reject. A priority above the max fee is never drawn -- that
    transaction is invalid and would be discarded before any comparison
    could see it.
    """
    max_fee = rng.choice((base, base + 1, 2 * base, 10 * base))
    priority = rng.choice(tuple({0, 1, max_fee - 1, max_fee}))
    return {
        "max_fee_per_gas": HexNumber(max_fee),
        "max_priority_fee_per_gas": HexNumber(priority),
    }


def _authorizations(
    rng: random.Random,
    domains: ValueDomains,
    sender: Address,
    senders: List[Address],
    accounts: Dict[Address, FuzzerAccountInput],
    nonces: Dict[Address, int],
    pool: AddressPool,
) -> List[FuzzerAuthorizationInput]:
    """
    One or two set-code authorizations, signed by a real authority.

    Authorities are drawn from accounts that send no transactions, and
    that restriction is load-bearing rather than tidiness. An applied
    authorization increments its authority's nonce, but only if the
    transaction carrying it succeeds -- a transaction that runs out of
    gas rolls the increment back. The generator cannot know which
    transactions will succeed, so any *transaction* nonce that depended
    on an authorization having applied would be wrong exactly when
    execution failed, and the case would not fill. Measured before this
    restriction: 1 case in 40 died that way, with the sender rejected as
    nonce-too-high two transactions later.

    Confining authorities to non-senders makes the failure benign. The
    worst a rolled-back increment can now cause is a later authorization
    being skipped, which is a legitimate outcome the generator produces
    on purpose anyway.

    A share carries the wrong nonce deliberately, above *and* below the
    authority's own: such an authorization is skipped, not rejected, so
    the transaction still fills while the comparison is exercised in
    both directions. Only the below case distinguishes the spec's `!=`
    from a mutant weakening it to `<`; a too-high nonce leaves the two
    agreeing, so a one-directional draw would leave that mutant alive
    while looking exercised.

    The delegation target is drawn from the same pool as calls, so an
    authority delegated to a generated contract runs fuzzed code when
    the pool later calls it; precompiles and never-existing addresses
    are the boundaries.
    """
    del sender
    out = []
    for _ in range(rng.choice((1, 1, 2))):
        authority = rng.choice(senders)
        key = accounts[authority].private_key
        assert key is not None, "every authority carries its key"
        nonce = nonces[authority]
        wrong = rng.random() < domains.wrong_auth_nonce_share
        if wrong:
            # Both directions, deliberately. The spec skips on `!=`, so a
            # mutant weakening that to `<` is only distinguishable by a
            # declared nonce *below* the authority's -- a too-high one
            # alone leaves both comparisons agreeing, and the mutant
            # would survive while looking exercised.
            declared = (
                nonce + 1 if (nonce == 0 or rng.random() < 0.5) else nonce - 1
            )
        else:
            declared = nonce
        out.append(
            FuzzerAuthorizationInput(
                chain_id=HexNumber(rng.choice((1, 1, 1, 0))),
                address=Address(rng.choice(pool.call_targets())),
                nonce=HexNumber(declared),
                signer_key=key,
            )
        )
        if not wrong:
            # An applied authorization increments its authority's nonce,
            # so every later transaction from that account moves up. Not
            # tracking this is not a harmless omission: the next such
            # transaction is rejected as nonce-too-low and the case never
            # fills, which would have made set-code transactions look
            # generated while contributing nothing.
            nonces[authority] += 1
    return out


WITHDRAWAL_RECIPIENT_BASE = 0x2F000
"""Where a withdrawal to an address nothing else touches is sent: a
dedicated range, so the recipient is guaranteed absent from the
pre-state and from every other role in the case."""


def _withdrawals(
    rng: random.Random,
    domains: ValueDomains,
    coinbase: Address,
    pools: Dict[str, List[Address]],
) -> List[FuzzerWithdrawalInput]:
    """
    The block's withdrawals, drawn once the coinbase is known.

    A recipient can be the coinbase, so the coinbase is drawn first. An
    empty pool falls back to an untouched address rather than skipping the
    draw, so a recipient kind can never silently turn into no withdrawal at
    all.
    """
    if rng.random() >= domains.withdrawal_rate:
        return []
    kinds, shares = zip(*domains.withdrawal_recipient_shares, strict=False)
    drawn = []
    for index in range(rng.randint(1, domains.max_withdrawals)):
        kind = rng.choices(kinds, weights=shares)[0]
        fresh = Address(WITHDRAWAL_RECIPIENT_BASE + index)
        if kind == "coinbase":
            recipient = coinbase
        elif kind == "nonexistent":
            recipient = fresh
        elif kind in ("sender", "code", "precompile", "system_contract"):
            pool = pools[kind]
            recipient = rng.choice(pool) if pool else fresh
        else:
            raise ValueError(f"unknown withdrawal recipient kind {kind!r}")
        if rng.random() < domains.withdrawal_zero_amount_share:
            amount = 0
        else:
            amount = rng.randrange(1, 10**9)
        drawn.append(
            FuzzerWithdrawalInput(
                index=HexNumber(index),
                validator_index=HexNumber(rng.randrange(0, 2**16)),
                address=recipient,
                amount=HexNumber(amount),
            )
        )
    return drawn


def _highest_base_fee(fork: Fork, domains: ValueDomains, block: int) -> int:
    """
    The highest base fee the ``block``-th block of a case can have.

    The base fee moves between blocks with how full the parent was, so a
    fee drawn against the first block's can be invalid by the time the
    transaction lands in a later one -- it was, for one multi-block case
    in five. Whether it is depends on execution, so it is derived rather
    than drawn: every parent is assumed full, the fork's own calculator
    gives the ceiling, and a fee at or above it is valid whatever happens
    first. The first block keeps the exact base fee, and with it the
    inclusion boundary the fee draw aims at.
    """
    calculate = fork.base_fee_per_gas_calculator()
    base_fee = domains.base_fee_per_gas
    for _ in range(block):
        base_fee = calculate(
            parent_base_fee_per_gas=base_fee,
            parent_gas_used=domains.block_gas_limit,
            parent_gas_limit=domains.block_gas_limit,
        )
    return base_fee


def _block_count(rng: random.Random, domains: ValueDomains) -> int:
    """How many blocks the case's transactions are spread across."""
    counts, shares = zip(*domains.block_count_shares, strict=False)
    return int(rng.choices(counts, weights=shares)[0])


def generate_fuzzer_output(
    fork: Fork,
    seed: int,
    *,
    num_senders: int = 3,
    num_contracts: int = 3,
    num_transactions: int = 5,
    max_ops_per_contract: int = 40,
    domains: Optional[ValueDomains] = None,
) -> FuzzerOutput:
    """
    Generate one reproducible ``FuzzerOutput`` for the given fork and seed.

    Senders are funded EOAs with deterministic keys; contracts hold
    stack-aware generated bytecode. Transactions reference senders and
    target contracts (or perform value transfers) with correct per-sender
    nonces.

    ``domains`` overrides the value distributions and walk-action weights
    (the experiment arms inject one here); ``None`` uses the fork default,
    so passing it is distribution-neutral -- the default reproduces the
    generator byte-for-byte.
    """
    # Seed from a stable string; a raw tuple hash would be salted per process.
    rng = random.Random(f"{GENERATOR_VERSION}:{fork.name()}:{seed}")

    accounts: Dict[Address, FuzzerAccountInput] = {}

    sender_addresses: List[Address] = []
    for _ in range(num_senders):
        key = _derive_key(rng)
        address = Address(EOA(key=key))
        accounts[address] = FuzzerAccountInput(
            balance=HexNumber(10**20),
            nonce=HexNumber(0),
            private_key=key,
        )
        sender_addresses.append(address)

    # Authorities send no transactions of their own: see `_authorizations`
    # for why that separation is load-bearing rather than tidiness.
    authority_addresses: List[Address] = []
    authority_start: Dict[Address, int] = {}
    for _ in range(AUTHORITY_ACCOUNTS):
        key = _derive_key(rng)
        address = Address(EOA(key=key))
        # Some authorities start with history. A declared nonce *below*
        # the authority's is the only case distinguishing the spec's
        # `!=` from a `<`, and it is unreachable on a fresh account:
        # there is nothing below zero. Starting every authority at zero
        # held that case to 2 occurrences in 132 authorizations.
        start = rng.choice((0, 0, 1, 3))
        accounts[address] = FuzzerAccountInput(
            balance=HexNumber(10**20),
            nonce=HexNumber(start),
            private_key=key,
        )
        authority_addresses.append(address)
        authority_start[address] = start

    # Manifest-driven: precompiles the fork introduced are up-weighted, so
    # the fuzzer aims at the changed surface (see eip_properties.targeting).
    precompiles = fuzz_precompile_targets(fork)
    if domains is None:
        domains = fork_domains(fork)

    # One mixed pool: contracts call every sibling (nested frames and
    # recursion arise naturally) but also senders, the precompile-range
    # boundary, and addresses that do not exist yet -- and transactions
    # can enter at any of them, precompiles included.
    contract_ints = [0x10000 + i for i in range(num_contracts)]
    pool = mixed_address_pool(
        precompiles,
        code=contract_ints,
        senders=[int.from_bytes(bytes(a), "big") for a in sender_addresses],
    )
    # A funded precompile is an edge every client must handle -- but an
    # UNFUNDED one is the richer path: sending value to a precompile that
    # does not exist yet pays the account-creation charge, and that is
    # where clients have actually diverged. Funding them in every case
    # silently deleted that precondition, so it is now a minority draw and
    # most cases keep the precompiles absent from the pre-state.
    if rng.random() < PRECOMPILE_FUNDING_RATE:
        for one_wei in pool.one_wei_accounts():
            accounts[Address(one_wei)] = FuzzerAccountInput(
                balance=HexNumber(1),
            )
    accounts[Address(DESTRUCTOR_ADDRESS)] = FuzzerAccountInput(
        balance=HexNumber(0),
        nonce=HexNumber(1),
        code=Bytes(bytes(Op.ORIGIN + Op.SELFDESTRUCT)),
    )
    accounts[Address(INTERLEAVER_ADDRESS)] = FuzzerAccountInput(
        balance=HexNumber(0),
        nonce=HexNumber(1),
        code=Bytes(interleaving_spill_code(rng)),
    )
    accounts[Address(SPILLER_ADDRESS)] = FuzzerAccountInput(
        balance=HexNumber(0),
        nonce=HexNumber(1),
        code=Bytes(bytes(Op.PUSH1(1) + Op.GAS + Op.SSTORE + Op.INVALID)),
    )
    failer, failer_storage = failer_code(rng, domains)
    accounts[Address(FAILER_ADDRESS)] = FuzzerAccountInput(
        balance=HexNumber(0),
        nonce=HexNumber(1),
        code=Bytes(failer),
        storage=failer_storage,
    )
    contract_addresses: List[Address] = []
    for target in contract_ints:
        address = Address(target)
        accounts[address] = FuzzerAccountInput(
            balance=HexNumber(rng.randrange(0, 10**18)),
            nonce=HexNumber(0),
            code=Bytes(
                bytes(
                    fuzzed_bytecode(
                        rng,
                        max_ops=max_ops_per_contract,
                        precompiles=precompiles,
                        call_targets=pool.call_targets(),
                        selfdestructor=DESTRUCTOR_ADDRESS,
                        spiller=SPILLER_ADDRESS,
                        interleaver=INTERLEAVER_ADDRESS,
                        domains=domains,
                    )
                )
            ),
            storage={
                HexNumber(key): HexNumber(value)
                for key, value in domains.storage_seed(rng).items()
            },
        )
        contract_addresses.append(address)

    accounts[Address(STATE_EXHAUSTER_ADDRESS)] = FuzzerAccountInput(
        balance=HexNumber(0),
        nonce=HexNumber(1),
        code=Bytes(state_exhauster_code()),
    )
    accounts[Address(BURNER_ADDRESS)] = FuzzerAccountInput(
        balance=HexNumber(0),
        nonce=HexNumber(1),
        code=Bytes(bytes(Op.INVALID)),
    )
    fresh_store_state = Op.SSTORE(
        key_warm=False, original_value=0, new_value=1
    ).state_cost(fork)
    nonces: Dict[Address, int] = dict.fromkeys(sender_addresses, 0)
    authority_nonces: Dict[Address, int] = dict(authority_start)
    tx_targets = pool.tx_targets()

    transactions: List[FuzzerTransactionInput] = []
    # Transactions must fit the block, or the block itself is invalid.
    tx_gas_cap = fork.transaction_gas_limit_cap() or domains.block_gas_limit
    tx_gas_choices = tuple(
        tx_gas_cap // divisor for divisor in (128, 32, 8, 1)
    )
    types, shares = zip(*domains.tx_type_shares, strict=False)
    block_count = _block_count(rng, domains)
    # One budget per block. A single budget spent in draw order let the
    # first block's transactions use it up, leaving later blocks nearly
    # empty: 388 of 409 executed BLOCKHASH reads landed in the first block.
    budgets = [domains.block_gas_limit] * block_count
    for index in range(num_transactions):
        block = index * block_count // num_transactions
        base_fee = _highest_base_fee(fork, domains, block)
        sender = rng.choice(sender_addresses)
        to = Address(rng.choice(tx_targets))
        gas_need_fraction = None
        exhaust: Optional[Tuple[int, int]] = None
        if rng.random() < domains.failing_tx_rate:
            to = Address(FAILER_ADDRESS)
        elif rng.random() < domains.toucher_tx_rate:
            to = Address(TOUCHER_ADDRESS)
            gas_need_fraction = rng.choice(domains.toucher_margins)
        elif (
            domains.reservoir_tx_gas
            and rng.random() < domains.state_exhaust_tx_rate
        ):
            # The limit is the cap plus the drawn reservoir: arithmetic on
            # the draw, not a prediction of what execution needs.
            reservoir = int(
                rng.choice(domains.state_exhaust_reservoir_stores)
                * fresh_store_state
            )
            if tx_gas_cap + reservoir <= budgets[block]:
                to = Address(STATE_EXHAUSTER_ADDRESS)
                exhaust = (
                    tx_gas_cap + reservoir,
                    -(-reservoir // fresh_store_state),
                )
        choices = tx_gas_choices
        if domains.reservoir_tx_gas and rng.random() < RESERVOIR_TX_RATE:
            choices = domains.reservoir_tx_gas + tx_gas_choices
        affordable = [g for g in choices if g <= budgets[block]]
        for rejected in choices:
            if rejected > budgets[block]:
                DISCARDED_DRAWS["tx_gas"] = (
                    DISCARDED_DRAWS.get("tx_gas", 0) + 1
                )
        if not affordable:
            # This block is full; the next transaction may belong to a
            # later one with room, so the draw goes on.
            continue
        gas = rng.choice(affordable)
        tx_type = rng.choices(types, weights=shares)[0]
        data = Bytes(fuzzed_calldata(rng, domains=domains))
        if exhaust is not None:
            # No authorizations: their intrinsic state would come out of
            # the reservoir the draw sized.
            gas, stores = exhaust
            tx_type = 2
            data = Bytes(stores.to_bytes(32, "big"))
        budgets[block] -= gas
        # Read before building authorizations: an authorization whose
        # authority is this sender advances `nonces[sender]`, and the
        # transaction's own nonce is the value from before that.
        tx_nonce = nonces[sender]
        fields: Dict[str, Any] = {}
        if tx_type == 0:
            fields["gas_price"] = HexNumber(2 * base_fee)
        else:
            fields.update(_fee_market_fields(rng, base_fee))
        if tx_type == 4:
            fields["authorization_list"] = _authorizations(
                rng,
                domains,
                sender,
                authority_addresses,
                accounts,
                authority_nonces,
                pool,
            )
        transactions.append(
            FuzzerTransactionInput(
                **{"from": sender},
                block=block,
                to=to,
                gas=HexNumber(gas),
                nonce=HexNumber(tx_nonce),
                value=HexNumber(rng.randrange(0, 10**16)),
                data=data,
                gas_need_fraction=gas_need_fraction,
                **fields,
            )
        )
        nonces[sender] = max(nonces[sender], tx_nonce) + 1

    # The toucher is drawn once the transactions are, so its "other
    # transaction" targets are the senders and targets of transactions
    # sharing a block with one sent to it.
    toucher = Address(TOUCHER_ADDRESS)
    owned_blocks = {tx.block for tx in transactions if tx.to == toucher}
    others = sorted(
        {
            int.from_bytes(bytes(address), "big")
            for tx in transactions
            if tx.block in owned_blocks and tx.to != toucher
            for address in (tx.from_, tx.to)
            if address is not None
        }
    )
    code, storage = toucher_code(rng, domains, pool.call_targets(), others)
    accounts[toucher] = FuzzerAccountInput(
        # Enough for every value call to carry one wei.
        balance=HexNumber(domains.toucher_max_touches),
        nonce=HexNumber(1),
        code=Bytes(code),
        storage=storage,
    )

    kinds, shares = zip(*domains.coinbase_shares, strict=False)
    coinbase_kind = rng.choices(kinds, weights=shares)[0]
    # The manifest's weighting carries over: a precompile the fork
    # introduced is drawn as the coinbase more often too.
    pools: Dict[str, List[Address]] = {
        "sender": sender_addresses,
        "code": [Address(i) for i in contract_ints],
        "precompile": [Address(p) for p in precompiles],
    }
    aliased = pools.get(coinbase_kind, [])
    coinbase = rng.choice(aliased) if aliased else Address(FIXED_COINBASE)

    withdrawals = _withdrawals(
        rng,
        domains,
        coinbase,
        {**pools, "system_contract": list(fork.system_contracts())},
    )

    env = Environment(
        fee_recipient=coinbase,
        gas_limit=domains.block_gas_limit,
        number=1,
        timestamp=1000,
        prev_randao=Hash(seed),
        base_fee_per_gas=domains.base_fee_per_gas,
    )

    return FuzzerOutput(
        version="2.0",
        fork=fork,
        chain_id=HexNumber(1),
        accounts=accounts,
        transactions=transactions,
        env=env,
        withdrawals=withdrawals,
        block_count=block_count,
    )
