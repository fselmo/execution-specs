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
from typing import Any, Dict, FrozenSet, List, Optional

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
from execution_testing.vm import Opcodes as Op

from .models import (
    FuzzerAccountInput,
    FuzzerAuthorizationInput,
    FuzzerOutput,
    FuzzerTransactionInput,
)

# Contract bodies and calldata come from the shared strategy library
# (`execution_testing.fuzzing`), the same helpers test authors use. Bump
# this whenever generation logic changes so old seeds are not silently
# reinterpreted.
GENERATOR_VERSION = 14

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
"""Fraction of cases that seed the precompiles into the pre-state. The
majority leave them absent, so a value-bearing call to one pays the
account-creation charge -- the historically bug-productive path."""


def _derive_key(rng: random.Random) -> Hash:
    """Draw a valid secp256k1 private key deterministically."""
    # secp256k1 order; any value in [1, n-1] is a valid key.
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    return Hash((rng.randrange(1, n)).to_bytes(32, "big"))


def _fee_market_fields(
    rng: random.Random, domains: ValueDomains
) -> Dict[str, Any]:
    """
    Fee-market fields bracketing the base fee.

    The priority fee includes the exact max-fee boundary on purpose:
    `max_fee < priority` is the rejection, so priority equal to max fee
    is the last accepted value and the one a flipped comparison would
    reject. A priority above the max fee is never drawn -- that
    transaction is invalid and would be discarded before any comparison
    could see it.
    """
    base = domains.base_fee_per_gas
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
    for _ in range(AUTHORITY_ACCOUNTS):
        key = _derive_key(rng)
        address = Address(EOA(key=key))
        accounts[address] = FuzzerAccountInput(
            balance=HexNumber(10**20),
            nonce=HexNumber(0),
            private_key=key,
        )
        authority_addresses.append(address)

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

    nonces: Dict[Address, int] = dict.fromkeys(sender_addresses, 0)
    authority_nonces: Dict[Address, int] = dict.fromkeys(
        authority_addresses, 0
    )
    tx_targets = pool.tx_targets()

    transactions: List[FuzzerTransactionInput] = []
    # Transactions must fit the block, or the block itself is invalid.
    gas_budget = domains.block_gas_limit
    tx_gas_cap = fork.transaction_gas_limit_cap() or domains.block_gas_limit
    tx_gas_choices = tuple(
        tx_gas_cap // divisor for divisor in (128, 32, 8, 1)
    )
    types, shares = zip(*domains.tx_type_shares, strict=False)
    for _ in range(num_transactions):
        sender = rng.choice(sender_addresses)
        to = Address(rng.choice(tx_targets))
        choices = tx_gas_choices
        if domains.reservoir_tx_gas and rng.random() < RESERVOIR_TX_RATE:
            choices = domains.reservoir_tx_gas + tx_gas_choices
        affordable = [g for g in choices if g <= gas_budget]
        for rejected in choices:
            if rejected > gas_budget:
                DISCARDED_DRAWS["tx_gas"] = (
                    DISCARDED_DRAWS.get("tx_gas", 0) + 1
                )
        if not affordable:
            break
        gas = rng.choice(affordable)
        gas_budget -= gas
        tx_type = rng.choices(types, weights=shares)[0]
        # Read before building authorizations: an authorization whose
        # authority is this sender advances `nonces[sender]`, and the
        # transaction's own nonce is the value from before that.
        tx_nonce = nonces[sender]
        fields: Dict[str, Any] = {}
        if tx_type == 0:
            fields["gas_price"] = HexNumber(2 * domains.base_fee_per_gas)
        else:
            fields.update(_fee_market_fields(rng, domains))
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
                to=to,
                gas=HexNumber(gas),
                nonce=HexNumber(tx_nonce),
                value=HexNumber(rng.randrange(0, 10**16)),
                data=Bytes(fuzzed_calldata(rng, domains=domains)),
                **fields,
            )
        )
        nonces[sender] = max(nonces[sender], tx_nonce) + 1

    env = Environment(
        fee_recipient=Address(0xC0FFEE),
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
    )
