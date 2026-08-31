"""
Value domains and mixture distributions shared by all generation engines.

Uniform random values almost never land where EVM semantics change, and
exact boundary constants alone never explore the space between them.
Every domain here draws from a four-mode mixture -- zero, a boundary
set, a small uniform range, and full width -- with the weights held as
data, so "which distribution" is a measurable campaign parameter rather
than a property of the code.

Boundary sets are computed from the fork object, never written as
literals: a repriced opcode or a raised cap changes the distribution
with no edit to this package.
"""

import random
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Optional, Sequence, Tuple

if TYPE_CHECKING:
    from execution_testing.forks import Fork


def boundary_values(bits: int) -> List[int]:
    """Type-width edges where arithmetic and encoding behavior change."""
    values = {0, 1, 2, (1 << bits) - 1, (1 << bits) - 2}
    for exp in (7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255):
        if exp < bits:
            values.update({1 << exp, (1 << exp) - 1, (1 << exp) + 1})
    return sorted(values)


U256_BOUNDARIES: Tuple[int, ...] = tuple(boundary_values(256))

WORD_BOUNDARY_SIZES: Tuple[int, ...] = (0, 1, 31, 32, 33, 63, 64, 65)
"""Byte-string sizes straddling the 32-byte words that price memory."""

SMALL_SIZE_MAX = 64
"""Upper end of the small-uniform mode for byte-string sizes."""


@dataclass(frozen=True)
class MixtureWeights:
    """Mode weights for one value domain; must sum to 1."""

    zero: float
    boundary: float
    small: float
    full: float

    def __post_init__(self) -> None:
        """Reject weight vectors that are not a distribution."""
        total = self.zero + self.boundary + self.small + self.full
        if abs(total - 1.0) > 1e-9:
            raise ValueError(f"mixture weights sum to {total}, not 1")


GAS_WEIGHTS = MixtureWeights(zero=0.10, boundary=0.40, small=0.10, full=0.40)
VALUE_WEIGHTS = MixtureWeights(zero=0.30, boundary=0.25, small=0.35, full=0.10)
SIZE_WEIGHTS = MixtureWeights(zero=0.20, boundary=0.30, small=0.35, full=0.15)
OPERAND_WEIGHTS = MixtureWeights(
    zero=0.05, boundary=0.20, small=0.10, full=0.65
)


@dataclass(frozen=True)
class WalkWeights:
    """
    Per-op action weights for the bytecode walk.

    Each weight is checked sequentially against the remaining walk, and
    whatever falls through lands on a plain palette op. Halt kinds and
    deliberate invalidity are first-class, low-weight actions.
    """

    precompile_call: float = 0.15
    message_call: float = 0.15
    halting_child: float = 0.10
    spill_interleave: float = 0.08
    create2_self_copy: float = 0.08
    destructor_call: float = 0.06
    raw_byte: float = 0.05
    # Frame-ending actions are charged PER OP, so they compound over the
    # walk: at 0.03 each they ended ~90% of bodies early, cutting call
    # sites per case in half. They only need to fire often enough to keep
    # their reach cells alive (~25% of cases at these weights), so they
    # stay low -- density is what finds bugs, coverage only proves reach.
    terminator: float = 0.01
    returndata_overread: float = 0.005
    initcode_ef_prefix: float = 0.01
    stack_bomb: float = 0.005
    bad_jump: float = 0.005
    # Share of message calls that recurse into the current contract
    # rather than a pool address. Self-calls are the cheapest route to
    # deep frames, so this is drawn explicitly instead of falling out of
    # the pool's length -- where weighting code accounts up for density
    # silently squeezed recursion down.
    self_call: float = 0.3

    def __post_init__(self) -> None:
        """Reject weights outside [0, 1]."""
        for name, weight in vars(self).items():
            if not 0.0 <= weight <= 1.0:
                raise ValueError(f"{name} weight {weight} outside [0, 1]")


WALK_WEIGHTS = WalkWeights()


def draw_mixed(
    rng: random.Random,
    weights: MixtureWeights,
    *,
    boundaries: Sequence[int],
    full_bits: int = 256,
    small_max: int = 255,
) -> int:
    """
    Draw one value from the four-mode mixture.

    An empty boundary set falls through to the small mode.
    """
    roll = rng.random()
    if roll < weights.zero:
        return 0
    roll -= weights.zero
    if roll < weights.boundary and boundaries:
        return rng.choice(list(boundaries))
    roll -= weights.boundary
    if roll < weights.small:
        return rng.randint(0, small_max)
    return rng.getrandbits(full_bits)


@dataclass(frozen=True)
class ValueDomains:
    """Fork-computed boundary sets with per-domain mixture weights."""

    call_gas_boundaries: Tuple[int, ...]
    spill_gas: Tuple[int, ...]
    salt_domain: Tuple[int, ...]
    value_boundaries: Tuple[int, ...] = (1, 2)
    storage_keys: Tuple[int, ...] = tuple(range(8))
    storage_values: Tuple[int, ...] = (1, 2, 3)
    reservoir_tx_gas: Tuple[int, ...] = ()
    walk: WalkWeights = WALK_WEIGHTS
    gas_weights: MixtureWeights = GAS_WEIGHTS
    value_weights: MixtureWeights = VALUE_WEIGHTS
    size_weights: MixtureWeights = SIZE_WEIGHTS
    operand_weights: MixtureWeights = OPERAND_WEIGHTS

    def call_gas(self, rng: random.Random) -> Optional[int]:
        """Gas for a message call; None forwards everything via GAS."""
        weights = self.gas_weights
        roll = rng.random()
        if roll < weights.zero:
            return 0
        roll -= weights.zero
        if roll < weights.boundary:
            return rng.choice(list(self.call_gas_boundaries))
        roll -= weights.boundary
        if roll < weights.small:
            return rng.randint(0, 255)
        return None

    def call_value(self, rng: random.Random) -> int:
        """Value for a message call; full width bounces on balance."""
        return draw_mixed(
            rng, self.value_weights, boundaries=self.value_boundaries
        )

    def operand(self, rng: random.Random) -> int:
        """A PUSH operand: mostly full width, with a boundary tail."""
        return draw_mixed(
            rng, self.operand_weights, boundaries=U256_BOUNDARIES
        )

    def storage_seed(self, rng: random.Random) -> Dict[int, int]:
        """
        A tiny pre-state storage: keys drawn from the same small domain
        later writes use, so reset/set/clear pricing transitions collide
        by construction.
        """
        return {
            rng.choice(self.storage_keys): rng.choice(self.storage_values)
            for _ in range(rng.randrange(0, len(self.storage_keys)))
        }

    def byte_size(self, rng: random.Random, cap: int = 256) -> int:
        """A byte-string size in [0, cap], word-boundary weighted."""
        weights = self.size_weights
        roll = rng.random()
        if roll < weights.zero:
            return 0
        roll -= weights.zero
        if roll < weights.boundary:
            sizes = [s for s in WORD_BOUNDARY_SIZES if s <= cap]
            if sizes:
                return rng.choice(sizes)
        roll -= weights.boundary
        if roll < weights.small:
            return rng.randint(0, min(SMALL_SIZE_MAX, cap))
        return rng.randint(0, cap)


GENERIC_DOMAINS = ValueDomains(
    call_gas_boundaries=tuple(boundary_values(16)),
    spill_gas=(22_100, 44_200),
    salt_domain=tuple(range(4)),
)
"""Fork-free defaults for callers without a fork in hand."""


def fork_domains(
    fork: "Fork", block_gas_limit: Optional[int] = None
) -> ValueDomains:
    """
    Compute the fork's value domains from its own gas schedule.

    The call-gas boundary set brackets the stipend, warm and cold access,
    a cold write, and the cost of creating a funded account -- each one a
    gas amount at which a child frame's capabilities change. The spill
    set brackets a cold write from above, the amount a child needs to
    charge state gas at all.
    """
    costs = fork.gas_costs()
    stipend = costs.CALL_STIPEND
    create_funded = (
        costs.COLD_ACCOUNT_ACCESS + costs.NEW_ACCOUNT + costs.CALL_VALUE
    )
    call_gas = sorted(
        {
            1,
            costs.WARM_ACCESS,
            stipend - 1,
            stipend,
            stipend + 1,
            costs.COLD_ACCOUNT_ACCESS - 1,
            costs.COLD_ACCOUNT_ACCESS,
            costs.COLD_STORAGE_ACCESS,
            costs.COLD_STORAGE_ACCESS + costs.STORAGE_SET,
            create_funded,
        }
    )
    # A child only spills state gas if it can *afford* the charge: an
    # unaffordable one raises OutOfGasError before any spill is recorded.
    # So this brackets a cold write from exactly-affordable upward, the
    # opposite of starving the frame.
    cold_write = costs.COLD_STORAGE_ACCESS + costs.STORAGE_SET
    spill = sorted({cold_write * factor for factor in (1, 2, 8, 32)})
    # A transaction's state gas reservoir is whatever its gas limit
    # exceeds the *execution* cap by -- validation caps the intrinsic
    # cost, not `tx.gas`. Only a reservoir that covers a whole cold
    # write reaches the branch that serves a charge from the reservoir,
    # so the set brackets that cost rather than the cap itself.
    # The interesting edge is a reservoir that exactly covers one charge
    # against one a unit short, so the set brackets a single cold write
    # rather than scaling by it. Values must also stay inside a block:
    # an unaffordable draw is silently discarded by the gas budget, which
    # is how a widened domain can look wider than it is.
    # Only a fork that splits the reservoir out treats gas above the cap
    # as valid: before EIP-8037 the same cap is a hard validity check on
    # `tx.gas`, so drawing above it there produces invalid transactions.
    cap = fork.transaction_gas_limit_cap()
    reservoir_tx_gas: Tuple[int, ...] = ()
    if cap is not None and fork.state_gas_reservoir_enabled():
        candidates = [
            cap + 1,
            cap + cold_write - 1,
            cap + cold_write,
            cap + cold_write * 8,
        ]
        if block_gas_limit is not None:
            # A value a block can never fit is not a wider domain, it is
            # a draw the budget silently discards. The upper bound is the
            # block's own limit, which is itself the largest legal draw.
            candidates = [g for g in candidates if g <= block_gas_limit]
            candidates.append(block_gas_limit)
        reservoir_tx_gas = tuple(sorted(set(candidates)))
    return ValueDomains(
        call_gas_boundaries=tuple(call_gas),
        spill_gas=tuple(spill),
        reservoir_tx_gas=reservoir_tx_gas,
        salt_domain=tuple(range(4)),
    )


@dataclass(frozen=True)
class AddressPool:
    """
    One mixed pool: existence, warmth, and precompile dispatch are all
    exercised by a single target draw.
    """

    code: Tuple[int, ...]
    senders: Tuple[int, ...]
    precompiles: Tuple[int, ...]
    boundary: int
    nonexistent: Tuple[int, ...]

    def call_targets(self) -> List[int]:
        """
        Weighted in-EVM call targets, heavily biased toward code accounts.

        A call into a codeless account returns immediately, so every such
        draw is a frame that does no work; the non-code targets earn their
        place (cold accounts, the precompile-range boundary) but must stay
        a minority or nested-frame density collapses.
        """
        return (
            list(self.code) * 6
            + list(self.senders)
            + [self.boundary]
            + list(self.nonexistent)
        )

    def tx_targets(self) -> List[int]:
        """
        Weighted transaction targets: code accounts dominate heavily.

        A transaction entering at a precompile or an EOA executes no
        fuzzed bytecode, so those draws spend the block's transaction
        budget without exercising the generated program. They stay in the
        pool -- entering directly at a precompile reaches cells nothing
        else does -- but at a few percent, not half the budget. The
        precompile list is deduplicated here: its per-address weighting
        is for *call* targeting, and would otherwise dominate this draw.
        """
        return (
            list(self.code) * 30
            + list(self.senders) * 3
            + sorted(set(self.precompiles))
            + [self.boundary]
            + list(self.nonexistent)
        )

    def one_wei_accounts(self) -> List[int]:
        """
        Addresses the generator seeds with one wei so they exist: the
        precompiles themselves (a funded precompile is a real edge every
        client must handle).
        """
        return sorted(set(self.precompiles))


def mixed_address_pool(
    precompiles: Sequence[int],
    *,
    code: Sequence[int],
    senders: Sequence[int],
) -> AddressPool:
    """
    Build the pool around the fork's precompile range.

    ``precompiles`` may carry repeats (a weighted list biased toward the
    fork's new precompiles); the repeats are preserved so target draws
    keep the bias. The nonexistent addresses sit just past the range
    boundary, so touching them exercises cold account creation.
    """
    boundary = max(precompiles) + 1
    return AddressPool(
        code=tuple(code),
        senders=tuple(senders),
        precompiles=tuple(precompiles),
        boundary=boundary,
        nonexistent=(boundary + 1, boundary + 2),
    )
