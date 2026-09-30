"""
Labeled, recorded draws: the generator's randomness as a tree of named
choices that can be replayed, pinned, varied or set one at a time.

Every draw has a label, a path such as `tx:3/motif:exhaust/reservoir`,
and takes its value from a stream seeded by the case's seed and that
path alone. So a draw never depends on how many draws came before it:
adding, removing or changing one unit leaves every other label's value
where it was, and a case replays byte-identically from its seed or from
its recorded tree.

A draw is `structural` when it decides which units or labels exist (how
many transactions, which motif a transaction runs, whether a block is
added) and `param` when it only fills in a value. The labels a
structural draw decides live beneath it: under `tx:3/motif`, as
`tx:3/motif:exhaust/...`. Values the generator computes from draws, such
as nonces, gas budgets and whether a transaction fits its block, are
never recorded: they are derived again on every replay.
"""

import json
import random
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    TypeVar,
)

STRUCTURAL = "structural"
PARAM = "param"

T = TypeVar("T")


class DrawError(ValueError):
    """A plan or a label the generator cannot honor."""


@dataclass(frozen=True)
class Domain:
    """
    What a label's value may be, which `set` is checked against: the
    type's valid values, not the range the generator samples from.
    """

    name: str
    check: Callable[[Any], bool]
    encode: Callable[[Any], Any] = lambda value: value
    decode: Callable[[Any], Any] = lambda value: value
    alternatives: Optional[Tuple[Any, ...]] = None
    """Every value, encoded, when there are few enough to try each."""


SMALL_DOMAIN = 16
"""Most values a domain may have for triage to try each one."""


def integers(lo: int, hi: int) -> Domain:
    """Integers from ``lo`` to ``hi`` inclusive."""
    return Domain(
        f"int[{lo}, {hi}]",
        lambda v: isinstance(v, int)
        and not isinstance(v, bool)
        and lo <= v <= hi,
        alternatives=(
            tuple(range(lo, hi + 1)) if hi - lo < SMALL_DOMAIN else None
        ),
    )


FLAG = Domain(
    "bool", lambda v: isinstance(v, bool), alternatives=(False, True)
)
SEED = integers(0, 2**64 - 1)
BYTES = Domain(
    "bytes",
    lambda v: isinstance(v, bytes),
    encode=lambda v: "0x" + bytes(v).hex(),
    decode=lambda v: bytes.fromhex(v[2:]) if isinstance(v, str) else v,
)
UINT256 = integers(0, 2**256 - 1)
FORWARD_ALL_OR_UINT256 = Domain(
    "null (forward all) or int[0, 2**256 - 1]",
    lambda v: v is None or UINT256.check(v),
)


def one_of(options: Sequence[Any]) -> Domain:
    """One of ``options``, recorded as its string form when not JSON."""
    encoded = {_encode(o): o for o in options}
    return Domain(
        "one of " + ", ".join(str(k) for k in encoded),
        lambda v: _encode(v) in encoded,
        encode=_encode,
        decode=lambda v: encoded[v] if v in encoded else v,
        alternatives=(
            tuple(encoded) if len(encoded) <= SMALL_DOMAIN else None
        ),
    )


def _encode(value: Any) -> Any:
    if isinstance(value, (bool, int, str)) or value is None:
        return value
    return str(value)


@dataclass
class Draw:
    """One recorded draw."""

    label: str
    kind: str
    value: Any
    """The value as JSON: what a tree file holds and a pin replays."""
    domain: str
    alternatives: Optional[List[Any]] = None
    """Every value the label can take, when few enough to try each."""
    lower: Optional[int] = None
    """An integer domain's least value, which triage also tries."""


@dataclass
class Plan:
    """
    How to replay a case: labels held to a value, labels resampled.

    A label in `values` takes that value (a pin replays the recorded one,
    a set gives a literal); a label in `varied`, or beneath a varied
    structural label, is drawn again from a stream salted with `salt`;
    anything else is drawn as the seed alone would draw it.
    """

    values: Dict[str, Any] = field(default_factory=dict)
    varied: Set[str] = field(default_factory=set)
    salt: int = 0
    set_labels: Set[str] = field(default_factory=set)
    """Labels whose value is a literal, checked against the domain."""

    def resampled(self, label: str) -> bool:
        """Whether ``label`` is varied, or decided by a varied label."""
        return any(label == v or beneath(label, v) for v in self.varied)


def beneath(label: str, parent: str) -> bool:
    """Whether ``label`` is decided by ``parent``: nested under its path."""
    return label.startswith(parent + "/") or label.startswith(parent + ":")


class Draws:
    """
    The draw source a case is generated from, recording as it goes.

    `unit` scopes the labels under a structural unit's path; every draw
    method takes the label's last segment and its kind.
    """

    def __init__(
        self,
        root: str,
        plan: Optional[Plan] = None,
        *,
        _path: str = "",
        _tree: Optional[Dict[str, Draw]] = None,
    ) -> None:
        self.root = root
        self.plan = plan or Plan()
        self.path = _path
        self.tree: Dict[str, Draw] = _tree if _tree is not None else {}

    def unit(self, name: str) -> "Draws":
        """The draws of a unit nested under this one."""
        return Draws(
            self.root, self.plan, _path=self._label(name), _tree=self.tree
        )

    def _label(self, name: str) -> str:
        return f"{self.path}/{name}" if self.path else name

    def _draw(
        self,
        name: str,
        kind: str,
        domain: Domain,
        sample: Callable[[random.Random], Any],
    ) -> Any:
        label = self._label(name)
        if label in self.tree:
            raise DrawError(f"label {label!r} drawn twice")
        if label in self.plan.values:
            encoded = self.plan.values[label]
            value = domain.decode(encoded)
            if not domain.check(value):
                raise DrawError(
                    f"{label} = {encoded!r} is outside its domain, "
                    f"{domain.name}"
                )
        else:
            stream = f"{self.root}|{label}"
            if self.plan.resampled(label):
                stream += f"|vary:{self.plan.salt}"
            value = sample(random.Random(stream))
        lower = None
        if domain.name.startswith("int["):
            lower = int(domain.name[4:].split(",")[0])
        self.tree[label] = Draw(
            label,
            kind,
            domain.encode(value),
            domain.name,
            list(domain.alternatives) if domain.alternatives else None,
            lower,
        )
        return value

    def sample(
        self,
        name: str,
        sampler: Callable[[random.Random], Any],
        domain: Domain,
        *,
        kind: str = PARAM,
    ) -> Any:
        """A value from ``sampler``, run on the label's own stream."""
        return self._draw(name, kind, domain, sampler)

    def flag(self, name: str, p: float, *, kind: str = STRUCTURAL) -> bool:
        """True with probability ``p``."""
        return self._draw(name, kind, FLAG, lambda r: r.random() < p)

    def pick(
        self,
        name: str,
        options: Sequence[T],
        *,
        kind: str = PARAM,
        weights: Optional[Sequence[float]] = None,
        domain: Optional[Domain] = None,
    ) -> T:
        """One of ``options``, uniformly or by ``weights``."""

        def sample(r: random.Random) -> Any:
            if weights is None:
                return r.choice(options)
            return r.choices(options, weights=weights)[0]

        return self._draw(name, kind, domain or one_of(options), sample)

    def member(
        self,
        name: str,
        members: Sequence[T],
        *,
        kind: str = PARAM,
        weights: Optional[Sequence[float]] = None,
    ) -> T:
        """
        One of ``members``, recorded by its position.

        For a pick among other units -- a sender, a call target -- whose
        values are derived: varying a sender's key changes its address,
        and a pick recorded by address would then name nobody, where one
        recorded by position still names that sender.
        """
        positions = range(len(members))
        index = self._draw(
            name,
            kind,
            integers(0, len(members) - 1),
            lambda r: (
                r.randrange(len(members))
                if weights is None
                else r.choices(positions, weights=weights)[0]
            ),
        )
        return members[index]

    def integer(
        self,
        name: str,
        lo: int,
        hi: int,
        *,
        kind: str = PARAM,
        domain: Optional[Domain] = None,
    ) -> int:
        """An integer from ``lo`` to ``hi`` inclusive."""
        return self._draw(
            name,
            kind,
            domain or integers(lo, hi),
            lambda r: r.randint(lo, hi),
        )

    def bits(self, name: str, n: int, *, kind: str = PARAM) -> int:
        """``n`` random bits."""
        return self._draw(
            name, kind, integers(0, 2**n - 1), lambda r: r.getrandbits(n)
        )

    def constant(self, name: str, value: int, domain: Domain) -> int:
        """A value the generator does not vary, but that can be set."""
        return self._draw(name, PARAM, domain, lambda _r: value)

    def stream(self, name: str) -> random.Random:
        """
        A generator for code the label covers as a whole, such as a
        contract body: its seed is the recorded value.
        """
        return random.Random(
            self._draw(name, PARAM, SEED, lambda r: r.getrandbits(64))
        )


class LabeledRandom(random.Random):
    """
    A `random.Random` that strategy code can also label draws through.

    Code written against `random.Random` runs on it unchanged: its plain
    draws come from one stream per unit, seeded by the recorded `rest`
    label on first use. Code that knows it may be labeled calls `unit`
    to scope a sub-unit and `labeled` to give a draw its own label; the
    `scoped` and `drawn` helpers do either, and fall back to the plain
    draw on an ordinary `random.Random`.
    """

    def __init__(self, draws: Draws) -> None:
        super().__init__(0)
        self.draws = draws
        self._rest = False

    def _ensure_rest(self) -> None:
        if not self._rest:
            self._rest = True
            super().seed(
                self.draws._draw(
                    "rest", PARAM, SEED, lambda r: r.getrandbits(64)
                )
            )

    def random(self) -> float:
        """As `random.Random.random`, from the unit's stream."""
        self._ensure_rest()
        return super().random()

    def getrandbits(self, k: int) -> int:
        """As `random.Random.getrandbits`, from the unit's stream."""
        self._ensure_rest()
        return super().getrandbits(k)

    def unit(self, name: str) -> "LabeledRandom":
        """The labeled random of a unit nested under this one."""
        return LabeledRandom(self.draws.unit(name))


def scoped(rng: random.Random, name: str) -> random.Random:
    """``rng``'s sub-unit ``name`` when it is labeled, else ``rng``."""
    if isinstance(rng, LabeledRandom):
        return rng.unit(name)
    return rng


def drawn(
    rng: random.Random,
    name: str,
    sampler: Callable[[random.Random], T],
    domain: Domain,
    *,
    kind: str = PARAM,
) -> T:
    """
    ``sampler(rng)``, or, when ``rng`` is labeled, the same sampler run on
    label ``name``'s own stream and recorded.
    """
    if isinstance(rng, LabeledRandom):
        return rng.draws.sample(name, sampler, domain, kind=kind)
    return sampler(rng)


def drawn_bytes(rng: random.Random, name: str, size: int) -> bytes:
    """
    ``size`` random bytes. Labeled, the label records their seed rather
    than the bytes, so a varied size gets fresh bytes of the new length
    instead of the old bytes overriding it.
    """
    if isinstance(rng, LabeledRandom):
        seed = rng.draws.sample(name, lambda r: r.getrandbits(64), SEED)
        return random.Random(seed).randbytes(size)
    return rng.randbytes(size)


def chain_weights(entries: Sequence[Tuple[str, float, bool]]) -> List[float]:
    """
    Each entry's chance of being the first taken, then the chance none is.

    An entry is taken when available and its own draw passes; one draw
    over these weights gives each the same chance as the flags drawn one
    after another.
    """
    weights = []
    rest = 1.0
    for _, rate, available in entries:
        taken = rate if available else 0.0
        weights.append(rest * taken)
        rest *= 1 - taken
    weights.append(rest)
    return weights


@dataclass
class DrawTree:
    """A case's recorded draws, in draw order, with what made them."""

    generator_version: int
    fork: str
    seed: int
    draws: List[Draw]

    def values(self) -> Dict[str, Any]:
        """Every label's recorded value."""
        return {d.label: d.value for d in self.draws}

    def kinds(self) -> Dict[str, str]:
        """Every label's kind."""
        return {d.label: d.kind for d in self.draws}

    def to_json(self) -> str:
        """The tree as a file a replay can start from."""
        return json.dumps(
            {
                "generator_version": self.generator_version,
                "fork": self.fork,
                "seed": self.seed,
                "draws": [d.__dict__ for d in self.draws],
            },
            indent=1,
        )

    @classmethod
    def from_json(cls, text: str) -> "DrawTree":
        """A tree written by `to_json`."""
        data = json.loads(text)
        return cls(
            data["generator_version"],
            data["fork"],
            data["seed"],
            [Draw(**d) for d in data["draws"]],
        )


def focus_plan(
    tree: DrawTree,
    *,
    vary: Sequence[str] = (),
    pin: Sequence[str] = (),
    sets: Optional[Mapping[str, Any]] = None,
    salt: int = 0,
) -> Plan:
    """
    The plan for a focused run of ``tree``: every recorded label pinned,
    except the varied ones and those beneath a varied structural label,
    and the set ones, which take their literal.

    A structural label is varied only by releasing what it decides, so an
    explicit pin beneath one is refused: the pinned value might belong to
    a unit the new draw removes, or mean something else under it.
    """
    sets = dict(sets or {})
    kinds = tree.kinds()
    for label in [*vary, *pin, *sets]:
        if label not in kinds:
            raise DrawError(f"no label {label!r} in the case")
    for v in vary:
        if v in sets:
            raise DrawError(f"{v} is both varied and set")
        if kinds[v] == STRUCTURAL:
            for p in [*pin, *sets]:
                if beneath(p, v):
                    raise DrawError(
                        f"{p} is pinned beneath {v}, which is structural "
                        "and varied: what it decides is drawn again"
                    )
    plan = Plan(varied=set(vary), salt=salt, set_labels=set(sets))
    for label, value in tree.values().items():
        if not plan.resampled(label):
            plan.values[label] = value
    plan.values.update(sets)
    return plan


def compare(
    before: DrawTree, after: DrawTree
) -> Tuple[List[str], List[str], List[str]]:
    """Labels whose value changed, labels only before, labels only after."""
    a, b = before.values(), after.values()
    changed = sorted(k for k in a.keys() & b.keys() if a[k] != b[k])
    return changed, sorted(a.keys() - b.keys()), sorted(b.keys() - a.keys())
