"""
Composition density: how often a case CONTAINS a bug-triggering shape.

The reach map answers "which cells can we reach", and the reach gate keeps
those cells alive. Neither can see density collapse: a generator change can
halve how often it emits value-bearing precompile calls, or send half the
transaction budget somewhere that runs no generated code, and every cell
still fires, every event still fires, and the gate stays green.

That is exactly what happened between v6 and v9 -- a blind campaign found
zero client divergences where an earlier version found them at ~9%, while
the reach map showed no regression at all.

Three guards live here, in increasing generality:

- ``axis_coverage`` -- the categorical-collapse detector. Every input
  dimension with more than one value (a precompile present or absent from
  the pre-state, a call target with code or without, a transfer with value
  or without) must keep showing *both* values. The v6 regression was one
  such dimension silently reduced to a constant, and this trips on it the
  day it lands, without knowing anything about any bug.
- ``rate_regressions`` -- relative, version over version. An absolute
  floor cannot see a rate fall from 297 to 133 while staying above it;
  a proportional drop between versions is the signal, and it needs no
  per-bug metric to cover a path.
- ``composition_density`` -- per-case emission rates for a small declared
  grid of shapes. Useful, but the narrowest: metrics picked after the fact
  from a bug you already know will Goodhart the same way the reach map
  did, so these warn where the two above fail.

Coverage proves reach. Density finds bugs. Both need a guard.
"""

from collections import Counter
from math import comb, erfc, sqrt
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Tuple

if TYPE_CHECKING:
    from execution_testing.forks import Fork

CALL, CALLCODE, DELEGATECALL, STATICCALL = 0xF1, 0xF2, 0xF4, 0xFA
_CALL_KINDS = frozenset({CALL, CALLCODE, DELEGATECALL, STATICCALL})
_ADDRESS, _GAS, _PUSH0 = 0x30, 0x5A, 0x5F
_FIRST_CONTRACT = 0x10000

DENSITY_FLOORS: Dict[str, float] = {
    "tx_into_contract_pct": 50.0,
    "unfunded_precompile_pct": 50.0,
    "precompile_calls_per_case": 4.0,
    "value_precompile_calls_per_case": 1.2,
    "value_callcode_precompile_per_case": 0.6,
    "call_sites_per_case": 15.0,
}
"""Minimum densities, set at roughly two thirds of the v10 baseline: loose
enough that ordinary drift does not trip them, tight enough that halving a
composition rate does. The v9 regression trips
``tx_into_contract_pct`` (27.6) and ``unfunded_precompile_pct`` (0)."""


def _decode(code: bytes) -> List[Tuple[int, bytes]]:
    """Instructions as (opcode, immediate), push data skipped correctly."""
    out: List[Tuple[int, bytes]] = []
    i = 0
    while i < len(code):
        op = code[i]
        if 0x60 <= op <= 0x7F:
            width = op - 0x5F
            out.append((op, code[i + 1 : i + 1 + width]))
            i += 1 + width
        else:
            out.append((op, b""))
            i += 1
    return out


def _call_sites(
    instrs: List[Tuple[int, bytes]],
) -> Iterator[Tuple[int, int, int, bool]]:
    """
    Yield ``(kind, target, value, gas_forwarded)`` per emitted call site.

    Every call the strategies emit ends with the same three instructions:
    an address push (or ADDRESS), a gas push (or GAS), then the call
    opcode -- with the value push immediately before the address for the
    value-carrying kinds. ``target`` is -1 for a self-call, ``value`` -1
    when the kind carries none.
    """
    for idx, (op, _) in enumerate(instrs):
        if op not in _CALL_KINDS or idx < 2:
            continue
        gas_op, _ = instrs[idx - 1]
        if gas_op != _GAS and not 0x60 <= gas_op <= 0x7F:
            continue
        gas_forwarded = gas_op == _GAS
        addr_op, addr_imm = instrs[idx - 2]
        if addr_op == _ADDRESS:
            target = -1
        elif 0x60 <= addr_op <= 0x7F:
            target = int.from_bytes(addr_imm, "big")
        else:
            continue
        value = -1
        if op in (CALL, CALLCODE) and idx >= 3:
            value_op, value_imm = instrs[idx - 3]
            if value_op == _PUSH0:
                value = 0
            elif 0x60 <= value_op <= 0x7F:
                value = int.from_bytes(value_imm, "big")
        yield op, target, value, gas_forwarded


def composition_density(fork: "Fork", seeds: range) -> Dict[str, float]:
    """
    Per-case emission rates of the bug-triggering compositions.

    Generation only -- no fill, no clients -- so this is cheap enough to
    run on every generator change.
    """
    from execution_testing.eip_properties import fuzz_precompile_targets

    from .generator import generate_fuzzer_output

    precompiles = set(fuzz_precompile_targets(fork))
    totals: Dict[str, float] = dict.fromkeys(
        (
            "cases",
            "txs",
            "txs_into_contract",
            "cases_unfunded_precompiles",
            "precompile_calls",
            "value_precompile_calls",
            "value_callcode_precompile",
            "call_sites",
        ),
        0.0,
    )

    for seed in seeds:
        case = generate_fuzzer_output(fork, seed)
        totals["cases"] += 1
        alloc = {int.from_bytes(bytes(a), "big") for a in case.accounts}
        if not alloc & precompiles:
            totals["cases_unfunded_precompiles"] += 1

        contracts = {
            int.from_bytes(bytes(a), "big")
            for a, account in case.accounts.items()
            if account.code
            and int.from_bytes(bytes(a), "big") >= _FIRST_CONTRACT
        }
        for tx in case.transactions:
            totals["txs"] += 1
            if tx.to is not None:
                if int.from_bytes(bytes(tx.to), "big") in contracts:
                    totals["txs_into_contract"] += 1

        for address, account in case.accounts.items():
            if (
                not account.code
                or int.from_bytes(bytes(address), "big") < _FIRST_CONTRACT
            ):
                continue
            for kind, target, value, _ in _call_sites(
                _decode(bytes(account.code))
            ):
                totals["call_sites"] += 1
                if target in precompiles:
                    totals["precompile_calls"] += 1
                    if value > 0:
                        totals["value_precompile_calls"] += 1
                        if kind == CALLCODE:
                            totals["value_callcode_precompile"] += 1

    cases = max(totals["cases"], 1)
    txs = max(totals["txs"], 1)
    return {
        "tx_into_contract_pct": 100 * totals["txs_into_contract"] / txs,
        "unfunded_precompile_pct": (
            100 * totals["cases_unfunded_precompiles"] / cases
        ),
        "precompile_calls_per_case": totals["precompile_calls"] / cases,
        "value_precompile_calls_per_case": (
            totals["value_precompile_calls"] / cases
        ),
        "value_callcode_precompile_per_case": (
            totals["value_callcode_precompile"] / cases
        ),
        "call_sites_per_case": totals["call_sites"] / cases,
    }


AXIS_FLOOR = 0.05
"""Least share of draws each value of an input axis must hold. A value
below this is a dimension collapsing toward a constant -- the shape of
the v6 regression, where precompile pre-state existence went to always."""

REGRESSION_TOLERANCE = 0.40
"""Largest proportional drop a tracked rate may take between generator
versions before it is a regression. An absolute floor cannot see a rate
fall by half and stay above it; this can."""


def axis_coverage(fork: "Fork", seeds: range) -> Dict[str, Dict[str, float]]:
    """
    Share of draws holding each value of every multi-valued input axis.

    Bugs live in preconditions, and a precondition is one value of an
    axis. Any axis that stops showing both values has stopped testing the
    thing it existed to vary -- regardless of whether any cell went dark.
    """
    from execution_testing.eip_properties import fuzz_precompile_targets

    from .generator import generate_fuzzer_output

    precompiles = set(fuzz_precompile_targets(fork))
    tally: Dict[str, Counter] = {
        "precompile_prestate": Counter(),
        "tx_target": Counter(),
        "call_target": Counter(),
        "call_value": Counter(),
        "call_gas": Counter(),
        "call_kind": Counter(),
        "contract_storage": Counter(),
        "coinbase": Counter(),
        "withdrawals": Counter(),
        "withdrawal_recipient": Counter(),
        "withdrawal_amount": Counter(),
        "block_count": Counter(),
        "blockhash_read": Counter(),
        "blockhash_depth": Counter(),
    }
    reads = _blockhash_signatures()

    for seed in seeds:
        case = generate_fuzzer_output(fork, seed)
        alloc = {int.from_bytes(bytes(a), "big") for a in case.accounts}
        tally["precompile_prestate"][
            "present" if alloc & precompiles else "absent"
        ] += 1

        contracts = {
            int.from_bytes(bytes(a), "big")
            for a, account in case.accounts.items()
            if account.code
            and int.from_bytes(bytes(a), "big") >= _FIRST_CONTRACT
        }
        coinbase = int.from_bytes(bytes(case.env.fee_recipient), "big")
        keyed = {
            int.from_bytes(bytes(a), "big")
            for a, account in case.accounts.items()
            if account.private_key is not None
        }
        if coinbase in keyed:
            tally["coinbase"]["sender"] += 1
        elif coinbase in contracts:
            tally["coinbase"]["contract"] += 1
        elif coinbase in precompiles:
            tally["coinbase"]["precompile"] += 1
        else:
            tally["coinbase"]["fixed"] += 1
        system = {
            int.from_bytes(bytes(a), "big") for a in fork.system_contracts()
        }
        tally["withdrawals"]["present" if case.withdrawals else "absent"] += 1
        for withdrawal in case.withdrawals:
            recipient = int.from_bytes(bytes(withdrawal.address), "big")
            if recipient == coinbase:
                kind = "coinbase"
            elif recipient in system:
                kind = "system_contract"
            elif recipient in keyed:
                kind = "sender"
            elif recipient in contracts:
                kind = "code"
            elif recipient in precompiles:
                kind = "precompile"
            elif recipient not in alloc:
                kind = "nonexistent"
            else:
                raise ValueError(
                    f"unclassified withdrawal recipient {recipient:#x}"
                )
            tally["withdrawal_recipient"][kind] += 1
            amount = "zero" if int(withdrawal.amount) == 0 else "nonzero"
            tally["withdrawal_amount"][amount] += 1
        tally["block_count"][
            "one" if case.block_count == 1 else "several"
        ] += 1
        codes = [bytes(account.code) for account in case.accounts.values()]
        depths = {
            kind
            for kind, signatures in reads.items()
            for signature in signatures
            if any(signature in code for code in codes)
        }
        tally["blockhash_read"]["present" if depths else "absent"] += 1
        for kind in depths:
            tally["blockhash_depth"][kind] += 1
        for tx in case.transactions:
            target = (
                int.from_bytes(bytes(tx.to), "big")
                if tx.to is not None
                else None
            )
            if target is None:
                kind = "creation"
            elif target in contracts:
                kind = "contract"
            elif target in precompiles:
                kind = "precompile"
            else:
                kind = "other"
            tally["tx_target"][kind] += 1

        for address, account in case.accounts.items():
            if (
                not account.code
                or int.from_bytes(bytes(address), "big") < _FIRST_CONTRACT
            ):
                continue
            tally["contract_storage"][
                "seeded" if account.storage else "empty"
            ] += 1
            for opcode, target, value, forwarded in _call_sites(
                _decode(bytes(account.code))
            ):
                tally["call_kind"][f"0x{opcode:02x}"] += 1
                tally["call_gas"]["forwarded" if forwarded else "bounded"] += 1
                if target == -1:
                    tally["call_target"]["self"] += 1
                elif target in contracts:
                    tally["call_target"]["contract"] += 1
                elif target in precompiles:
                    tally["call_target"]["precompile"] += 1
                else:
                    tally["call_target"]["other"] += 1
                if value >= 0:
                    tally["call_value"][
                        "nonzero" if value > 0 else "zero"
                    ] += 1

    return {
        axis: {
            value: count / max(sum(counts.values()), 1)
            for value, count in counts.items()
        }
        for axis, counts in tally.items()
    }


def _blockhash_signatures() -> Dict[str, Tuple[bytes, ...]]:
    """
    The bytes of each BLOCKHASH read the generator can emit, by kind.

    Produced by the emitter itself, up to the store, so a change in how
    the motif is encoded changes what is looked for instead of silently
    matching nothing.
    """
    from execution_testing.fuzzing.strategies import BLOCKHASH_DEPTHS
    from execution_testing.vm import Opcodes as Op

    kinds: Dict[str, List[bytes]] = {}
    for depth in set(BLOCKHASH_DEPTHS):
        if depth == 0:
            kind = "current"
        elif depth == 1:
            kind = "parent"
        elif depth <= 256:
            kind = "in_case"
        else:
            kind = "out_of_window"
        read = bytes(Op.BLOCKHASH(Op.SUB(Op.NUMBER, depth)))
        kinds.setdefault(kind, []).append(read)
    return {kind: tuple(reads) for kind, reads in kinds.items()}


def axis_collapse_warnings(
    coverage: Dict[str, Dict[str, float]],
    floor: float = AXIS_FLOOR,
    expected: "Optional[Dict[str, Tuple[str, ...]]]" = None,
) -> List[str]:
    """
    Axis values that vanished or fell below ``floor``.

    ``expected`` names the values an axis must show; a value absent
    entirely is the worst case (a dimension became a constant) and is
    reported as 0.00, which a share-based check alone would miss.
    """
    expected = expected if expected is not None else EXPECTED_AXIS_VALUES
    warnings = []
    for axis, values in sorted(expected.items()):
        seen = coverage.get(axis, {})
        for value in values:
            share = seen.get(value, 0.0)
            if share < floor:
                warnings.append(f"{axis}={value} {share:.2%} < {floor:.0%}")
    return warnings


EXPECTED_AXIS_VALUES: Dict[str, Tuple[str, ...]] = {
    "precompile_prestate": ("present", "absent"),
    "tx_target": ("contract", "precompile", "other"),
    "call_target": ("contract", "self", "precompile", "other"),
    "call_value": ("zero", "nonzero"),
    "call_gas": ("forwarded", "bounded"),
    "contract_storage": ("seeded", "empty"),
    "coinbase": ("fixed", "sender", "contract", "precompile"),
    "withdrawals": ("present", "absent"),
    "withdrawal_recipient": (
        "nonexistent",
        "precompile",
        "coinbase",
        "sender",
        "code",
        "system_contract",
    ),
    "withdrawal_amount": ("zero", "nonzero"),
    "block_count": ("one", "several"),
    "blockhash_read": ("present", "absent"),
    "blockhash_depth": ("parent", "in_case", "current", "out_of_window"),
}
"""Every axis whose values must all keep appearing. Adding a dimension to
the generator means adding it here, or its collapse goes unnoticed."""


def rate_regressions(
    previous: Dict[str, float],
    current: Dict[str, float],
    tolerance: float = REGRESSION_TOLERANCE,
) -> List[str]:
    """
    Tracked rates that fell proportionally further than ``tolerance``.

    Works over any name -> number mapping, so the same check covers the
    L1 event rates and the composition densities without either needing a
    per-bug metric written for it.
    """
    regressions = []
    for name, before in sorted(previous.items()):
        after = current.get(name)
        if after is None or before <= 0:
            continue
        drop = (before - after) / before
        if drop > tolerance:
            regressions.append(
                f"{name} {before:.2f} -> {after:.2f} (-{drop:.0%})"
            )
    return regressions


REGRESSION_ALPHA = 0.01
"""How unlikely a count drop must be under an unchanged rate before it is
a regression rather than sampling."""


def significant_drops(
    previous: Dict[str, int],
    current: Dict[str, int],
    previous_seeds: int,
    current_seeds: int,
    tolerance: float = REGRESSION_TOLERANCE,
    alpha: float = REGRESSION_ALPHA,
) -> List[str]:
    """
    Event counts that fell further than ``tolerance`` *and* further than
    sampling explains.

    A proportional threshold alone cries wolf on rare events: `child-revert`
    went from 6 to 2 in 400 seeds between v15 and v16, a 67% drop, and
    from 11 to 25 on the next 2000. Under an unchanged rate the later
    count, given the total of the two, is binomial with the later sample's
    share of the seeds, so the chance of a count this low is exact and
    needs no approximation. A check that alarms on noise gets ignored,
    which is how four version bumps went unchecked.
    """
    share = current_seeds / (previous_seeds + current_seeds)
    drops = []
    for name, before in sorted(previous.items()):
        after = current.get(name, 0)
        if before <= 0:
            continue
        before_rate = before / previous_seeds
        after_rate = after / current_seeds
        if (before_rate - after_rate) / before_rate <= tolerance:
            continue
        total = before + after
        chance = sum(
            comb(total, k) * share**k * (1 - share) ** (total - k)
            for k in range(after + 1)
        )
        if chance < alpha:
            drops.append(
                f"{name} {before}/{previous_seeds} -> "
                f"{after}/{current_seeds} (p={chance:.1e})"
            )
    return drops


def rank_sum_lower(before: List[int], after: List[int]) -> float:
    """
    One-sided p-value that ``after`` tends lower than ``before``.

    The Mann-Whitney rank-sum under its normal approximation, corrected
    for ties: most cases put zero or a handful of opcodes in a block, so
    ties are the rule. It compares where the samples sit, not their
    means, so one case running a million opcodes cannot carry it.
    """
    pooled = sorted([(v, 0) for v in before] + [(v, 1) for v in after])
    n = len(pooled)
    rank_after = 0.0
    tie_term = 0
    i = 0
    while i < n:
        j = i
        while j < n and pooled[j][0] == pooled[i][0]:
            j += 1
        rank = (i + j + 1) / 2
        rank_after += rank * sum(1 for _, side in pooled[i:j] if side)
        tie_term += (j - i) ** 3 - (j - i)
        i = j
    n1, n2 = len(before), len(after)
    u = rank_after - n2 * (n2 + 1) / 2
    variance = n1 * n2 / 12 * ((n + 1) - tie_term / (n * (n - 1)))
    if variance <= 0:
        return 1.0
    z = (u - n1 * n2 / 2) / sqrt(variance)
    return erfc(-z / sqrt(2)) / 2


def block_step_drops(
    previous: Dict[str, Dict[str, Any]],
    current: Dict[str, Dict[str, Any]],
    tolerance: float = REGRESSION_TOLERANCE,
    alpha: float = REGRESSION_ALPHA,
) -> List[str]:
    """
    Later blocks whose per-case opcode counts fell between versions.

    A drop counts when the mean per case falls further than ``tolerance``
    *and* the rank-sum says the cases sit lower than sampling explains,
    the same two conditions `significant_drops` puts on event counts.
    Each block is measured only over the cases that drew it, so drawing a
    block more or less often is not read as starving it.
    """
    drops = []
    for number, before in sorted(previous.items()):
        after = current.get(number)
        if int(number) < 2 or not after or not before.get("steps"):
            continue
        mean_before = sum(before["steps"]) / len(before["steps"])
        mean_after = sum(after["steps"]) / len(after["steps"])
        if mean_before <= 0:
            continue
        if (mean_before - mean_after) / mean_before <= tolerance:
            continue
        chance = rank_sum_lower(before["steps"], after["steps"])
        if chance < alpha:
            drops.append(
                f"block {number} opcodes per case {mean_before:.0f} -> "
                f"{mean_after:.0f} (p={chance:.1e})"
            )
    return drops


def density_floor_warnings(density: Dict[str, float]) -> List[str]:
    """Compositions that fell below their floor -- a density regression."""
    return sorted(
        f"{name} {density[name]:.2f} < {floor}"
        for name, floor in DENSITY_FLOORS.items()
        if name in density and density[name] < floor
    )


def density_record(fork: "Fork", seeds: range) -> Dict[str, Any]:
    """One trendable reach-log record of composition density."""
    from datetime import datetime, timezone

    from execution_testing.cli.mutation.reach_log import eels_commit

    from .generator import GENERATOR_VERSION

    density = composition_density(fork, seeds)
    return {
        "kind": "composition-density",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "eels_commit": eels_commit(),
        "fork": fork.name(),
        "generator_version": GENERATOR_VERSION,
        "seeds": len(seeds),
        "density": density,
        "below_floor": density_floor_warnings(density),
    }


def render_density(record: Dict[str, Any]) -> str:
    """Render one density record as a small table, flagging the floors."""
    lines = [
        f"composition density (generator v{record['generator_version']}, "
        f"{record['fork']}, {record['seeds']} seeds):"
    ]
    for name, value in sorted(record["density"].items()):
        floor = DENSITY_FLOORS.get(name)
        flag = (
            "  <- below floor" if floor is not None and value < floor else ""
        )
        lines.append(f"  {name}: {value:.2f}{flag}")
    return "\n".join(lines)
