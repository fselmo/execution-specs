"""
Composition density: how often a case CONTAINS a bug-triggering shape.

The reach map answers "which cells can we reach", and the reach gate keeps
those cells alive. Neither can see density collapse: a generator change can
halve how often it emits value-bearing precompile calls, or send half the
transaction budget somewhere that runs no generated code, and every cell
still fires, every event still fires, and the gate stays green.

That is exactly what happened between v6 and v9 -- a blind campaign found
zero client divergences where an earlier version found them at ~9%, while
the reach map showed no regression at all. This module is the instrument
that would have caught it: per-case emission rates for the compositions
that actually trigger bugs, with floors that fail when one collapses.

Coverage proves reach. Density finds bugs. Both need a guard.
"""

from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Tuple

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
) -> Iterator[Tuple[int, int, int]]:
    """
    Yield ``(kind, target, value)`` per emitted call site.

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
        yield op, target, value


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
            for kind, target, value in _call_sites(
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
