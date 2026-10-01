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
from math import erfc, exp, lgamma, log, sqrt
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Tuple

from .negative import NEGATIVE_KINDS

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


_TOUCH_KINDS = {
    0x31: "balance",
    0x3B: "extcodesize",
    0x3F: "extcodehash",
    0x3C: "extcodecopy",
    0x54: "sload",
    0x55: "sstore",
    0xF1: "value_call",
}
"""The toucher's touch opcodes, by the kind names the generator draws."""


def _tally_toucher(case: Any, tally: Dict[str, Counter]) -> None:
    """
    Count the toucher's presence, touch kinds and target classes.

    Read back from the case: each account-level target is a 20-byte push
    in the toucher's code, classed as itself, an address another
    transaction in an owned block sends from or to, or any other pool
    address. Storage touches act on the toucher's own storage.
    """
    from execution_testing.base_types import Address

    from .generator import TOUCHER_ADDRESS

    toucher = Address(TOUCHER_ADDRESS)
    owned = {tx.block for tx in case.transactions if tx.to == toucher}
    if not owned:
        tally["toucher_tx"]["absent"] += 1
        return
    tally["toucher_tx"]["present"] += 1
    others = {
        int.from_bytes(bytes(address), "big")
        for tx in case.transactions
        if tx.block in owned and tx.to != toucher
        for address in (tx.from_, tx.to)
        if address is not None
    }
    for opcode, immediate in _decode(bytes(case.accounts[toucher].code)):
        if opcode in _TOUCH_KINDS:
            tally["toucher_touch"][_TOUCH_KINDS[opcode]] += 1
            if opcode in (0x54, 0x55):
                tally["toucher_target"]["self"] += 1
        elif opcode == 0x73:  # PUSH20: an account-level target
            target = int.from_bytes(immediate, "big")
            if target == TOUCHER_ADDRESS:
                tally["toucher_target"]["self"] += 1
            elif target in others:
                tally["toucher_target"]["other_tx"] += 1
            else:
                tally["toucher_target"]["pool"] += 1


def _tally_state_exhaust(
    case: Any, fork: "Fork", tally: Dict[str, Counter]
) -> None:
    """
    Count the state exhauster's presence and the reservoirs it was given.

    The reservoir is what the gas limit exceeds the cap by, measured in
    fresh-slot stores: under one leaves a store paying from both pools.
    """
    from execution_testing.base_types import Address
    from execution_testing.vm import Opcodes as Op

    from .generator import STATE_EXHAUSTER_ADDRESS

    exhauster = Address(STATE_EXHAUSTER_ADDRESS)
    owned = [tx for tx in case.transactions if tx.to == exhauster]
    tally["state_exhaust_tx"]["present" if owned else "absent"] += 1
    cap = fork.transaction_gas_limit_cap()
    store = Op.SSTORE(key_warm=False, original_value=0, new_value=1)
    per_store = store.state_cost(fork)
    for tx in owned:
        stores = (int(tx.gas) - (cap or 0)) / per_store
        if stores < 1:
            tally["state_exhaust_reservoir"]["under_one_store"] += 1
        elif stores == 1:
            tally["state_exhaust_reservoir"]["one_store"] += 1
        else:
            tally["state_exhaust_reservoir"]["several"] += 1


def _tally_exact_charge(case: Any, tally: Dict[str, Counter]) -> None:
    """Count the exact charger's presence, the pool paying, and margins."""
    from execution_testing.base_types import Address

    from .generator import EXACT_CHARGE_SOURCES, EXACT_CHARGER_ADDRESS

    charger = Address(EXACT_CHARGER_ADDRESS)
    owned = [tx for tx in case.transactions if tx.to == charger]
    tally["exact_charge_tx"]["present" if owned else "absent"] += 1
    for tx in owned:
        words = bytes(tx.data)
        source = EXACT_CHARGE_SOURCES[int.from_bytes(words[32:64], "big")]
        tally["exact_charge_source"][source] += 1
        margin = int.from_bytes(words[64:96], "big", signed=True)
        if margin == 0:
            tally["exact_charge_margin"]["exact"] += 1
        elif margin < 0:
            tally["exact_charge_margin"]["short"] += 1
        else:
            tally["exact_charge_margin"]["over"] += 1


def _tally_authorities(case: Any, tally: Dict[str, Counter]) -> None:
    """
    Count authorities aliased with their own transaction's accesses, the
    ones that then send, and authorizations at the nonce's top.
    """
    from execution_testing.base_types import Address
    from execution_testing.test_types.account_types import EOA

    from .generator import AUTHORITY_PROBE_ADDRESS, MAX_NONCE

    probe = Address(AUTHORITY_PROBE_ADDRESS)
    senders = {tx.from_ for tx in case.transactions}
    aliased = capped = False
    for tx in case.transactions:
        for auth in tx.authorization_list or []:
            authority = Address(EOA(key=auth.signer_key))
            if int(auth.nonce) >= MAX_NONCE - 1:
                capped = True
                tally["max_nonce_authority_nonce"][
                    "max" if int(auth.nonce) == MAX_NONCE else "below_max"
                ] += 1
            elif tx.to in (authority, probe):
                aliased = True
                tally["authority_alias_kind"][
                    "target" if tx.to == authority else "probe"
                ] += 1
                tally["authority_sends_later"][
                    "yes" if authority in senders else "no"
                ] += 1
    tally["authority_alias_tx"]["present" if aliased else "absent"] += 1
    tally["max_nonce_authority_tx"]["present" if capped else "absent"] += 1


def _margin_name(margin: int) -> str:
    if margin == 0:
        return "exact"
    elif margin < 0:
        return "short"
    return "over"


def _tally_account_charge(
    case: Any, fork: "Fork", tally: Dict[str, Counter]
) -> None:
    """Count the account charger's presence, children and margins."""
    from execution_testing.base_types import Address

    from .generator import (
        ACCOUNT_CHARGE_CHILDREN,
        ACCOUNT_CHARGER_ADDRESS,
        account_charge_need,
    )

    charger = Address(ACCOUNT_CHARGER_ADDRESS)
    kinds = {child: kind for kind, child in ACCOUNT_CHARGE_CHILDREN.items()}
    owned = [tx for tx in case.transactions if tx.to == charger]
    tally["account_charge_tx"]["present" if owned else "absent"] += 1
    for tx in owned:
        words = bytes(tx.data)
        kind = kinds[int.from_bytes(words[32:64], "big")]
        tally["account_charge_kind"][kind] += 1
        margin = int.from_bytes(words[:32], "big") - account_charge_need(
            kind, fork
        )
        tally["account_charge_margin"][_margin_name(margin)] += 1


def _tally_auth_prepare(
    case: Any, fork: "Fork", tally: Dict[str, Counter]
) -> None:
    """Count authorizations sent with gas for exactly their charges."""
    from execution_testing.base_types import Address
    from execution_testing.test_types.account_types import EOA

    from .generator import BURNER_ADDRESS, auth_prepare_gas

    burner = Address(BURNER_ADDRESS)
    owned = [
        tx
        for tx in case.transactions
        if tx.to == burner and tx.authorization_list
    ]
    tally["auth_prepare_tx"]["present" if owned else "absent"] += 1
    for tx in owned:
        (auth,) = tx.authorization_list
        exists = Address(EOA(key=auth.signer_key)) in case.accounts
        tally["auth_prepare_authority"][
            "existing" if exists else "absent"
        ] += 1
        margin = int(tx.gas) - auth_prepare_gas(fork, exists)
        tally["auth_prepare_margin"][_margin_name(margin)] += 1


def _tally_bal_cap(case: Any, tally: Dict[str, Counter]) -> None:
    """Count cases at the access list's size cap, and which side."""
    offset = case.bal_cap_offset
    tally["bal_cap_case"]["absent" if offset is None else "present"] += 1
    if offset is not None:
        tally["bal_cap_side"]["at_cap" if offset == 0 else "over_cap"] += 1


def _tally_tx_validity(case: Any, tally: Dict[str, Counter]) -> None:
    """Count cases ending in a transaction breaking a validity rule."""
    from .generator import TX_VALIDITY_KINDS

    rejected = [
        tx
        for tx in case.transactions
        if tx.error
        and tx.error.split("|")[0]
        in (
            "GAS_LIMIT_EXCEEDS_MAXIMUM",
            "INTRINSIC_GAS_TOO_LOW",
            "INTRINSIC_GAS_BELOW_FLOOR_GAS_COST",
        )
    ]
    tally["tx_validity_case"]["present" if rejected else "absent"] += 1
    for tx in rejected:
        if tx.error == "GAS_LIMIT_EXCEEDS_MAXIMUM":
            kind = "above_total_cap"
        elif tx.error.startswith("INTRINSIC_GAS_BELOW_FLOOR_GAS_COST"):
            kind = "floor_short"
        elif len(bytes(tx.data)) > 1024:
            kind = "floor_above_cap"
        else:
            kind = "intrinsic_short"
        assert kind in TX_VALIDITY_KINDS
        tally["tx_validity_kind"][kind] += 1
        if tx.authorization_list:
            tx_type = "4"
        elif tx.blob_versioned_hashes:
            tx_type = "3"
        elif tx.gas_price is None:
            tx_type = "2"
        elif tx.access_list:
            tx_type = "1"
        else:
            tx_type = "0"
        tally["tx_validity_type"][tx_type] += 1


def _tally_repay(case: Any, tally: Dict[str, Counter]) -> None:
    """Count the repayer's presence and whether its restorer reverts."""
    from execution_testing.base_types import Address

    from .generator import REPAYER_ADDRESS, REVERTING_RESTORER_ADDRESS

    repayer = Address(REPAYER_ADDRESS)
    owned = [tx for tx in case.transactions if tx.to == repayer]
    tally["repay_tx"]["present" if owned else "absent"] += 1
    for tx in owned:
        restorer = int.from_bytes(bytes(tx.data)[:32], "big")
        tally["repay_child"][
            "reverts" if restorer == REVERTING_RESTORER_ADDRESS else "succeeds"
        ] += 1


def _tally_graver(case: Any, tally: Dict[str, Counter]) -> None:
    """Count the graver's presence, beneficiaries and values."""
    from execution_testing.base_types import Address

    from .generator import (
        DEAD_BENEFICIARY_BASE,
        EMPTY_BENEFICIARY_ADDRESS,
        GRAVER_ADDRESS,
    )

    graver = Address(GRAVER_ADDRESS)
    owned = [tx for tx in case.transactions if tx.to == graver]
    tally["graver_tx"]["present" if owned else "absent"] += 1
    for tx in owned:
        beneficiary = int.from_bytes(bytes(tx.data)[:32], "big")
        if beneficiary == EMPTY_BENEFICIARY_ADDRESS:
            tally["graver_beneficiary"]["empty"] += 1
        elif DEAD_BENEFICIARY_BASE <= beneficiary < EMPTY_BENEFICIARY_ADDRESS:
            tally["graver_beneficiary"]["nonexistent"] += 1
        else:
            tally["graver_beneficiary"]["alive"] += 1
        tally["graver_value"]["nonzero" if int(tx.value) else "zero"] += 1


def _tally_creation(case: Any, tally: Dict[str, Counter]) -> None:
    """Count creation transactions and what their target address holds."""
    from execution_testing.test_types import compute_create_address

    creations = [tx for tx in case.transactions if tx.to is None]
    tally["creation_tx"]["present" if creations else "absent"] += 1
    for tx in creations:
        target = compute_create_address(address=tx.from_, nonce=int(tx.nonce))
        occupant = case.accounts.get(target)
        if occupant is None:
            kind = "fresh"
        elif occupant.code:
            kind = "code"
        elif int(occupant.nonce or 0):
            kind = "nonce"
        else:
            kind = "balance_only"
        tally["creation_target"][kind] += 1


def _tally_near_full(
    case: Any, fork: "Fork", tally: Dict[str, Counter]
) -> None:
    """
    Count near-full blocks, what filled them, the state filler's size and
    the last transaction's margin.

    A block sending the burner a transaction at the cap is filled with
    execution gas: no other draw sends the burner one.
    """
    from execution_testing.base_types import Address
    from execution_testing.vm import Opcodes as Op

    from .generator import BURNER_ADDRESS, STATE_FILLER_ADDRESS

    filler = Address(STATE_FILLER_ADDRESS)
    burner = Address(BURNER_ADDRESS)
    cap = fork.transaction_gas_limit_cap()
    limit = int(case.env.gas_limit)
    store = Op.SSTORE(key_warm=False, original_value=0, new_value=1)
    blocks = {}
    for tx in case.transactions:
        if tx.to == filler:
            stores = int.from_bytes(bytes(tx.data)[:32], "big")
            tally["near_full_stores"][str(stores)] += 1
            blocks[tx.block] = ("state", stores * store.state_cost(fork))
        elif tx.to == burner and int(tx.gas) == cap:
            blocks[tx.block] = ("execution", 0)
    tally["near_full_block"]["present" if blocks else "absent"] += 1
    for block, (kind, state_used) in blocks.items():
        tally["near_full_kind"][kind] += 1
        in_block = [t for t in case.transactions if t.block == block]
        last = in_block[-1]
        if kind == "state":
            left = limit - state_used
        elif kind == "execution":
            left = limit - sum(int(t.gas) for t in in_block[:-1])
        else:
            raise ValueError(kind)
        margin = int(last.gas) - left
        tally["near_full_margin"]["exact" if margin == 0 else "over"] += 1


def _tally_deployer(case: Any, tally: Dict[str, Counter]) -> None:
    """Count deployer transactions, their opcode and initcode size."""
    from execution_testing.base_types import Address

    from .generator import DEPLOYER_ADDRESSES

    by_address = {Address(a): k for k, a in DEPLOYER_ADDRESSES.items()}
    owned = [tx for tx in case.transactions if tx.to in by_address]
    tally["deployer_tx"]["present" if owned else "absent"] += 1
    for tx in owned:
        assert tx.to is not None
        tally["deployer_kind"][by_address[tx.to]] += 1
        tally["deployer_initcode"][
            "empty" if not bytes(tx.data) else "nonempty"
        ] += 1


def _tally_requests(
    case: Any, fork: "Fork", tally: Dict[str, Counter]
) -> None:
    """Count request transactions, their type and whether they pay."""
    from execution_testing.base_types import Address

    from .generator import REQUEST_FEE

    by_address = {
        Address(c.system_contract_address): c
        for c in fork.system_contract_request_types()
    }
    owned = [tx for tx in case.transactions if tx.to in by_address]
    tally["request_tx"]["present" if owned else "absent"] += 1
    for tx in owned:
        assert tx.to is not None
        cls = by_address[tx.to]
        tally["request_kind"][cls.__name__] += 1
        if hasattr(cls, "min_fee"):
            valid = int(tx.value) >= REQUEST_FEE
        else:
            valid = int(tx.value) % 10**9 == 0
        tally["request_valid"]["yes" if valid else "no"] += 1


def _tally_max_initcode(
    case: Any, fork: "Fork", tally: Dict[str, Counter]
) -> None:
    """Count creations at the largest initcode and one byte over it."""
    from execution_testing.base_types import Address

    from .generator import MAX_INITCODE_CREATOR_ADDRESS

    creator = Address(MAX_INITCODE_CREATOR_ADDRESS)
    owned = [tx for tx in case.transactions if tx.to == creator]
    tally["max_initcode_tx"]["present" if owned else "absent"] += 1
    for tx in owned:
        size = int.from_bytes(bytes(tx.data)[:32], "big")
        over = size > fork.max_initcode_size()
        tally["max_initcode_size"]["one_over" if over else "exact"] += 1


def _tally_delegated_calls(case: Any, tally: Dict[str, Counter]) -> None:
    """Count transactions to the delegated account, warm and cold."""
    from execution_testing.base_types import Address

    from .generator import DELEGATED_ACCOUNT_ADDRESS

    delegated = Address(DELEGATED_ACCOUNT_ADDRESS)
    owned = [tx for tx in case.transactions if tx.to == delegated]
    tally["delegated_call_tx"]["present" if owned else "absent"] += 1
    for tx in owned:
        warm = bool(tx.access_list)
        tally["delegated_target"]["warm" if warm else "cold"] += 1


def _tally_negative(case: Any, tally: Dict[str, Counter]) -> None:
    """Count negative cases, their family and kind."""
    negative = case.negative
    tally["negative_case"]["present" if negative else "absent"] += 1
    if negative is None:
        return
    tally["negative_family"][negative.family] += 1
    tally[f"negative_{negative.family}_kind"][negative.kind] += 1


def axis_coverage(fork: "Fork", seeds: range) -> Dict[str, Dict[str, float]]:
    """
    Share of draws holding each value of every multi-valued input axis.

    Bugs live in preconditions, and a precondition is one value of an
    axis. Any axis that stops showing both values has stopped testing the
    thing it existed to vary -- regardless of whether any cell went dark.
    """
    from execution_testing.base_types import Address
    from execution_testing.eip_properties import fuzz_precompile_targets
    from execution_testing.vm import Opcodes as Op

    from .generator import FAILER_ADDRESS, generate_fuzzer_output

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
        "failing_tx": Counter(),
        "failer_outcome": Counter(),
        "toucher_tx": Counter(),
        "toucher_touch": Counter(),
        "toucher_target": Counter(),
        "state_exhaust_tx": Counter(),
        "state_exhaust_reservoir": Counter(),
        "exact_charge_tx": Counter(),
        "exact_charge_margin": Counter(),
        "exact_charge_source": Counter(),
        "authority_alias_tx": Counter(),
        "authority_alias_kind": Counter(),
        "authority_sends_later": Counter(),
        "max_nonce_authority_tx": Counter(),
        "max_nonce_authority_nonce": Counter(),
        "repay_tx": Counter(),
        "repay_child": Counter(),
        "account_charge_tx": Counter(),
        "account_charge_kind": Counter(),
        "account_charge_margin": Counter(),
        "auth_prepare_tx": Counter(),
        "auth_prepare_authority": Counter(),
        "auth_prepare_margin": Counter(),
        "bal_cap_case": Counter(),
        "bal_cap_side": Counter(),
        "tx_validity_case": Counter(),
        "tx_validity_kind": Counter(),
        "tx_validity_type": Counter(),
        "graver_tx": Counter(),
        "graver_beneficiary": Counter(),
        "graver_value": Counter(),
        "creation_tx": Counter(),
        "creation_target": Counter(),
        "near_full_block": Counter(),
        "near_full_stores": Counter(),
        "near_full_margin": Counter(),
        "near_full_kind": Counter(),
        "deployer_tx": Counter(),
        "deployer_kind": Counter(),
        "max_nonce_block": Counter(),
        "max_nonce_rejected": Counter(),
        "max_nonce_account": Counter(),
        "request_tx": Counter(),
        "request_kind": Counter(),
        "request_valid": Counter(),
        "max_initcode_tx": Counter(),
        "max_initcode_size": Counter(),
        "delegated_call_tx": Counter(),
        "delegated_target": Counter(),
        "negative_case": Counter(),
        "negative_family": Counter(),
        **{f"negative_{family}_kind": Counter() for family in NEGATIVE_KINDS},
        "deployer_initcode": Counter(),
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
        failer = Address(FAILER_ADDRESS)
        if any(tx.to == failer for tx in case.transactions):
            tally["failing_tx"]["present"] += 1
            last = bytes(case.accounts[failer].code)[-1]
            if last == Op.REVERT.int():
                tally["failer_outcome"]["revert"] += 1
            elif last == Op.INVALID.int():
                tally["failer_outcome"]["exceptional_halt"] += 1
            else:
                raise ValueError(f"unclassified failer ending {last:#x}")
        else:
            tally["failing_tx"]["absent"] += 1
        _tally_toucher(case, tally)
        _tally_state_exhaust(case, fork, tally)
        _tally_exact_charge(case, tally)
        _tally_authorities(case, tally)
        _tally_repay(case, tally)
        _tally_account_charge(case, fork, tally)
        _tally_auth_prepare(case, fork, tally)
        _tally_bal_cap(case, tally)
        _tally_tx_validity(case, tally)
        _tally_graver(case, tally)
        _tally_creation(case, tally)
        _tally_near_full(case, fork, tally)
        _tally_deployer(case, tally)
        _tally_requests(case, fork, tally)
        _tally_max_initcode(case, fork, tally)
        _tally_delegated_calls(case, tally)
        _tally_negative(case, tally)
        carries_max = any(
            int(account.nonce or 0) >= 2**64 - 2
            for account in case.accounts.values()
        )
        tally["max_nonce_account"]["present" if carries_max else "absent"] += 1
        maxed = [tx for tx in case.transactions if int(tx.nonce) >= 2**64 - 2]
        tally["max_nonce_block"]["present" if maxed else "absent"] += 1
        if maxed:
            rejected = any(tx.error for tx in maxed)
            tally["max_nonce_rejected"]["yes" if rejected else "no"] += 1
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
    "failing_tx": ("present", "absent"),
    "failer_outcome": ("revert", "exceptional_halt"),
    "toucher_tx": ("present", "absent"),
    "toucher_touch": (
        "balance",
        "extcodesize",
        "extcodehash",
        "extcodecopy",
        "sload",
        "sstore",
        "value_call",
    ),
    "toucher_target": ("self", "pool", "other_tx"),
    "state_exhaust_tx": ("present", "absent"),
    "state_exhaust_reservoir": ("under_one_store", "one_store", "several"),
    "exact_charge_tx": ("present", "absent"),
    "exact_charge_margin": ("exact", "short", "over"),
    "exact_charge_source": ("gas_left", "reservoir", "split"),
    "authority_alias_tx": ("present", "absent"),
    "authority_alias_kind": ("target", "probe"),
    "authority_sends_later": ("yes", "no"),
    "max_nonce_authority_tx": ("present", "absent"),
    "max_nonce_authority_nonce": ("below_max", "max"),
    "repay_tx": ("present", "absent"),
    "repay_child": ("succeeds", "reverts"),
    "account_charge_tx": ("present", "absent"),
    "account_charge_kind": (
        "value_call",
        "create",
        "selfdestruct",
        "code_deposit",
    ),
    "account_charge_margin": ("exact", "short", "over"),
    "auth_prepare_tx": ("present", "absent"),
    "auth_prepare_authority": ("absent", "existing"),
    "auth_prepare_margin": ("exact", "short", "over"),
    "bal_cap_case": ("present", "absent"),
    "bal_cap_side": ("at_cap", "over_cap"),
    "tx_validity_case": ("present", "absent"),
    "tx_validity_kind": (
        "above_total_cap",
        "intrinsic_short",
        "floor_short",
        "floor_above_cap",
    ),
    "tx_validity_type": ("0", "1", "2", "3", "4"),
    "graver_tx": ("present", "absent"),
    "graver_beneficiary": ("nonexistent", "empty", "alive"),
    "graver_value": ("nonzero", "zero"),
    "creation_tx": ("present", "absent"),
    "creation_target": ("fresh", "balance_only", "nonce", "code"),
    "near_full_block": ("present", "absent"),
    "near_full_stores": ("150", "160"),
    "near_full_margin": ("exact", "over"),
    "near_full_kind": ("state", "execution"),
    "deployer_tx": ("present", "absent"),
    "deployer_kind": ("CREATE", "CREATE2", "near_max_nonce", "max_nonce"),
    "max_nonce_block": ("present", "absent"),
    "max_nonce_rejected": ("yes", "no"),
    "max_nonce_account": ("present", "absent"),
    "request_tx": ("present", "absent"),
    "request_kind": (
        "DepositRequest",
        "WithdrawalRequest",
        "ConsolidationRequest",
        "BuilderDepositRequest",
        "BuilderExitRequest",
    ),
    "request_valid": ("yes", "no"),
    "max_initcode_tx": ("present", "absent"),
    "max_initcode_size": ("exact", "one_over"),
    "delegated_call_tx": ("present", "absent"),
    "delegated_target": ("warm", "cold"),
    "deployer_initcode": ("empty", "nonempty"),
    "negative_case": ("present", "absent"),
    "negative_family": tuple(NEGATIVE_KINDS),
    **{
        f"negative_{family}_kind": kinds
        for family, kinds in NEGATIVE_KINDS.items()
    },
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


def binomial_lower_tail(at_most: int, total: int, share: float) -> float:
    """
    P(X <= ``at_most``) for X binomial over ``total`` trials at ``share``.

    Summed in log space: at counts in the thousands a term's binomial
    coefficient no longer fits a float, and the plain product raised
    `OverflowError` out of the health check.
    """
    if share >= 1:
        return 1.0 if at_most >= total else 0.0
    log_share, log_rest = log(share), log(1 - share)
    logs = [
        lgamma(total + 1)
        - lgamma(k + 1)
        - lgamma(total - k + 1)
        + k * log_share
        + (total - k) * log_rest
        for k in range(at_most + 1)
    ]
    peak = max(logs)
    return min(1.0, exp(peak) * sum(exp(v - peak) for v in logs))


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
        chance = binomial_lower_tail(after, before + after, share)
        if chance < alpha:
            drops.append(
                f"{name} {before}/{previous_seeds} -> "
                f"{after}/{current_seeds} (p={chance:.1e})"
            )
    return drops


def significant_rises(
    previous: Dict[str, int],
    current: Dict[str, int],
    previous_seeds: int,
    current_seeds: int,
    tolerance: float = REGRESSION_TOLERANCE,
    alpha: float = REGRESSION_ALPHA,
) -> List[str]:
    """
    Event counts that rose further than ``tolerance`` *and* further than
    sampling explains: `significant_drops` turned around. Under an
    unchanged rate a later count this high is an earlier one this low,
    given the total of the two, at the earlier sample's share.
    """
    share = previous_seeds / (previous_seeds + current_seeds)
    rises = []
    for name, before in sorted(previous.items()):
        after = current.get(name, 0)
        if before <= 0:
            continue
        before_rate = before / previous_seeds
        after_rate = after / current_seeds
        if (after_rate - before_rate) / before_rate <= tolerance:
            continue
        chance = binomial_lower_tail(before, before + after, share)
        if chance < alpha:
            rises.append(
                f"{name} {before}/{previous_seeds} -> "
                f"{after}/{current_seeds} (p={chance:.1e})"
            )
    return rises


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
