"""
Witness tests for the distribution arms.

The arms are pre-registered experiment machinery, so they get the same
discipline as a detector: if the hook silently drops a weight, or an arm
differs from its definition, the comparison stops being controlled without
anyone noticing. These tests are what keep "equal but for the weights" true.
"""

import random

import pytest

from execution_testing.cli.fuzzer_bridge.generator import (
    generate_fuzzer_output,
)
from execution_testing.forks import Amsterdam

from ..arms import GAS_C, VALUE_C, arm_domains
from ..domains import fork_domains

CALL_FAMILY = {0xF1, 0xF2, 0xF4, 0xFA}  # CALL CALLCODE DELEGATECALL STATICCALL
# Opcodes that ONLY a motif action emits (CREATE/CREATE2 are legit palette
# ops, so they are not proof of a leaked motif): the call family (message /
# precompile / destructor / halting-child), JUMP (bad-jump), and
# RETURNDATACOPY (returndata-overread).
MOTIF_MARKERS = CALL_FAMILY | {0x56, 0x3E}
GAS, SELFBALANCE, RETURNDATASIZE = 0x5A, 0x47, 0x3D


def _instructions(code: bytes) -> list:
    ops, i = [], 0
    while i < len(code):
        op = code[i]
        ops.append(op)
        i += 1 + (op - 0x5F) if 0x60 <= op <= 0x7F else 1
    return ops


# The generator deploys fuzzed contracts at 0x10000+ and one fixed helper
# (ORIGIN SELFDESTRUCT) at DESTRUCTOR_ADDRESS; only the former are fuzzed
# bodies with an epilogue.
_FUZZED_CONTRACTS = frozenset(0x10000 + i for i in range(3))


def _all_bytecode(arm: str, seeds: int = 40) -> list:
    """The instruction stream of every fuzzed contract across ``seeds``."""
    domains = arm_domains(Amsterdam, arm)
    streams = []
    for seed in range(seeds):
        out = generate_fuzzer_output(Amsterdam, seed, domains=domains)
        for address, account in out.accounts.items():
            addr_int = int.from_bytes(bytes(address), "big")
            if account.code and addr_int in _FUZZED_CONTRACTS:
                streams.append(_instructions(bytes(account.code)))
    return streams


def test_hook_is_distribution_neutral() -> None:
    """Passing the fork-default domains reproduces the generator exactly."""
    default = generate_fuzzer_output(Amsterdam, 7)
    injected = generate_fuzzer_output(
        Amsterdam, 7, domains=fork_domains(Amsterdam)
    )
    assert default.model_dump_json() == injected.model_dump_json()
    # Arm (d) is the fork default, so it too is byte-identical.
    d = generate_fuzzer_output(
        Amsterdam, 7, domains=arm_domains(Amsterdam, "d")
    )
    assert d.model_dump_json() == default.model_dump_json()


def test_arm_is_deterministic() -> None:
    """A given (fork, seed, arm) yields identical output."""
    a = arm_domains(Amsterdam, "c")
    first = generate_fuzzer_output(Amsterdam, 3, domains=a).model_dump_json()
    second = generate_fuzzer_output(Amsterdam, 3, domains=a).model_dump_json()
    assert first == second


def test_unknown_arm_raises() -> None:
    """An unknown arm fails loudly, never silently defaults."""
    with pytest.raises(ValueError, match="unknown arm"):
        arm_domains(Amsterdam, "z")


def test_arm_a_injects_no_motif_and_keeps_the_epilogue() -> None:
    """
    The floor is runnable-random: no motif or call action fires, but the
    epilogue (part of the oracle, not a strategy) stays -- every body ends
    by storing GAS, RETURNDATASIZE and SELFBALANCE.
    """
    streams = _all_bytecode("a")
    assert streams
    for ops in streams:
        assert not (set(ops) & MOTIF_MARKERS), "arm (a) leaked a motif/call"
        tail = ops[-12:]
        assert GAS in tail and RETURNDATASIZE in tail and SELFBALANCE in tail


def test_arm_b_boundary_sets_are_non_empty() -> None:
    """
    Arm (b) draws boundary-only; a domain with an empty fork-derived
    boundary set would silently fall back, so assert each is non-empty.
    """
    domains = arm_domains(Amsterdam, "b")
    assert domains.call_gas_boundaries
    assert domains.value_boundaries
    # Operand and size boundary sets are static (U256 edges / word sizes) and
    # non-empty by construction; the fork-derived one is call gas.


def test_arm_c_reproduces_goevmlab_gas_and_value_frequencies() -> None:
    """
    Arm (c)'s mixtures are goevmlab's, not an approximation.

    Over 200k draws the realized zero/full fractions match the transplanted
    randInt constants within 1%. (Gas's full mode is None -- forward via GAS;
    value's full mode exceeds one byte -- so both modes are identifiable.)
    """
    domains = arm_domains(Amsterdam, "c")
    rng = random.Random(0)
    n = 200_000
    tol = 0.01

    gas = [domains.call_gas(rng) for _ in range(n)]
    gas_zero = sum(1 for g in gas if g == 0) / n
    gas_full = sum(1 for g in gas if g is None) / n
    assert abs(gas_zero - GAS_C.zero) < tol
    assert abs(gas_full - GAS_C.full) < tol

    value = [domains.call_value(rng) for _ in range(n)]
    value_zero = sum(1 for v in value if v == 0) / n
    value_full = sum(1 for v in value if v > 0xFF) / n
    assert abs(value_zero - VALUE_C.zero) < tol
    assert abs(value_full - VALUE_C.full) < tol
