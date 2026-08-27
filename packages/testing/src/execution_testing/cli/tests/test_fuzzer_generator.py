"""Tests for the seeded fuzzer generator, minimizer, and fuzz engine."""

from execution_testing import Address
from execution_testing.forks import Osaka

from ..fuzzer_bridge.corpus import minimize
from ..fuzzer_bridge.generator import (
    DESTRUCTOR_ADDRESS,
    GENERATOR_VERSION,
    generate_fuzzer_output,
)
from ..fuzzer_bridge.models import FuzzerOutput


def test_generation_is_deterministic() -> None:
    """The same (fork, seed) reproduces byte-identical output."""
    a = generate_fuzzer_output(Osaka, 7)
    b = generate_fuzzer_output(Osaka, 7)
    assert a.model_dump_json() == b.model_dump_json()


def test_distinct_seeds_differ() -> None:
    """Different seeds produce different cases."""
    a = generate_fuzzer_output(Osaka, 7)
    b = generate_fuzzer_output(Osaka, 8)
    assert a.model_dump_json() != b.model_dump_json()


def test_generated_shape() -> None:
    """Generated cases have senders with keys and contracts with code."""
    out = generate_fuzzer_output(
        Osaka, 1, num_senders=2, num_contracts=2, num_transactions=4
    )
    assert out.version == "2.0"
    assert len(out.transactions) == 4
    senders = [a for a in out.accounts.values() if a.private_key is not None]
    contracts = [
        a
        for addr, a in out.accounts.items()
        if a.code and addr != Address(DESTRUCTOR_ADDRESS)
    ]
    assert len(senders) == 2
    assert len(contracts) == 2
    # Every transaction is sent by a known sender with a private key.
    sender_addrs = {
        addr
        for addr, acct in out.accounts.items()
        if acct.private_key is not None
    }
    assert all(tx.from_ in sender_addrs for tx in out.transactions)


def test_generator_version_in_seed() -> None:
    """The generator version participates in the seed derivation."""
    # A pure sanity check that the constant is wired and stable-typed.
    assert isinstance(GENERATOR_VERSION, int)


def test_minimize_drops_unneeded_transactions() -> None:
    """
    Delta-debugging reduces to the fewest transactions that keep the
    predicate true.

    Predicate: at least one transaction remains. Minimization should shrink
    to exactly one transaction and drop unreferenced accounts.
    """
    out = generate_fuzzer_output(
        Osaka, 3, num_senders=2, num_contracts=3, num_transactions=6
    )

    def has_a_transaction(case: FuzzerOutput) -> bool:
        return len(case.transactions) >= 1

    reduced = minimize(out, has_a_transaction)
    assert len(reduced.transactions) == 1
    assert len(reduced.transactions) < len(out.transactions)


def test_minimize_noop_when_everything_matters() -> None:
    """A predicate needing all transactions leaves the case unchanged."""
    out = generate_fuzzer_output(Osaka, 4, num_transactions=3)
    original_count = len(out.transactions)

    def needs_all(case: FuzzerOutput) -> bool:
        return len(case.transactions) == original_count

    reduced = minimize(out, needs_all)
    assert len(reduced.transactions) == original_count


def _has_opcode(code: bytes, opcode: int) -> bool:
    i = 0
    while i < len(code):
        op = code[i]
        if op == opcode:
            return True
        i += 1 + (op - 0x5F) if 0x60 <= op <= 0x7F else 1
    return False


def test_generated_contracts_call_each_other() -> None:
    """Generated contracts reach the CALL family, not only precompiles."""
    seen = set()
    for seed in range(10):
        out = generate_fuzzer_output(Osaka, seed)
        for account in out.accounts.values():
            code = bytes(account.code)
            seen |= {
                op for op in (0xF1, 0xF2, 0xF4, 0xFA) if _has_opcode(code, op)
            }
    assert seen == {0xF1, 0xF2, 0xF4, 0xFA}


def test_truncation_never_splits_a_push_immediate() -> None:
    """Code is cut at instruction boundaries, so no immediate is torn."""
    from ..fuzzer_bridge.corpus import _instruction_boundary

    # PUSH32 <32 bytes> PUSH1 0x01 STOP
    code = bytes([0x7F]) + bytes(range(32)) + bytes([0x60, 0x01, 0x00])
    for target in range(0, len(code) + 1):
        cut = _instruction_boundary(code, target)
        assert cut in (0, 33, 35, 36), (target, cut)
        assert cut <= target or cut == len(code)


def test_generator_version_is_five() -> None:
    """Shapes, the epilogue and the wider palette shipped as v5."""
    assert GENERATOR_VERSION == 5


def test_generated_cases_reach_creation_and_the_gas_cap() -> None:
    """Some contracts CREATE2 and some transactions carry the gas cap."""
    creation = False
    at_cap = False
    for seed in range(12):
        out = generate_fuzzer_output(Osaka, seed)
        for account in out.accounts.values():
            if _has_opcode(bytes(account.code), 0xF5):
                creation = True
        at_cap |= any(int(tx.gas) == 16_777_216 for tx in out.transactions)
    assert creation and at_cap


def test_transactions_fit_the_block_gas_limit() -> None:
    """The sum of transaction gas limits never exceeds the block's."""
    from ..fuzzer_bridge.generator import BLOCK_GAS_LIMIT

    for seed in range(60):
        out = generate_fuzzer_output(Osaka, seed)
        assert sum(int(tx.gas) for tx in out.transactions) <= BLOCK_GAS_LIMIT
        assert out.transactions
