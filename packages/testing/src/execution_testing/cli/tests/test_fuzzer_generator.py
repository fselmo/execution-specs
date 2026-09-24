"""Tests for the seeded fuzzer generator, minimizer, and fuzz engine."""

from execution_testing import Address
from execution_testing.forks import Osaka

from ..fuzzer_bridge.corpus import minimize
from ..fuzzer_bridge.generator import (
    AUTHORITY_ACCOUNTS,
    DESTRUCTOR_ADDRESS,
    FAILER_ADDRESS,
    GENERATOR_VERSION,
    INTERLEAVER_ADDRESS,
    SPILLER_ADDRESS,
    TOUCHER_ADDRESS,
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
    # Authorities carry keys too but send nothing; the senders are the
    # key-holders a transaction is actually from.
    senders = [
        a
        for addr, a in out.accounts.items()
        if a.private_key is not None
        and any(tx.from_ == addr for tx in out.transactions)
    ]
    keyed = [a for a in out.accounts.values() if a.private_key is not None]
    assert len(keyed) == 2 + AUTHORITY_ACCOUNTS
    contracts = [
        a
        for addr, a in out.accounts.items()
        if a.code
        and addr
        not in (
            Address(DESTRUCTOR_ADDRESS),
            Address(SPILLER_ADDRESS),
            Address(INTERLEAVER_ADDRESS),
            Address(FAILER_ADDRESS),
            Address(TOUCHER_ADDRESS),
        )
    ]
    assert len(senders) <= 2
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


def test_generator_version_covers_the_shape_era() -> None:
    """
    Shapes, the epilogue and the wider palette shipped as v5.

    Pinned as a floor, not an equality: the exact version is enforced
    where it carries meaning -- the reach gate's baseline check, which
    fails on any bump until the gate is deliberately re-baselined.
    """
    assert GENERATOR_VERSION >= 5


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
    """Each block's transaction gas limits sum to at most its own limit."""
    for seed in range(60):
        out = generate_fuzzer_output(Osaka, seed)
        for block in range(out.block_count):
            assert sum(
                int(tx.gas) for tx in out.transactions if tx.block == block
            ) <= int(out.env.gas_limit), (seed, block)
        assert out.transactions


def test_the_coinbase_aliases_every_kind_of_account() -> None:
    """
    The fee recipient is drawn from four pools; a sender coinbase is one
    of that case's own senders and a code coinbase one of its contracts,
    so the alias is real, not a lookalike address.
    """
    from execution_testing.cli.fuzzer_bridge.generator import FIXED_COINBASE
    from execution_testing.eip_properties import fuzz_precompile_targets
    from execution_testing.forks import Amsterdam

    precompiles = set(fuzz_precompile_targets(Amsterdam))
    seen = set()
    for seed in range(120):
        case = generate_fuzzer_output(Amsterdam, seed)
        coinbase = int.from_bytes(bytes(case.env.fee_recipient), "big")
        senders = {
            int.from_bytes(bytes(a), "big")
            for a, acc in case.accounts.items()
            if acc.private_key is not None
        }
        contracts = {
            int.from_bytes(bytes(a), "big")
            for a, acc in case.accounts.items()
            if acc.code and acc.private_key is None
        }
        if coinbase in senders:
            seen.add("sender")
        elif coinbase in contracts:
            seen.add("code")
        elif coinbase in precompiles:
            seen.add("precompile")
        else:
            assert coinbase == FIXED_COINBASE
            seen.add("fixed")
    assert seen == {"fixed", "sender", "code", "precompile"}


def test_a_filled_case_carries_the_fork_s_system_contracts() -> None:
    """
    The fill merges the fork's predeploys into the pre-state, so a client
    routing BLOCKHASH or the beacon root through a system contract's
    storage adds an access the block access list can see. This pins it:
    without the contracts the phantom read would be undetectable.
    """
    from execution_testing.cli.fuzzer_bridge.campaign import fill_case
    from execution_testing.client_clis.clis.execution_specs import (
        ExecutionSpecsTransitionTool,
    )
    from execution_testing.forks import Amsterdam

    fixture = fill_case(
        generate_fuzzer_output(Amsterdam, 3),
        Amsterdam,
        ExecutionSpecsTransitionTool(),
    )
    pre = {int(address, 16) for address in fixture["pre"]}
    system = {
        int.from_bytes(bytes(a), "big") for a in Amsterdam.system_contracts()
    }
    assert system and system <= pre
    # The predeploy mapping is keyed by int, not Address.
    predeploys = {int(a) for a in Amsterdam.pre_allocation_blockchain()}
    assert predeploys <= pre
