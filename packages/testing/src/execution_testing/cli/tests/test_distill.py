"""Tests for distilling a fuzzer corpus case into a readable test."""

import ast

from execution_testing.forks import Osaka

from ..fuzzer_bridge.distill import distill_source
from ..fuzzer_bridge.generator import generate_fuzzer_output


def _source(seed: int = 0) -> str:
    case = generate_fuzzer_output(
        Osaka, seed, num_senders=1, num_contracts=1, num_transactions=2
    )
    return distill_source(
        case,
        fork_name="Osaka",
        reason="unit test",
        seed=seed,
        generator_version=1,
    )


def test_distilled_source_is_valid_python() -> None:
    """The rendered test module parses as valid Python."""
    ast.parse(_source())


def test_distilled_source_is_deterministic() -> None:
    """The same case renders identically each time."""
    assert _source(3) == _source(3)


def test_provenance_in_docstring() -> None:
    """Fork, seed, generator version, and reason are recorded."""
    source = _source(7)
    assert "Fork: Osaka" in source
    assert "Seed: 7" in source
    assert "Generator version: 1" in source
    assert "Reason: unit test" in source


def test_senders_and_pre_and_txs_present() -> None:
    """The rendered module wires senders, pre-state, and transactions."""
    source = _source()
    # Tokens chosen to survive ruff line-wrapping of long calls.
    assert "sender_0 = EOA(" in source
    assert "key=0x" in source
    assert "pre = Alloc(" in source
    assert "Transaction(" in source
    assert "blockchain_test(" in source


def test_contract_code_is_rendered_faithfully() -> None:
    """A contract's generated code appears verbatim as a Bytes literal."""
    case = generate_fuzzer_output(
        Osaka, 1, num_senders=1, num_contracts=1, num_transactions=1
    )
    contract_code = next(
        bytes(a.code) for a in case.accounts.values() if a.code
    )
    source = distill_source(
        case, fork_name="Osaka", reason="code check", seed=1
    )
    # The hex string survives formatting even if the enclosing call wraps.
    assert contract_code.hex() in source


def test_transaction_targets_use_sender_variables() -> None:
    """A tx to a known account references its variable, not an address."""
    # Targets are drawn from a pool that includes precompiles and
    # never-existing addresses, so which seed sends to the sender is a
    # draw -- pinning one makes the test fail on any generation change
    # for a reason unrelated to what it checks.
    sender_directed = None
    for seed in range(40):
        case = generate_fuzzer_output(
            Osaka, seed, num_senders=1, num_contracts=0, num_transactions=3
        )
        senders = {
            address
            for address, account in case.accounts.items()
            if account.private_key is not None
        }
        if any(tx.to in senders for tx in case.transactions):
            sender_directed = (case, seed)
            break
    assert sender_directed is not None, "no seed sent to the sender"
    case, seed = sender_directed
    source = distill_source(
        case, fork_name="Osaka", reason="target check", seed=seed
    )
    assert "to=sender_0" in source
