"""
Transaction types as reach cells.

Before these, a typed transaction was not rare in the reach map; it was
absent from it, and no rate floor or gate can see a dimension that has
no cell. The type is folded into the signature from the input -- an
analytic witness, since `TransactionStart` carries nothing -- and the
map's `no-tx-type` bucket is derived from the fork's types minus what
the generator declares it emits, so it cannot drift from generation.
"""

from typing import Any

from execution_testing.base_types import Address, Bytes, Hash, HexNumber
from execution_testing.cli.fuzzer_bridge import signature_baseline as base
from execution_testing.cli.fuzzer_bridge.campaign import fill_case
from execution_testing.cli.fuzzer_bridge.generator import (
    GENERATED_TX_TYPES,
    generate_fuzzer_output,
)
from execution_testing.cli.fuzzer_bridge.models import (
    FuzzerAccountInput,
    FuzzerOutput,
    FuzzerTransactionInput,
)
from execution_testing.client_clis.clis.execution_specs import (
    ExecutionSpecsTransitionTool,
)
from execution_testing.evm_tools.t8n.evm_trace.signature import (
    Signature,
    merge_signatures,
)
from execution_testing.forks import Amsterdam
from execution_testing.test_types import Environment
from execution_testing.test_types.account_types import EOA
from execution_testing.vm import Opcodes as Op


def _signed_case(**tx_fields: Any) -> FuzzerOutput:
    """A one-transaction case whose transaction fields are the argument."""
    key = Hash((21).to_bytes(32, "big"))
    sender = Address(EOA(key=key))
    target = Address(0x60000)
    return FuzzerOutput(
        version="2.0",
        fork=Amsterdam,
        accounts={
            sender: FuzzerAccountInput(
                balance=HexNumber(10**18), private_key=key
            ),
            target: FuzzerAccountInput(
                balance=HexNumber(0), code=Bytes(bytes(Op.STOP))
            ),
        },
        transactions=[
            FuzzerTransactionInput(
                **{"from": sender},
                to=target,
                gas=HexNumber(100_000),
                nonce=HexNumber(0),
                **tx_fields,
            )
        ],
        env=Environment(
            fee_recipient=Address(0xC0FFEE),
            gas_limit=30_000_000,
            number=1,
            timestamp=1000,
            prev_randao=Hash(0),
            base_fee_per_gas=7,
        ),
    )


def _fill_types(case: FuzzerOutput) -> frozenset:
    eels = ExecutionSpecsTransitionTool()
    eels.compute_signature = True
    eels.last_signature = None
    fill_case(case, Amsterdam, eels)
    assert eels.last_signature is not None
    return eels.last_signature.tx_types


def test_merge_unions_transaction_types() -> None:
    """Types accumulate across a case's blocks like every other layer."""
    a = Signature(
        frozenset(), frozenset(), frozenset(), tx_types=frozenset({0})
    )
    b = Signature(
        frozenset(), frozenset(), frozenset(), tx_types=frozenset({2})
    )
    assert merge_signatures(a, b).tx_types == {0, 2}


def test_a_generated_case_reports_the_types_it_carries() -> None:
    """The witness reflects the input: today's generator emits legacy only."""
    eels = ExecutionSpecsTransitionTool()
    eels.compute_signature = True
    eels.last_signature = None
    fill_case(generate_fuzzer_output(Amsterdam, 9001), Amsterdam, eels)
    assert eels.last_signature is not None
    assert eels.last_signature.tx_types == GENERATED_TX_TYPES


def test_a_typed_transaction_lights_its_cell() -> None:
    """
    Kill check: the wiring must respond to a type the generator cannot
    yet produce, or the cell would stay dark for the wrong reason once
    generation widens.
    """
    fee_market = _signed_case(
        max_fee_per_gas=HexNumber(20), max_priority_fee_per_gas=HexNumber(1)
    )
    assert _fill_types(fee_market) == {2}
    legacy = _signed_case(gas_price=HexNumber(10))
    assert _fill_types(legacy) == {0}


def test_unreached_types_are_the_fork_types_minus_what_was_seen() -> None:
    """The tracker names every accepted type no case carried."""
    tracker = base.NoveltyTracker()
    tracker.observe(
        Signature(
            frozenset(), frozenset(), frozenset(), tx_types=frozenset({0})
        )
    )
    assert tracker.unreached_tx_types(Amsterdam) == [1, 2, 3, 4]
    tracker.observe(
        Signature(
            frozenset(), frozenset(), frozenset(), tx_types=frozenset({2})
        )
    )
    assert tracker.unreached_tx_types(Amsterdam) == [1, 3, 4]


def test_the_no_tx_type_bucket_is_derived_not_listed(monkeypatch: Any) -> None:
    """
    Widening generation must move the entry by itself. If the bucket
    were hand-listed, the next generator version would report a type it
    emits as blind, which is the flattening the buckets exist to stop.
    """
    from execution_testing.cli.fuzzer_bridge import generator

    blind = base.generator_blind(Amsterdam)["no-tx-type"]
    assert [t for t, _ in blind] == [
        f"tx type {t} ({base.TX_TYPE_NAMES[t]})" for t in (1, 2, 3, 4)
    ]
    monkeypatch.setattr(generator, "GENERATED_TX_TYPES", frozenset({0, 2, 4}))
    widened = base.generator_blind(Amsterdam)["no-tx-type"]
    assert [t for t, _ in widened] == [
        f"tx type {t} ({base.TX_TYPE_NAMES[t]})" for t in (1, 3)
    ]


def test_every_bucket_renders_with_its_reason() -> None:
    """A dark target is named with why, never flattened to 'unreachable'."""
    tracker = base.NoveltyTracker()
    text = base.render_unreached(tracker, Amsterdam)
    assert "unreached tx types (5)" in text
    for bucket in base.BLIND_BUCKETS:
        assert f"generator-blind, {bucket}" in text
    assert "the generator does not emit it" in text
    assert "block-level generation" in text
