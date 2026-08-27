"""
Properties of the [EIP-7825] transaction gas-limit cap.

[EIP-7825] introduces a cap on the gas limit a single transaction may
specify:

    > This proposal introduces a protocol-level cap on the maximum gas
    > usage per transaction to 16,777,216 (2^24) gas.

and, on the rejection side:

    > Transactions specifying gas limits higher than 16,777,216 gas will
    > be rejected with an appropriate error code (e.g.,
    > `MAX_GAS_LIMIT_EXCEEDED`).

with the block-validation rule pinning the boundary to a strict
inequality (at the cap is valid; strictly above is invalid):

    > any block having a transaction with `gasLimit` > 16,777,216 is
    > deemed invalid and rejected.

These properties are grounded in that prose, not in the spec's own
implementation of the check, so they cannot restate the code they guard.

Note on the fork-covariant behaviour: Osaka enforces the cap against the
transaction's *declared* gas limit (`tx.gas`), raising
`TransactionGasLimitExceededError`. Amsterdam keeps the same 2^24 constant
but re-anchors it onto the *intrinsic* gas cost under its repriced gas
model (raising `InsufficientTransactionGasError`), so it does not reject an
over-cap `tx.gas`. The declared-gas boundary is therefore only asserted on
forks that enforce it directly; the constant and the at-cap validity hold
on both.

[EIP-7825]: https://eips.ethereum.org/EIPS/eip-7825
"""

import importlib
from types import ModuleType
from typing import Any

import pytest
from ethereum_types.bytes import Bytes
from ethereum_types.numeric import U8, U64, U256, Uint
from hypothesis import given
from hypothesis import strategies as st

from ethereum.state import Address

# Value asserted directly from EIP-7825 prose ("2^24 (16,777,216) units"),
# independent of the spec constant it is compared against.
EIP_7825_GAS_CAP = 2**24

SENDER = Address(b"\xaa" * 20)
RECIPIENT = Address(b"\xbb" * 20)

# Osaka rejects a transaction whose declared gas limit exceeds the cap.
# Amsterdam re-anchors the same cap onto intrinsic gas (see module docstring),
# so the declared-gas boundary is only asserted where enforced directly.
FORKS_REJECTING_OVER_CAP_TX_GAS = {"osaka"}

TX_TYPES = [
    "legacy",
    "access_list",
    "fee_market",
    "blob",
    "set_code",
]


@pytest.fixture(scope="session")
def transactions(fork_name: str) -> ModuleType:
    """Transactions module of the fork under test."""
    return importlib.import_module(f"ethereum.forks.{fork_name}.transactions")


@pytest.fixture(scope="session")
def fork_exceptions(fork_name: str) -> ModuleType:
    """Fork-local exceptions module of the fork under test."""
    return importlib.import_module(f"ethereum.forks.{fork_name}.exceptions")


def build_tx(
    transactions: ModuleType, tx_type: str, gas: Uint, to: Address
) -> Any:
    """
    Build a minimal, otherwise-valid transaction of the given type whose
    only interesting field is `gas`. Signatures are never inspected by
    `validate_transaction`, so placeholder values suffice; blob and
    set-code transactions carry the single blob hash / authorization that
    validation requires.
    """
    if tx_type == "legacy":
        return transactions.LegacyTransaction(
            nonce=U256(0),
            gas_price=Uint(10),
            gas=gas,
            to=to,
            value=U256(0),
            data=Bytes(b""),
            v=U256(27),
            r=U256(1),
            s=U256(1),
        )
    elif tx_type == "access_list":
        return transactions.AccessListTransaction(
            chain_id=U64(1),
            nonce=U256(0),
            gas_price=Uint(10),
            gas=gas,
            to=to,
            value=U256(0),
            data=Bytes(b""),
            access_list=(),
            y_parity=U256(0),
            r=U256(1),
            s=U256(1),
        )
    elif tx_type == "fee_market":
        return transactions.FeeMarketTransaction(
            chain_id=U64(1),
            nonce=U256(0),
            max_priority_fee_per_gas=Uint(1),
            max_fee_per_gas=Uint(10),
            gas=gas,
            to=to,
            value=U256(0),
            data=Bytes(b""),
            access_list=(),
            y_parity=U256(0),
            r=U256(1),
            s=U256(1),
        )
    elif tx_type == "blob":
        return transactions.BlobTransaction(
            chain_id=U64(1),
            nonce=U256(0),
            max_priority_fee_per_gas=Uint(1),
            max_fee_per_gas=Uint(10),
            gas=gas,
            to=to,
            value=U256(0),
            data=Bytes(b""),
            access_list=(),
            max_fee_per_blob_gas=U256(1),
            blob_versioned_hashes=(
                transactions.VersionedHash(b"\x01" + b"\x00" * 31),
            ),
            y_parity=U256(0),
            r=U256(1),
            s=U256(1),
        )
    elif tx_type == "set_code":
        return transactions.SetCodeTransaction(
            chain_id=U64(1),
            nonce=U64(0),
            max_priority_fee_per_gas=Uint(1),
            max_fee_per_gas=Uint(10),
            gas=gas,
            to=to,
            value=U256(0),
            data=Bytes(b""),
            access_list=(),
            authorizations=(
                transactions.Authorization(
                    chain_id=U256(1),
                    address=to,
                    nonce=U64(0),
                    y_parity=U8(0),
                    r=U256(1),
                    s=U256(1),
                ),
            ),
            y_parity=U256(0),
            r=U256(1),
            s=U256(1),
        )
    else:
        raise ValueError(f"unhandled transaction type: {tx_type}")


def validate(fork_name: str, transactions: ModuleType, tx: Any) -> Any:
    """Adapt to the per-fork `validate_transaction` calling convention."""
    if fork_name == "osaka":
        return transactions.validate_transaction(tx)
    elif fork_name == "amsterdam":
        return transactions.validate_transaction(tx, SENDER)
    else:
        raise ValueError(f"unhandled fork: {fork_name}")


def test_cap_constant_matches_eip(transactions: ModuleType) -> None:
    """
    The spec's cap constant equals the value EIP-7825 fixes.

    EIP-7825 states the cap value directly:

        > a protocol-level cap on the maximum gas usage per transaction to
        > 16,777,216 (2^24) gas.

    Grounding: EIP prose. Non-circular because the expected value is taken
    from the EIP text, not read back from the spec.
    """
    assert transactions.TX_MAX_GAS_LIMIT == Uint(EIP_7825_GAS_CAP)


@pytest.mark.parametrize("tx_type", TX_TYPES)
def test_at_cap_is_valid(
    fork_name: str, transactions: ModuleType, tx_type: str
) -> None:
    """
    A transaction whose declared gas limit is exactly the cap is not
    rejected. EIP-7825 rejects a transaction only when its `gasLimit` is
    "higher than 16,777,216" (`gasLimit > 16,777,216`), so the cap value
    itself sits on the valid side of the boundary.

    Grounding: EIP prose (`> 16,777,216` ⇒ the cap itself is allowed). The
    transaction is otherwise minimal (empty data, no access list, valid
    nonce, non-creation) so nothing but the cap governs the outcome.
    """
    tx = build_tx(
        transactions, tx_type, gas=Uint(EIP_7825_GAS_CAP), to=RECIPIENT
    )
    validate(fork_name, transactions, tx)


@pytest.mark.parametrize("tx_type", TX_TYPES)
@given(excess=st.integers(min_value=1, max_value=2**63))
def test_above_cap_is_rejected(
    fork_name: str,
    transactions: ModuleType,
    fork_exceptions: ModuleType,
    tx_type: str,
    excess: int,
) -> None:
    """
    A transaction whose declared gas limit exceeds the cap is invalidated.

    EIP-7825 requires such a transaction to be rejected:

        > Transactions specifying gas limits higher than 16,777,216 gas
        > will be rejected with an appropriate error code.

    The spec enforces this in `validate_transaction` by raising
    `TransactionGasLimitExceededError` (a subclass of `InvalidTransaction`).

    Grounding: EIP prose for the rejection; the exact exception type is the
    documented enforcement. Non-circular: the threshold used here is the
    EIP-stated 2^24, not the spec constant, and the transaction is minimal
    so the intrinsic-gas / init-code / nonce checks cannot fire first.
    """
    if fork_name not in FORKS_REJECTING_OVER_CAP_TX_GAS:
        pytest.skip(
            f"{fork_name} does not cap declared tx.gas directly "
            "(see module docstring)"
        )
    tx = build_tx(
        transactions,
        tx_type,
        gas=Uint(EIP_7825_GAS_CAP + excess),
        to=RECIPIENT,
    )
    with pytest.raises(fork_exceptions.TransactionGasLimitExceededError):
        validate(fork_name, transactions, tx)


@pytest.mark.parametrize("tx_type", TX_TYPES)
def test_boundary_is_exact(
    fork_name: str,
    transactions: ModuleType,
    fork_exceptions: ModuleType,
    tx_type: str,
) -> None:
    """
    The cap boundary is exact: `cap` gas validates but `cap + 1` is
    rejected. This pins EIP-7825's `gasLimit > 16,777,216` to a strict
    inequality (inclusive at the cap), distinguishing `>` from `>=` in the
    check.

    Grounding: EIP prose. Non-circular for the same reasons as
    `test_above_cap_is_rejected`.
    """
    if fork_name not in FORKS_REJECTING_OVER_CAP_TX_GAS:
        pytest.skip(
            f"{fork_name} does not cap declared tx.gas directly "
            "(see module docstring)"
        )
    at_cap = build_tx(
        transactions, tx_type, gas=Uint(EIP_7825_GAS_CAP), to=RECIPIENT
    )
    validate(fork_name, transactions, at_cap)

    above = build_tx(
        transactions, tx_type, gas=Uint(EIP_7825_GAS_CAP + 1), to=RECIPIENT
    )
    with pytest.raises(fork_exceptions.TransactionGasLimitExceededError):
        validate(fork_name, transactions, above)
