"""Build spec dataclasses, such as transactions, with zeroed fields."""

import dataclasses
import inspect
from types import ModuleType, UnionType
from typing import (
    Any,
    Callable,
    Dict,
    NamedTuple,
    Tuple,
    Union,
    get_args,
    get_origin,
)

from ethereum_types.bytes import Bytes
from ethereum_types.numeric import FixedUnsigned, Uint

from ethereum.state import Address

TX_SENDER = Address(b"\xaa" * 20)
TX_RECIPIENT = Address(b"\xbb" * 20)

# EIP-4844: a versioned hash starts with the KZG version byte.
VERSIONED_HASH_VERSION_KZG = b"\x01"


def _zero_value(field_type: Any) -> Any:
    origin = get_origin(field_type)
    if origin in (UnionType, Union):
        field_type = get_args(field_type)[0]
        origin = get_origin(field_type)
    if origin is tuple:
        return ()
    if origin is list:
        return []
    if isinstance(field_type, type) and issubclass(field_type, bool):
        return False
    if isinstance(field_type, type) and issubclass(
        field_type, (FixedUnsigned, Uint)
    ):
        return field_type(0)
    length = getattr(field_type, "LENGTH", None)
    if length is not None:
        return field_type(b"\x00" * length)
    return field_type(b"")


def zeroed(cls: Any, **overrides: Any) -> Any:
    """Build a dataclass with every field zero or empty except `overrides`."""
    fields = {f.name: _zero_value(f.type) for f in dataclasses.fields(cls)}
    fields.update(overrides)
    return cls(**fields)


def transaction_types(transactions: ModuleType) -> Tuple[type, ...]:
    """Return every transaction type in a fork's `Transaction` union."""
    return get_args(transactions.Transaction)


def kzg_versioned_hash(transactions: ModuleType) -> Any:
    """Return a versioned hash that passes the KZG version check."""
    return transactions.VersionedHash(
        VERSIONED_HASH_VERSION_KZG + b"\x00" * 31
    )


# Fields a transaction type cannot leave empty and still pass validation.
_REQUIRED_FIELDS: Dict[str, Callable[[ModuleType], Dict[str, Any]]] = {
    "BlobTransaction": lambda transactions: {
        "blob_versioned_hashes": (kzg_versioned_hash(transactions),),
    },
    "SetCodeTransaction": lambda transactions: {
        "authorizations": (zeroed(transactions.Authorization),),
    },
}


def build_tx(transactions: ModuleType, tx_type: type, **overrides: Any) -> Any:
    """
    Build a transaction that passes validation apart from its gas limit.

    Fields are zero except a call to `TX_RECIPIENT`, whatever `tx_type`
    needs to be well formed, and `overrides`.
    """
    required = _REQUIRED_FIELDS.get(tx_type.__name__)
    fields: Dict[str, Any] = {"to": TX_RECIPIENT}
    if required is not None:
        fields.update(required(transactions))
    fields.update(overrides)
    return zeroed(tx_type, **fields)


def legacy_tx(transactions: ModuleType, data: Bytes, to: Address) -> Any:
    """Return an unsigned legacy call to `to` carrying `data`."""
    return build_tx(
        transactions, transactions.LegacyTransaction, data=data, to=to
    )


def _takes_sender(function: Callable[..., Any]) -> bool:
    return "sender" in inspect.signature(function).parameters


def validate_tx(transactions: ModuleType, tx: Any) -> Any:
    """Validate `tx` as sent by `TX_SENDER`, if the fork needs a sender."""
    if _takes_sender(transactions.validate_transaction):
        return transactions.validate_transaction(tx, TX_SENDER)
    return transactions.validate_transaction(tx)


class Intrinsic(NamedTuple):
    """Intrinsic gas of a transaction, in names shared by every fork."""

    execution: Uint
    calldata_floor: Uint


def intrinsic_cost(transactions: ModuleType, tx: Any) -> Intrinsic:
    """
    Return the intrinsic gas of `tx` as sent by `TX_SENDER`.

    Forks before EIP-8037 call the execution part `regular`.
    """
    if _takes_sender(transactions.calculate_intrinsic_cost):
        cost = transactions.calculate_intrinsic_cost(tx, TX_SENDER)
    else:
        cost = transactions.calculate_intrinsic_cost(tx)
    if hasattr(cost, "execution"):
        execution = cost.execution
    else:
        execution = cost.regular
    return Intrinsic(Uint(execution), Uint(cost.calldata_floor))
