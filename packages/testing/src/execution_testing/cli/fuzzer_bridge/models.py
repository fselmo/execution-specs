"""
Pydantic models for fuzzer output format v2.

This module defines Data Transfer Objects (DTOs) for parsing
fuzzer output. These DTOs are intentionally separate from EEST
domain models (Transaction, Account) to maintain clean separation
between external data format and internal representation.

Design Principle:
- DTOs (this file): Parse external JSON-RPC standard format
- Domain Models (EEST): Internal test generation logic
- Converter (converter.py): Explicit transformation between the two
"""

from typing import Dict, List

from pydantic import BaseModel, ConfigDict, Field

from execution_testing.base_types import (
    AccessList,
    Address,
    Bytes,
    CamelModel,
    Hash,
    HexNumber,
)
from execution_testing.forks import Fork
from execution_testing.test_types import Environment


class FuzzerAccountInput(BaseModel):
    """
    Raw account data from fuzzer output.

    This is a DTO that accepts fuzzer's JSON format without triggering
    EEST's Account validation logic or defaults.
    """

    model_config = ConfigDict(populate_by_name=True)

    balance: HexNumber
    nonce: HexNumber = HexNumber(0)
    code: Bytes = Bytes(b"")
    storage: Dict[HexNumber, HexNumber] = Field(default_factory=dict)
    private_key: Hash | None = Field(None, alias="privateKey")


class FuzzerAuthorizationInput(BaseModel):
    """
    Raw authorization tuple from fuzzer output (EIP-7702).

    Accepts fuzzer's camelCase JSON format.
    """

    model_config = ConfigDict(populate_by_name=True)

    chain_id: HexNumber = Field(..., alias="chainId")
    address: Address
    nonce: HexNumber
    v: HexNumber = HexNumber(0)  # yParity
    r: HexNumber = HexNumber(0)
    s: HexNumber = HexNumber(0)
    signer_key: Hash | None = Field(None, alias="signerKey")
    """Private key of the authority. A raw fuzzer output carries `v`, `r`
    and `s`; a generated one carries the key and is signed by the
    framework at conversion, the way a sender is signed from its
    account's `private_key`."""


class FuzzerTransactionInput(BaseModel):
    """
    Raw transaction data from fuzzer output.

    This is a DTO that accepts standard Ethereum JSON-RPC transaction format
    without triggering EEST's Transaction.model_post_init logic.

    Key differences from EEST Transaction:
    - Uses "gas" not "gas_limit" (JSON-RPC standard)
    - Uses "data" not "input" (JSON-RPC standard)
    - Uses "from" not "sender" (JSON-RPC standard)
    - No automatic TestAddress injection
    - No automatic transaction type detection
    - No automatic signature handling
    """

    model_config = ConfigDict(populate_by_name=True)

    from_: Address = Field(..., alias="from")
    to: Address | None = None
    gas: HexNumber  # Will be mapped to gas_limit in converter
    gas_price: HexNumber | None = Field(None, alias="gasPrice")
    max_fee_per_gas: HexNumber | None = Field(None, alias="maxFeePerGas")
    max_priority_fee_per_gas: HexNumber | None = Field(
        None, alias="maxPriorityFeePerGas"
    )
    nonce: HexNumber
    data: Bytes = Bytes(b"")  # Will be mapped to data/input in converter
    value: HexNumber = HexNumber(0)
    access_list: List[AccessList] | None = Field(None, alias="accessList")
    blob_versioned_hashes: List[Hash] | None = Field(
        None, alias="blobVersionedHashes"
    )
    max_fee_per_blob_gas: HexNumber | None = Field(
        None, alias="maxFeePerBlobGas"
    )
    block: int = 0
    """Which of the case's blocks the transaction goes in, decided when it
    is drawn so its fee can be drawn for that block's base fee."""
    authorization_list: List[FuzzerAuthorizationInput] | None = Field(
        None, alias="authorizationList"
    )


class FuzzerWithdrawalInput(BaseModel):
    """One withdrawal in the case's block; `amount` is in Gwei."""

    index: HexNumber
    validator_index: HexNumber = Field(..., alias="validatorIndex")
    address: Address
    amount: HexNumber

    model_config = ConfigDict(populate_by_name=True)


class FuzzerOutput(CamelModel):
    """
    Main fuzzer output format v2.

    This is the top-level DTO that parses the complete fuzzer
    output JSON. It uses pure DTOs (FuzzerAccountInput,
    FuzzerTransactionInput) to avoid triggering EEST domain
    model logic during parsing.

    After parsing, the converter will transform these DTOs into
    EEST domain models.
    """

    version: str = Field(..., pattern="^2\\.0$")
    fork: Fork
    chain_id: HexNumber = Field(HexNumber(1))
    accounts: Dict[Address, FuzzerAccountInput]
    transactions: List[FuzzerTransactionInput]
    env: Environment
    parent_beacon_block_root: Hash | None = None
    withdrawals: List[FuzzerWithdrawalInput] = Field(default_factory=list)
    block_count: int = 1
    """How many blocks the case's transactions are spread across, in nonce
    order; withdrawals go on the last. Part of the case, so a seed
    reproduces its chain and not just its transactions."""
