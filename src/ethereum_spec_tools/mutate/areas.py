"""
The spec areas `ethereum-spec-mutate` knows: the functions it mutates and
the tests that must notice.

An area names spec functions by file, relative to the fork's package (or
to `src/` with a leading `@` for code outside the forks), the property
tests that cover them, and optionally the EEST tests whose filled fixtures
are an oracle too. Keep an area to the functions its tests claim to cover:
a mutant outside them measures nothing.
"""

from dataclasses import dataclass, field
from typing import Dict, Tuple

GAS = "vm/gas.py"
TRANSACTIONS = "transactions.py"
FORK = "fork.py"
BAL = "block_access_lists.py"
DELEGATION = "vm/eoa_delegation.py"


@dataclass(frozen=True)
class Area:
    """Spec functions and the tests that cover them."""

    functions: Tuple[Tuple[str, Tuple[str, ...]], ...]
    """Per file, the functions mutated (a name, or a prefix ending in `*`)."""
    properties: Tuple[str, ...] = ()
    """Modules under `tests_property/` that cover the functions."""
    fixtures: Tuple[str, ...] = ()
    """EEST test paths whose fixtures, filled once from the unmutated spec,
    the mutated spec must still import as filled."""
    forked: bool = True
    """Whether the property tests take the fork axis (`-k <Fork>`)."""
    notes: Dict[str, str] = field(default_factory=dict)
    """Mutants known to be equivalent, by `Mutant.construct`, with the
    reason."""


AREAS: Dict[str, Area] = {
    "memory-expansion": Area(
        functions=(
            (
                GAS,
                ("calculate_memory_gas_cost", "calculate_gas_extend_memory"),
            ),
        ),
        properties=("test_gas",),
    ),
    "call-gas": Area(
        functions=(
            (GAS, ("calculate_message_call_gas", "max_message_call_gas")),
        ),
        properties=("test_gas_meter",),
    ),
    "gas-meter": Area(
        functions=(
            (
                GAS,
                (
                    "check_gas",
                    "charge_gas_from_meter",
                    "charge_state_gas_from_meter",
                ),
            ),
        ),
        properties=("test_gas_meter",),
    ),
    "blob-pricing": Area(
        functions=(
            (
                GAS,
                (
                    "calculate_excess_blob_gas",
                    "calculate_total_blob_gas",
                    "calculate_blob_gas_price",
                    "calculate_data_fee",
                ),
            ),
            ("@ethereum/utils/numeric.py", ("taylor_exponential",)),
        ),
        properties=("test_gas",),
    ),
    "base-fee": Area(
        functions=((FORK, ("calculate_base_fee_per_gas",)),),
        properties=("test_gas", "test_header_validation"),
    ),
    "header-validation": Area(
        functions=((FORK, ("validate_header", "check_gas_limit")),),
        properties=("test_header_validation",),
    ),
    "tx-admission": Area(
        functions=(
            (FORK, ("check_transaction",)),
            (
                GAS,
                ("check_max_fee_per_blob_gas", "check_block_gas_capacity"),
            ),
            (
                TRANSACTIONS,
                (
                    "calculate_effective_gas_price",
                    "calculate_max_gas_fee",
                    "check_nonce",
                ),
            ),
        ),
        properties=("test_transaction_admission",),
    ),
    "intrinsic-gas": Area(
        functions=(
            (
                TRANSACTIONS,
                (
                    "validate_transaction",
                    "calculate_intrinsic_cost",
                    "count_tokens_in_data",
                ),
            ),
        ),
        properties=("test_transaction_gas", "test_transaction_admission"),
    ),
    "tx-encoding": Area(
        functions=(
            (TRANSACTIONS, ("encode_transaction", "decode_transaction")),
        ),
        properties=("test_rlp",),
    ),
    "signatures": Area(
        functions=(
            (
                TRANSACTIONS,
                ("chain_id", "recover_sender", "signing_hash_*"),
            ),
        ),
        properties=("test_signatures",),
    ),
    "bal": Area(
        functions=(
            (
                BAL,
                (
                    "ensure_account",
                    "add_*",
                    "remove_*",
                    "_build_from_builder",
                    "_get_pre_tx_account",
                    "_get_pre_tx_storage",
                    "_index_start_*",
                    "update_builder_from_tx",
                    "build_block_access_list",
                    "validate_block_access_list_gas_limit",
                ),
            ),
        ),
        properties=("test_block_access_list", "test_state_machine"),
        fixtures=("tests/amsterdam/eip7928_block_level_access_lists",),
        notes={
            "add_nonce_change: new_nonce > existing.new_nonce -> new_nonce "
            ">= existing.new_nonce": "It rewrites the same nonce.",
            "add_code_change: ensure_account(builder, address) -> pass": (
                "Every code change comes with a nonce change at the same "
                "index, a creation or a delegation, which added the account."
            ),
            "_get_pre_tx_storage: U256(0) -> Uint(0)": (
                "`Uint` and `U256` compare by value."
            ),
            "update_builder_from_tx: U256(0) -> Uint(0)": (
                "`Uint` and `U256` compare by value."
            ),
            "update_builder_from_tx: Uint(0) -> U256(0)": (
                "`Uint` and `U256` compare by value."
            ),
            "update_builder_from_tx: U64(post_nonce) -> Uint(post_nonce)": (
                "The same RLP encoding, and validity keeps a nonce below "
                "2**64."
            ),
            "update_builder_from_tx: remove_nonce_change(builder, address, "
            "idx) -> pass": (
                "Only a second system call at the same index could need it, "
                "and no system call moves a nonce back."
            ),
            "update_builder_from_tx: remove_code_change(builder, address, "
            "idx) -> pass": (
                "Only a second system call at the same index could need it, "
                "and no system call restores code it changed."
            ),
        },
    ),
    "eip7702": Area(
        functions=(
            (
                DELEGATION,
                (
                    "is_valid_delegation",
                    "get_delegated_code_address",
                    "resolve_delegated_code_address",
                    "recover_authority",
                    "calculate_delegation_cost",
                    "validate_authorization",
                    "set_delegation",
                ),
            ),
        ),
        fixtures=(
            "tests/prague/eip7702_set_code_tx",
            # The transaction's own call to a delegated account is charged
            # in the top frame from EIP-2780 on.
            "tests/amsterdam/eip2780_reduce_intrinsic_tx_gas",
        ),
        notes={
            "is_valid_delegation: len(code) == EOA_DELEGATED_CODE_LENGTH "
            "and code[:EOA_DELEGATION_MARKER_LENGTH] == "
            "EOA_DELEGATION_MARKER -> code[:EOA_DELEGATION_MARKER_LENGTH] "
            "== EOA_DELEGATION_MARKER": (
                "No account holds the marker at another length: EIP-3541 "
                "rejects deploying it and `set_delegation` writes 23 bytes."
            ),
            "calculate_delegation_cost: GasCosts.ZERO -> "
            "GasCosts.CREATE_ACCESS": (
                "The cost is charged only when the account is delegated."
            ),
            "calculate_delegation_cost: GasCosts.ZERO -> "
            "GasCosts.MEMORY_PER_WORD": (
                "The cost is charged only when the account is delegated."
            ),
            **{
                f"recover_authority: {original} -> {mutated}": (
                    "`secp256k1_recover` rejects r and s outside "
                    "1..N-1 itself."
                )
                for original, mutated in (
                    ("U256(0) >= r or r >= SECP256K1N", "False"),
                    (
                        "U256(0) >= r or r >= SECP256K1N",
                        "U256(0) >= r and r >= SECP256K1N",
                    ),
                    ("U256(0) >= r or r >= SECP256K1N", "r >= SECP256K1N"),
                    ("U256(0) >= r or r >= SECP256K1N", "U256(0) >= r"),
                    ("U256(0) >= r", "U256(0) > r"),
                    ("r >= SECP256K1N", "r > SECP256K1N"),
                    (
                        "U256(0) >= s or s > SECP256K1N // U256(2)",
                        "s > SECP256K1N // U256(2)",
                    ),
                    ("U256(0) >= s", "U256(0) > s"),
                )
            },
            "recover_authority: 32 -> 33": "The hash is 32 bytes long.",
        },
    ),
    "trie": Area(
        functions=(("@ethereum/merkle_patricia_trie.py", ("*",)),),
        properties=("test_trie",),
        forked=False,
    ),
}
