"""
Import a filled fixture's blocks back through EELS's own block import.

EELS fills a case with its transition tool, which builds a block and never
imports one, so the spec's import checks (`validate_header`,
`execute_block`) never run on a generated case. Importing each filled
block again through `state_transition` runs them: every block the fixture
expects valid must import, and every block it expects rejected must be
refused with the exception it names. A disagreement is a self-check
failure of the filler, scored apart from any differential verdict.

A `blockchain_test` block is imported from its RLP. A
`blockchain_test_engine` payload is imported as `newPayload` receives it:
the header is rebuilt from the payload, with the transactions, withdrawals,
requests and block access list hashed into it, and must hash to the
payload's `blockHash` before the block is executed.
"""

import importlib
import linecache
from dataclasses import dataclass
from typing import (
    Any,
    Callable,
    Iterator,
    List,
    Mapping,
    Optional,
    Tuple,
)

from ethereum.crypto.hash import keccak256
from ethereum.exceptions import EthereumException, InvalidBlock
from ethereum.merkle_patricia_trie import Trie, root, trie_set
from ethereum_rlp import rlp
from ethereum_types.numeric import U64, Uint

from execution_testing.client_clis.clis.execution_specs import (
    ExecutionSpecsExceptionMapper,
)
from execution_testing.exceptions import BlockException


class ImportCrashError(Exception):
    """EELS raised out of its import instead of accepting or rejecting."""


class BlockHashMismatchError(InvalidBlock):
    """A payload's rebuilt header does not hash to its `blockHash`."""


@dataclass(frozen=True)
class ImportResult:
    """How a fixture's blocks fared on EELS's import."""

    agreed: bool
    """Every block was imported or refused as the fixture expects."""
    reason: str = ""
    """The first disagreement, when there is one."""


BLOCK_CHECKS: Tuple[Tuple[Tuple[str, ...], BlockException], ...] = (
    (("MAX_RLP_BLOCK_SIZE",), BlockException.RLP_BLOCK_LIMIT_EXCEEDED),
    (("block_access_list_hash",), BlockException.INVALID_BLOCK_ACCESS_LIST),
    (("requests_hash",), BlockException.INVALID_REQUESTS),
    (("receipt_root",), BlockException.INVALID_RECEIPTS_ROOT),
    (
        ("header.timestamp", "parent_header.timestamp"),
        BlockException.INVALID_BLOCK_TIMESTAMP_OLDER_THAN_PARENT,
    ),
    (
        ("header.number", "parent_header.number"),
        BlockException.INVALID_BLOCK_NUMBER,
    ),
    (
        ("header.gas_used", "header.gas_limit"),
        BlockException.INVALID_GAS_USED_ABOVE_LIMIT,
    ),
    (("block_gas_used",), BlockException.INVALID_GAS_USED),
    (("block_state_root",), BlockException.INVALID_STATE_ROOT),
    (("transactions_root",), BlockException.INVALID_TRANSACTIONS_ROOT),
    (("block_logs_bloom",), BlockException.INVALID_LOG_BLOOM),
    (("withdrawals_root",), BlockException.INVALID_WITHDRAWALS_ROOT),
    (("blob_gas_used",), BlockException.INCORRECT_BLOB_GAS_USED),
    (("excess_blob_gas",), BlockException.INCORRECT_EXCESS_BLOB_GAS),
    (("base_fee_per_gas",), BlockException.INVALID_BASEFEE_PER_GAS),
    (("check_gas_limit",), BlockException.INVALID_GASLIMIT),
    (("extra_data",), BlockException.EXTRA_DATA_TOO_BIG),
    (("header.difficulty",), BlockException.INVALID_DIFFICULTY),
    (("ommers",), BlockException.INVALID_UNCLES_HASH),
    (("parent_hash",), BlockException.UNKNOWN_PARENT),
)
"""
The block checks a refusal is attributed to, by the words of the `if`
that raised it. Most of the spec's block checks raise a bare
`InvalidBlock`, so where it was raised is the only thing that names the
check. Only operands are matched, never the comparison, so a check whose
operator is mutated is still recognised.
"""


def _raising_condition(exc: BaseException) -> str:
    """The `if` line above the statement that raised ``exc``."""
    tb = exc.__traceback__
    if tb is None:
        return ""
    while tb.tb_next is not None:
        tb = tb.tb_next
    filename, line = tb.tb_frame.f_code.co_filename, tb.tb_lineno
    for lineno in range(line, max(line - 5, 0), -1):
        text = linecache.getline(filename, lineno).strip()
        if text.startswith(("if ", "elif ")):
            return text
    return linecache.getline(filename, line).strip()


def refused_as(exc: EthereumException) -> List[str]:
    """
    The EEST exceptions an EELS refusal may stand for, in a fixture's
    `expectException` spelling, or a description of the raising line when
    no known check raised it.
    """
    if isinstance(exc, BlockHashMismatchError):
        return [str(BlockException.INVALID_BLOCK_HASH)]
    condition = _raising_condition(exc)
    for words, exception in BLOCK_CHECKS:
        if all(word in condition for word in words):
            return [str(exception)]
    # A bare `InvalidBlock` names nothing, and the mapper would take it for
    # a transaction under the base fee, as older forks raised that.
    if type(exc) is not InvalidBlock or str(exc):
        mapped = ExecutionSpecsExceptionMapper().message_to_exception(
            repr(exc)
        )
        if isinstance(mapped, list):
            return [str(exception) for exception in mapped]
    return [f"{type(exc).__name__} under `{condition}`"]


def _expected_matches(expected: str, refusal: List[str]) -> bool:
    return bool(set(expected.split("|")).intersection(refusal))


Build = Callable[[], Any]


def _rlp_blocks(
    load: Any, fixture: Mapping[str, Any]
) -> Iterator[Tuple[Build, Optional[str]]]:
    for json_block in fixture["blocks"]:

        def build(json_block: Mapping[str, Any] = json_block) -> Any:
            block, header_hash, block_rlp = load.json_to_block(json_block)
            if keccak256(rlp.encode(block.header)) != header_hash:
                raise BlockHashMismatchError("header hash mismatch")
            if rlp.encode(block) != block_rlp:
                raise InvalidBlock("block RLP mismatch")
            return block

        yield build, json_block.get("expectException")


def _payload_blocks(
    load: Any, fixture: Mapping[str, Any], fork_short_name: str
) -> Iterator[Tuple[Build, Optional[str]]]:
    transactions_module = importlib.import_module(
        f"ethereum.forks.{fork_short_name}.transactions"
    )
    requests_module = importlib.import_module(
        f"ethereum.forks.{fork_short_name}.requests"
    )
    fork_module = importlib.import_module(
        f"ethereum.forks.{fork_short_name}.fork"
    )
    for new_payload in fixture["engineNewPayloads"]:
        params = new_payload["params"]

        def build(params: Any = params) -> Any:
            payload, versioned_hashes, beacon_root, requests = params
            transactions = tuple(
                raw
                if raw[0] <= 0x7F
                else rlp.decode_to(transactions_module.LegacyTransaction, raw)
                for raw in (
                    bytes.fromhex(t[2:]) for t in payload["transactions"]
                )
            )
            transactions_trie: Trie = Trie(secured=False, default=None)
            for index, tx in enumerate(transactions):
                trie_set(transactions_trie, rlp.encode(Uint(index)), tx)
            withdrawals = tuple(
                load.json_to_withdrawals(w) for w in payload["withdrawals"]
            )
            withdrawals_trie: Trie = Trie(secured=False, default=None)
            for index, withdrawal in enumerate(withdrawals):
                trie_set(
                    withdrawals_trie,
                    rlp.encode(Uint(index)),
                    rlp.encode(withdrawal),
                )
            blob_hashes = [
                "0x" + bytes(h).hex()
                for tx in transactions
                for h in getattr(
                    transactions_module.decode_transaction(tx),
                    "blob_versioned_hashes",
                    (),
                )
            ]
            if blob_hashes != list(versioned_hashes):
                raise InvalidBlock("blob versioned hashes mismatch")
            requests_hash = requests_module.compute_requests_hash(
                [bytes.fromhex(r[2:]) for r in requests]
            )
            bal = bytes.fromhex(payload["blockAccessList"][2:])
            header = load.json_to_header(
                {
                    "parentHash": payload["parentHash"],
                    "uncleHash": "0x" + fork_module.EMPTY_OMMER_HASH.hex(),
                    "coinbase": payload["feeRecipient"],
                    "stateRoot": payload["stateRoot"],
                    "transactionsTrie": "0x" + root(transactions_trie).hex(),
                    "receiptTrie": payload["receiptsRoot"],
                    "bloom": payload["logsBloom"],
                    "difficulty": "0x0",
                    "number": payload["blockNumber"],
                    "gasLimit": payload["gasLimit"],
                    "gasUsed": payload["gasUsed"],
                    "timestamp": payload["timestamp"],
                    "extraData": payload["extraData"],
                    "mixHash": payload["prevRandao"],
                    "nonce": "0x0000000000000000",
                    "baseFeePerGas": payload["baseFeePerGas"],
                    "withdrawalsRoot": "0x" + root(withdrawals_trie).hex(),
                    "blobGasUsed": payload["blobGasUsed"],
                    "excessBlobGas": payload["excessBlobGas"],
                    "parentBeaconBlockRoot": beacon_root,
                    "requestsHash": "0x" + requests_hash.hex(),
                    "blockAccessListHash": "0x" + keccak256(bal).hex(),
                    "slotNumber": payload["slotNumber"],
                }
            )
            block_hash = bytes.fromhex(payload["blockHash"][2:])
            if keccak256(rlp.encode(header)) != block_hash:
                raise BlockHashMismatchError("block hash mismatch")
            return load.fork.Block(header, transactions, (), withdrawals)

        yield build, new_payload.get("validationError")


def import_fixture(
    fixture: Mapping[str, Any], fork_short_name: str
) -> ImportResult:
    """
    Import ``fixture``'s blocks, in order, through the fork's
    `state_transition`.

    ``fixture`` is a `blockchain_test` or `blockchain_test_engine`
    fixture's JSON. A rejected block is not added to the chain, as a client
    would not add it. An exception that is not the spec's own
    (`EthereumException`) is the import crashing, not judging, and raises
    `ImportCrashError`.
    """
    from ethereum_spec_tools.loaders.fixture_loader import Load

    load = Load(fork_short_name)
    genesis_header = load.json_to_header(fixture["genesisBlockHeader"])
    parameters = [genesis_header, (), ()]
    if hasattr(genesis_header, "withdrawals_root"):
        parameters.append(())
    if hasattr(genesis_header, "requests_root"):
        parameters.append(())
    genesis_block = load.fork.Block(*parameters)
    chain = load.fork.BlockChain(
        blocks=[genesis_block],
        state=load.json_to_state(fixture["pre"]),
        chain_id=U64(int(fixture.get("config", {}).get("chainid", "0x1"), 16)),
    )
    engine = "engineNewPayloads" in fixture
    blocks = (
        _payload_blocks(load, fixture, fork_short_name)
        if engine
        else _rlp_blocks(load, fixture)
    )
    for position, (build, expected) in enumerate(blocks, start=1):
        try:
            load.fork.state_transition(chain, build())
        except EthereumException as exc:
            refusal = refused_as(exc)
            if expected is None:
                return ImportResult(
                    False,
                    f"block {position} expected valid, refused as "
                    f"{'|'.join(refusal)}: {exc}",
                )
            if not _expected_matches(expected, refusal):
                return ImportResult(
                    False,
                    f"block {position} expected {expected}, refused as "
                    f"{'|'.join(refusal)}",
                )
            continue
        except Exception as exc:
            raise ImportCrashError(
                f"block {position}: {type(exc).__name__}: {exc}"
            ) from exc
        if expected is not None:
            return ImportResult(
                False,
                f"block {position} expected {expected}, imported",
            )
    return ImportResult(True)
