"""
Import a filled fixture's blocks back through EELS's own block import.

EELS fills a case with its transition tool, which builds a block and never
imports one, so the spec's import checks (`validate_header`,
`execute_block`) never run on a generated case. Importing each filled
block again through `state_transition` runs them: every block the fixture
expects valid must import, and every block it expects rejected must be
refused. A disagreement is a self-check failure of the filler, scored
apart from any differential verdict.
"""

from dataclasses import dataclass
from typing import Any, Mapping

from ethereum.crypto.hash import keccak256
from ethereum.exceptions import EthereumException
from ethereum_rlp import rlp
from ethereum_types.numeric import U64


class ImportCrashError(Exception):
    """EELS raised out of its import instead of accepting or rejecting."""


@dataclass(frozen=True)
class ImportResult:
    """How a fixture's blocks fared on EELS's import."""

    agreed: bool
    """Every block was imported or refused as the fixture expects."""
    reason: str = ""
    """The first disagreement, when there is one."""


def import_fixture(
    fixture: Mapping[str, Any], fork_short_name: str
) -> ImportResult:
    """
    Import ``fixture``'s blocks, in order, through the fork's
    `state_transition`.

    ``fixture`` is a `blockchain_test` fixture's JSON. A rejected block is
    not added to the chain, as a client would not add it. An exception
    that is not the spec's own (`EthereumException`) is the import
    crashing, not judging, and raises `ImportCrashError`.
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
    for position, json_block in enumerate(fixture["blocks"], start=1):
        expected = json_block.get("expectException")
        try:
            block, header_hash, block_rlp = load.json_to_block(json_block)
            if keccak256(rlp.encode(block.header)) != header_hash:
                raise EthereumException("header hash mismatch")
            if rlp.encode(block) != block_rlp:
                raise EthereumException("block RLP mismatch")
            load.fork.state_transition(chain, block)
        except EthereumException as exc:
            if expected is None:
                return ImportResult(
                    False,
                    f"block {position} expected valid, refused: "
                    f"{type(exc).__name__}: {exc}",
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

