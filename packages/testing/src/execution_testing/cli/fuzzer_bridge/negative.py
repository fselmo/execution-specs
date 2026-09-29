"""
Negative cases: a filled block modified so every client must refuse it.

A case drawn negative is filled once as it is, then again with its last
block modified, and the fixture expects that block rejected. Two families:

- **BAL:** the block access list is changed one way. In the `delivered`
  variant only the list delivered beside the payload changes, and the
  header keeps the hash of the true list, so what is tested is the client
  comparing what it was given with what it executes. In the `rehashed`
  variant the header commits to the changed list, so the block's own
  validation must refuse it.
- **header:** one header field is corrupted and the block hash
  recomputed. The requests are the exception: the engine payload carries
  the requests and not their hash, so a request the block never produced
  is delivered and the header commits to it.

A client that answers VALID to a negative case fails its fixture, as one
that answers INVALID to a clean case does: both are findings, through the
campaign's ordinary verdicts.
"""

import random
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from execution_testing.base_types import Address, Hash
from execution_testing.exceptions import BlockException
from execution_testing.test_types.block_access_list import (
    BalAccountChange,
    BlockAccessList,
)
from execution_testing.test_types.block_access_list import (
    modifiers as bal_modifiers,
)

BAL_KINDS: Tuple[str, ...] = (
    "drop_account",
    "drop_storage_read",
    "change_value",
    "move_index",
    "add_untouched",
    "reorder",
    "duplicate",
)
BAL_VARIANTS: Tuple[str, ...] = ("delivered", "rehashed")
HEADER_KINDS: Tuple[str, ...] = (
    "number",
    "timestamp",
    "gas_used",
    "receipts_root",
    "requests",
)
"""The header fields a negative case corrupts. A block above the RLP size
limit is not among them: no generated block comes near it within the
block's gas, and a case that did would be a ten-megabyte fixture."""

UNTOUCHED_ADDRESS = Address(0x2DEAD)
"""An address no generated case touches, added to a list by
`add_untouched`."""

Modifier = Callable[[BlockAccessList], BlockAccessList]


def _changes(bal: BlockAccessList) -> List[Tuple[str, Address, int, int]]:
    """Every scalar change in ``bal``: (kind, address, index, value)."""
    found: List[Tuple[str, Address, int, int]] = []
    for account in bal.root:
        for change in account.balance_changes or []:
            found.append(
                (
                    "balance",
                    account.address,
                    int(change.block_access_index),
                    int(change.post_balance),
                )
            )
        for nonce in account.nonce_changes or []:
            found.append(
                (
                    "nonce",
                    account.address,
                    int(nonce.block_access_index),
                    int(nonce.post_nonce),
                )
            )
    return found


def bal_modifier(
    kind: str, bal: BlockAccessList, pick: int
) -> Optional[Modifier]:
    """
    The modification of ``kind`` to make to ``bal``, its target chosen by
    ``pick``; None when this list has nothing that kind can change (no
    storage read to drop, fewer than two indices to swap).
    """
    rng = random.Random(pick)
    accounts = list(bal.root)
    if kind == "drop_account":
        return bal_modifiers.remove_accounts(rng.choice(accounts).address)
    if kind == "drop_storage_read":
        readers = [a for a in accounts if a.storage_reads]
        if not readers:
            return None
        return bal_modifiers.remove_storage_reads(rng.choice(readers).address)
    if kind == "change_value":
        changes = _changes(bal)
        if not changes:
            return None
        what, address, index, value = rng.choice(changes)
        if what == "balance":
            return bal_modifiers.modify_balance(address, index, value + 1)
        if what == "nonce":
            return bal_modifiers.modify_nonce(address, index, value + 1)
        raise ValueError(f"unknown change {what!r}")
    if kind == "move_index":
        indices = sorted({i for _, _, i, _ in _changes(bal)})
        if len(indices) < 2:
            return None
        first, second = rng.sample(indices, 2)
        return bal_modifiers.swap_bal_indices(first, second)
    if kind == "add_untouched":
        return bal_modifiers.append_account(
            BalAccountChange(address=UNTOUCHED_ADDRESS)
        )
    if kind == "reorder":
        if len(accounts) < 2:
            return None
        return bal_modifiers.reverse_accounts()
    if kind == "duplicate":
        return bal_modifiers.duplicate_account(rng.choice(accounts).address)
    raise ValueError(f"unknown BAL modification {kind!r}")


def header_overrides(
    kind: str,
    header: Mapping[str, Any],
    parent: Mapping[str, Any],
    pick: int,
) -> Dict[str, Any]:
    """
    The block fields corrupting ``kind`` in a block whose fixture header is
    ``header`` and parent's is ``parent``, with the exception a client must
    answer it with.
    """
    from execution_testing.base_types import Bytes
    from execution_testing.specs.blockchain import Header

    rng = random.Random(pick)
    if kind == "number":
        fields: Dict[str, Any] = {"number": int(header["number"], 16) + 1}
        exception = BlockException.INVALID_BLOCK_NUMBER
    elif kind == "timestamp":
        fields = {"timestamp": int(parent["timestamp"], 16)}
        exception = BlockException.INVALID_BLOCK_TIMESTAMP_OLDER_THAN_PARENT
    elif kind == "gas_used":
        fields = {"gas_used": int(header["gasLimit"], 16) + 1}
        exception = BlockException.INVALID_GAS_USED_ABOVE_LIMIT
    elif kind == "receipts_root":
        fields = {"receipts_root": Hash(rng.getrandbits(256))}
        exception = BlockException.INVALID_RECEIPTS_ROOT
    elif kind == "requests":
        # One deposit of random bytes, type byte then its 192 bytes of data;
        # the header's hash is recomputed over it.
        deposit = Bytes(b"\x00" + rng.randbytes(192))
        return {
            "requests": [deposit],
            "exception": BlockException.INVALID_REQUESTS,
        }
    else:
        raise ValueError(f"unknown header corruption {kind!r}")
    return {"rlp_modifier": Header(**fields), "exception": exception}


def last_block_overrides(
    draw: Mapping[str, Any], clean: Mapping[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    The fields to set on the last block of a case drawn negative, from its
    clean `blockchain_test` fixture; None when the draw has nothing to
    change in this case.
    """
    from execution_testing.base_types import Bytes
    from execution_testing.test_types.block_access_list import (
        BlockAccessListExpectation,
    )

    blocks = clean["blocks"]
    last = blocks[-1]
    if draw["family"] == "bal":
        bal = BlockAccessList.model_validate(last["blockAccessList"])
        modifier = bal_modifier(draw["kind"], bal, draw["pick"])
        if modifier is None:
            return None
        exception = BlockException.INVALID_BLOCK_ACCESS_LIST
        if draw["variant"] == "delivered":
            return {
                "engine_new_payload_block_access_list": Bytes(
                    modifier(bal).rlp
                ),
                "exception": exception,
            }
        if draw["variant"] == "rehashed":
            return {
                "expected_block_access_list": BlockAccessListExpectation(
                    account_expectations={}
                ).modify(modifier),
                "exception": exception,
            }
        raise ValueError(f"unknown BAL variant {draw['variant']!r}")
    if draw["family"] == "header":
        parent = (
            blocks[-2]["blockHeader"]
            if len(blocks) > 1
            else clean["genesisBlockHeader"]
        )
        return header_overrides(
            draw["kind"], last["blockHeader"], parent, draw["pick"]
        )
    raise ValueError(f"unknown negative family {draw['family']!r}")


def modify_last_block(test: Any, overrides: Mapping[str, Any]) -> None:
    """Set ``overrides`` on the last block of the `BlockchainTest` ``test``."""
    test.blocks[-1] = test.blocks[-1].model_copy(update=dict(overrides))
    test.is_exception_test = True
