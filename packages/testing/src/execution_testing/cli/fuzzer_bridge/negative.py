"""
Negative cases: a filled block modified so every client must refuse it.

A case drawn negative is filled once as it is, then again with its last
block modified, and the fixture expects that block rejected. Four families:

- **bal:** the list's content is changed one way: an entry dropped, a
  value or index changed, an account added. The header commits to the
  changed list, so the block's own validation must refuse it.
- **form:** the list keeps its content but breaks a canonical-form rule:
  an order, a duplicate, a key both read and written, an empty slot, an
  index past the block, a change to the value already there. A client
  that compares lists after normalizing them misses these.
- **encoding:** the header commits to bytes no canonical encoder writes:
  a scalar with a leading zero, a byte after the list, a 19-byte address,
  a string where a list goes. Engine only, as a block's RLP carries no
  list.
- **header:** one header field is corrupted. The requests are the
  exception: the engine payload carries the requests and not their hash,
  so a request the block never produced is delivered and the header
  commits to it. The two-dimensional `gas_used` kinds put the block's
  execution plus state gas, or what its senders paid, where the larger
  of the two belongs (EIP-8037).

Every kind recomputes the block hash from the header rebuilt from the
modified payload, since that is the header a client derives from it.

A list delivered beside a header that keeps the true list's hash cannot
be a negative on the engine path: a client derives the header's list hash
from the list it is given, so the block hash no longer matches and the
payload is refused on its hash before any list check runs (669 besu and
nethermind failures at v32 were that, not client bugs). It is the import
lane's instead (`delivered_list_fixture`), as a valid-block case: the
header commits to the true list, so the block is valid and expected
valid, and only the delivered list a block-test runner attaches is wrong.
The runner interface (§1) has a runner hash the delivered list against
the header and drop it on a mismatch, so a client must import the block;
one that rejects it is using a list it should have dropped. EELS imports
it as an ordinary valid block, since it never reads that list.

A client that answers VALID to a negative case fails its fixture, as one
that answers INVALID to a clean case does: both are findings, through the
campaign's ordinary verdicts.
"""

import random
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

import ethereum_rlp as eth_rlp

from execution_testing.base_types import Address, Bytes, Hash
from execution_testing.exceptions import BlockException
from execution_testing.test_types.block_access_list import (
    BalAccountChange,
    BalBalanceChange,
    BalNonceChange,
    BalStorageChange,
    BalStorageSlot,
    BlockAccessList,
)
from execution_testing.test_types.block_access_list import (
    modifiers as bal_modifiers,
)

NEGATIVE_KINDS: Dict[str, Tuple[str, ...]] = {
    "bal": (
        "drop_account",
        "drop_storage_read",
        "change_value",
        "move_index",
        "add_untouched",
    ),
    "form": (
        "reorder",
        "duplicate",
        "reverse_field",
        "duplicate_field",
        "read_and_write",
        "empty_slot",
        "index_past_block",
        "noop_change",
    ),
    "encoding": (
        "non_minimal_scalar",
        "trailing_bytes",
        "short_address",
        "string_for_list",
    ),
    "header": (
        "number",
        "timestamp",
        "gas_used",
        "receipts_root",
        "requests",
        "gas_used_sum",
        "gas_used_receipts",
    ),
}
"""Every family's kinds. A block above the RLP size limit is not among
them: no generated block comes near it within the block's gas, and a case
that did would be a ten-megabyte fixture."""

LIST_FAMILIES = ("bal", "form", "encoding")
"""The families that change the block access list."""

UNTOUCHED_ADDRESS = Address(0x2DEAD)
"""An address no generated case touches, added to a list by
`add_untouched`."""

FIELD_LISTS = (
    "storage_changes",
    "storage_reads",
    "balance_changes",
    "nonce_changes",
    "code_changes",
)
"""An account's lists, each sorted and free of duplicates."""

Modifier = Callable[[BlockAccessList], BlockAccessList]
Encoder = Callable[[BlockAccessList], Bytes]


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


def content_modifier(
    kind: str, bal: BlockAccessList, pick: int
) -> Optional[Modifier]:
    """
    The `bal` modification of ``kind`` to make to ``bal``, its target
    chosen by ``pick``; None when this list has nothing that kind can
    change (no storage read to drop, fewer than two indices to swap).
    """
    rng = random.Random(pick)
    accounts = list(bal.root)
    if kind == "drop_account":
        return bal_modifiers.remove_accounts(rng.choice(accounts).address)
    elif kind == "drop_storage_read":
        readers = [a for a in accounts if a.storage_reads]
        if not readers:
            return None
        return bal_modifiers.remove_storage_reads(rng.choice(readers).address)
    elif kind == "change_value":
        changes = _changes(bal)
        if not changes:
            return None
        what, address, index, value = rng.choice(changes)
        if what == "balance":
            return bal_modifiers.modify_balance(address, index, value + 1)
        elif what == "nonce":
            return bal_modifiers.modify_nonce(address, index, value + 1)
        raise ValueError(f"unknown change {what!r}")
    elif kind == "move_index":
        indices = sorted({i for _, _, i, _ in _changes(bal)})
        if len(indices) < 2:
            return None
        first, second = rng.sample(indices, 2)
        return bal_modifiers.swap_bal_indices(first, second)
    elif kind == "add_untouched":
        # Sorted back into place, so the list's only fault is the account.
        append = bal_modifiers.append_account(
            BalAccountChange(address=UNTOUCHED_ADDRESS)
        )
        sort = bal_modifiers.sort_accounts_by_address()
        return lambda b: sort(append(b))
    raise ValueError(f"unknown BAL modification {kind!r}")


def _post_value(post: Mapping[str, Any], address: Address, field: str) -> int:
    """``address``'s ``field`` in a fixture's post state, 0 if absent."""
    for key, account in post.items():
        if Address(key) == address:
            return int(account.get(field, "0x0"), 16)
    return 0


def _post_storage(post: Mapping[str, Any], address: Address, slot: int) -> int:
    """``address``'s ``slot`` in a fixture's post state, 0 if absent."""
    for key, account in post.items():
        if Address(key) == address:
            for stored_slot, value in account.get("storage", {}).items():
                if int(stored_slot, 16) == slot:
                    return int(value, 16)
    return 0


REVERSERS: Dict[str, Callable[[Address], Modifier]] = {
    "storage_changes": bal_modifiers.reverse_storage_slots,
    "storage_reads": bal_modifiers.reverse_storage_reads,
    "balance_changes": bal_modifiers.reverse_balance_changes,
    "nonce_changes": bal_modifiers.reverse_nonce_changes,
    "code_changes": bal_modifiers.reverse_code_changes,
}


def form_modifier(
    kind: str,
    bal: BlockAccessList,
    pick: int,
    transactions: int,
    post: Mapping[str, Any],
) -> Optional[Modifier]:
    """
    The `form` modification of ``kind`` to make to ``bal``, the last
    list of a block with ``transactions`` transactions whose fixture
    post state is ``post``; None when this list has nothing to break.

    Each breaks one rule and leaves the rest canonical: a new entry goes
    where its order puts it.
    """
    rng = random.Random(pick)
    accounts = list(bal.root)
    if kind == "reorder":
        if len(accounts) < 2:
            return None
        return bal_modifiers.reverse_accounts()
    elif kind == "duplicate":
        return bal_modifiers.duplicate_account(rng.choice(accounts).address)
    elif kind == "reverse_field":
        lists: List[Modifier] = []
        for a in accounts:
            for field in FIELD_LISTS:
                if len(getattr(a, field)) >= 2:
                    lists.append(REVERSERS[field](a.address))
            for slot in a.storage_changes:
                if len(slot.slot_changes) >= 2:
                    lists.append(
                        bal_modifiers.reverse_slot_changes(
                            a.address, int(slot.slot)
                        )
                    )
        return rng.choice(lists) if lists else None
    elif kind == "duplicate_field":
        entries: List[Modifier] = []
        for a in accounts:
            for nonce in a.nonce_changes:
                entries.append(
                    bal_modifiers.duplicate_nonce_change(
                        a.address, int(nonce.block_access_index)
                    )
                )
            for balance in a.balance_changes:
                entries.append(
                    bal_modifiers.duplicate_balance_change(
                        a.address, int(balance.block_access_index)
                    )
                )
            for code in a.code_changes:
                entries.append(
                    bal_modifiers.duplicate_code_change(
                        a.address, int(code.block_access_index)
                    )
                )
            for read in a.storage_reads:
                entries.append(
                    bal_modifiers.duplicate_storage_read(a.address, int(read))
                )
            for stored in a.storage_changes:
                entries.append(
                    bal_modifiers.duplicate_storage_slot(
                        a.address, int(stored.slot)
                    )
                )
                for write in stored.slot_changes:
                    entries.append(
                        bal_modifiers.duplicate_slot_change(
                            a.address,
                            int(stored.slot),
                            int(write.block_access_index),
                        )
                    )
        return rng.choice(entries) if entries else None
    elif kind == "read_and_write":
        written = [
            (a.address, int(s.slot))
            for a in accounts
            for s in a.storage_changes
        ]
        if not written:
            return None
        return bal_modifiers.insert_storage_read(*rng.choice(written))
    elif kind == "empty_slot":
        account = rng.choice(accounts)
        # Past every key the account holds, so the slot sorts last and
        # names no key already read.
        key = 1 + max(
            [int(s.slot) for s in account.storage_changes]
            + [int(r) for r in account.storage_reads],
            default=-1,
        )
        return bal_modifiers.append_empty_slot(account.address, key)
    elif kind == "index_past_block":
        # One past the post-execution index, with a balance that differs
        # from the account's, so the index is the change's only fault.
        account = rng.choice(accounts)
        held = _post_value(post, account.address, "balance")
        return bal_modifiers.append_change(
            account.address,
            BalBalanceChange(
                block_access_index=transactions + 2, post_balance=held + 1
            ),
        )
    elif kind == "noop_change":
        # A change at index 1 to the value the account holds throughout
        # the block: one it never changes there, so its post-state value
        # is also its value before the block.
        targets: List[Tuple[str, Address, int]] = []
        for a in accounts:
            if not a.balance_changes:
                targets.append(("balance", a.address, 0))
            if not a.nonce_changes:
                targets.append(("nonce", a.address, 0))
            for read in a.storage_reads:
                targets.append(("storage", a.address, int(read)))
        if not targets:
            return None
        what, address, key = rng.choice(targets)
        if what == "balance":
            return bal_modifiers.append_change(
                address,
                BalBalanceChange(
                    block_access_index=1,
                    post_balance=_post_value(post, address, "balance"),
                ),
            )
        elif what == "nonce":
            return bal_modifiers.append_change(
                address,
                BalNonceChange(
                    block_access_index=1,
                    post_nonce=_post_value(post, address, "nonce"),
                ),
            )
        elif what == "storage":
            return _read_to_noop_write(
                address, key, _post_storage(post, address, key)
            )
        raise ValueError(f"unknown no-op target {what!r}")
    raise ValueError(f"unknown BAL form violation {kind!r}")


def _read_to_noop_write(address: Address, slot: int, value: int) -> Modifier:
    """Turn ``address``'s read of ``slot`` into a write of ``value``."""

    def transform(bal: BlockAccessList) -> BlockAccessList:
        root = []
        for account in bal.root:
            if account.address == address:
                account = account.model_copy(deep=True)
                account.storage_reads = [
                    r for r in account.storage_reads if int(r) != slot
                ]
                account.storage_changes = sorted(
                    [
                        *account.storage_changes,
                        BalStorageSlot(
                            slot=slot,
                            slot_changes=[
                                BalStorageChange(
                                    block_access_index=1, post_value=value
                                )
                            ],
                        ),
                    ],
                    key=lambda s: int(s.slot),
                )
            root.append(account)
        return BlockAccessList(root=root)

    return transform


def encoder(kind: str, bal: BlockAccessList, pick: int) -> Optional[Encoder]:
    """
    The `encoding` of ``kind`` to give ``bal``, its target chosen by
    ``pick``; None when this list has nothing that kind can re-encode.
    """
    rng = random.Random(pick)
    accounts = list(bal.root)
    if kind == "non_minimal_scalar":
        scalars: List[Tuple[Address, Any]] = []
        for a in accounts:
            if a.storage_changes:
                scalars += [
                    (a.address, "storage_slot"),
                    (a.address, "storage_value"),
                ]
            if a.storage_reads:
                scalars.append((a.address, "storage_read"))
            if a.balance_changes:
                scalars += [
                    (a.address, "balance"),
                    (a.address, "block_access_index"),
                ]
            if a.nonce_changes:
                scalars.append((a.address, "nonce"))
        if not scalars:
            return None
        return bal_modifiers.encode_scalar_non_minimally(*rng.choice(scalars))
    elif kind == "trailing_bytes":
        return lambda b: Bytes(eth_rlp.encode(b.to_list()) + b"\x00")
    elif kind == "short_address":
        position = rng.randrange(len(accounts))

        def short_address(b: BlockAccessList) -> Bytes:
            elements = b.to_list()
            elements[position][0] = bytes(elements[position][0])[:19]
            return Bytes(eth_rlp.encode(elements))

        return short_address
    elif kind == "string_for_list":
        empty = [
            (position, BalAccountChange.rlp_fields.index(field))
            for position, a in enumerate(accounts)
            for field in FIELD_LISTS
            if not getattr(a, field)
        ]
        if not empty:
            return None
        position, index = rng.choice(empty)

        def string_for_list(b: BlockAccessList) -> Bytes:
            elements = b.to_list()
            elements[position][index] = b""
            return Bytes(eth_rlp.encode(elements))

        return string_for_list
    raise ValueError(f"unknown BAL encoding {kind!r}")


LIST_EXCEPTIONS: Dict[str, Any] = {
    "reorder": [
        BlockException.INCORRECT_BLOCK_FORMAT,
        BlockException.INVALID_BLOCK_ACCESS_LIST,
    ],
    "duplicate": [
        BlockException.INCORRECT_BLOCK_FORMAT,
        BlockException.INVALID_BLOCK_ACCESS_LIST,
    ],
    "non_minimal_scalar": [
        BlockException.INVALID_BLOCK_ACCESS_LIST,
        BlockException.INVALID_BLOCK_HASH,
    ],
    "trailing_bytes": [
        BlockException.INVALID_BLOCK_ACCESS_LIST,
        BlockException.INVALID_BLOCK_HASH,
    ],
    "short_address": [
        BlockException.INVALID_BLOCK_ACCESS_LIST,
        BlockException.INVALID_BLOCK_HASH,
    ],
}
"""The list kinds a client may refuse other than as
`INVALID_BLOCK_ACCESS_LIST`, as EEST's own tests name them. Accounts out
of order or listed twice are a format error there; EELS, which checks
only the list's hash, refuses them as the list. A list a lenient decoder
accepts and re-encodes differently fails the client's block hash
instead."""


def header_overrides(
    kind: str,
    header: Mapping[str, Any],
    parent: Mapping[str, Any],
    pick: int,
    gas: Any = None,
) -> Optional[Dict[str, Any]]:
    """
    The block fields corrupting ``kind`` in a block whose fixture header is
    ``header`` and parent's is ``parent``, with the exception a client must
    answer it with. The `gas_used_*` kinds need the block's ``gas``
    (`eels_import.BlockGas`) and are None where the value they would
    write is the header's own, another kind's, or above the gas limit,
    which a client refuses first.
    """
    from execution_testing.base_types import Bytes as RequestBytes
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
        deposit = RequestBytes(b"\x00" + rng.randbytes(192))
        return {
            "requests": [deposit],
            "exception": BlockException.INVALID_REQUESTS,
        }
    elif kind in ("gas_used_sum", "gas_used_receipts"):
        if gas is None:
            return None
        if kind == "gas_used_sum":
            wrong = gas.execution + gas.state
        else:
            # Without a refund or a binding floor the senders pay exactly
            # the sum, and this would be `gas_used_sum` again.
            if gas.receipts == gas.execution + gas.state:
                return None
            wrong = gas.receipts
        if wrong == int(header["gasUsed"], 16) or wrong > int(
            header["gasLimit"], 16
        ):
            return None
        fields = {"gas_used": wrong}
        exception = BlockException.INVALID_GAS_USED
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
    from execution_testing.test_types.block_access_list import (
        BlockAccessListExpectation,
    )

    from .eels_import import last_block_gas

    blocks = clean["blocks"]
    last = blocks[-1]
    family, kind, pick = draw["family"], draw["kind"], draw["pick"]
    if family in LIST_FAMILIES:
        bal = BlockAccessList.model_validate(last["blockAccessList"])
        modifier: Optional[Modifier]
        if family == "bal":
            modifier = content_modifier(kind, bal, pick)
        elif family == "form":
            modifier = form_modifier(
                kind,
                bal,
                pick,
                len(last.get("transactions", [])),
                clean["postState"],
            )
        elif family == "encoding":
            encode = encoder(kind, bal, pick)
            modifier = bal_modifiers.override_rlp(encode) if encode else None
        else:
            raise ValueError(f"unknown list family {family!r}")
        if modifier is None:
            return None
        return {
            "expected_block_access_list": BlockAccessListExpectation(
                account_expectations={}
            ).modify(modifier),
            "exception": LIST_EXCEPTIONS.get(
                kind, BlockException.INVALID_BLOCK_ACCESS_LIST
            ),
        }
    elif family == "header":
        parent = (
            blocks[-2]["blockHeader"]
            if len(blocks) > 1
            else clean["genesisBlockHeader"]
        )
        gas = (
            last_block_gas(clean, clean["network"].lower())
            if kind.startswith("gas_used_")
            else None
        )
        return header_overrides(kind, last["blockHeader"], parent, pick, gas)
    raise ValueError(f"unknown negative family {family!r}")


DELIVERED_FAMILIES = ("bal", "form")
"""The families whose list a block-test runner can be handed: an encoding
fault does not survive the fixture's JSON, which carries a decoded
list."""


def delivered_list_fixture(
    clean: Mapping[str, Any], rehashed: Mapping[str, Any]
) -> Dict[str, Any]:
    """
    The import lane's delivered-list case: ``clean``, the case as filled,
    with its last block's delivered list swapped for the changed one from
    ``rehashed``, the case filled with that list committed to. The header
    and RLP are the clean fill's, committing to the true list, so the block
    is valid and expected valid; only the list a runner attaches is wrong.
    """
    changed = rehashed["blocks"][-1]["rlp_decoded"]["blockAccessList"]
    fixture = dict(clean)
    last = {**clean["blocks"][-1], "blockAccessList": changed}
    fixture["blocks"] = [*clean["blocks"][:-1], last]
    return fixture


def delivered_list_fault(fixture: Mapping[str, Any]) -> str:
    """
    Why ``fixture`` is not a delivered-list case, or "" when it is: its
    last block is expected valid, and the list it delivers is not the one
    the block's header commits to.
    """
    block = fixture["blocks"][-1]
    if "expectException" in block:
        return "delivered-list case: last block expected rejected"
    delivered = BlockAccessList.model_validate(block["blockAccessList"])
    committed = block["blockHeader"]["blockAccessListHash"]
    if Hash(delivered.rlp_hash) == Hash(committed):
        return "delivered-list case: the delivered list is the true one"
    return ""


def modify_last_block(test: Any, overrides: Mapping[str, Any]) -> None:
    """Set ``overrides`` on the last block of the `BlockchainTest` ``test``."""
    test.blocks[-1] = test.blocks[-1].model_copy(update=dict(overrides))
    test.is_exception_test = True
