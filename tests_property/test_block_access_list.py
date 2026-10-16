"""
Properties of the [EIP-7928] block access list builder.

The list must come out in one canonical form, sorted and deduplicated, and
record each change against the state at the start of its block access index.

[EIP-7928]: https://eips.ethereum.org/EIPS/eip-7928
"""

from types import ModuleType
from typing import Any, Dict, List, Set, Tuple

import pytest
from ethereum_types.bytes import Bytes32
from ethereum_types.numeric import U64, U256, Uint
from execution_testing.forks import Fork
from hypothesis import assume, given
from hypothesis import strategies as st

from ethereum.crypto.hash import keccak256
from ethereum.state import EMPTY_CODE_HASH, Account, Address
from ethereum.state_mpt import State

from .forks import requires
from .strategies import bytes_data, u64s, u256s

pytestmark = requires(lambda fork: fork.header_bal_hash_required())

# Addresses whose sorted order differs from their listed order, so a
# missing sort shows up.
ADDR_POOL = [
    Address(b"\x03" + b"\x00" * 19),
    Address(b"\x01" + b"\x00" * 19),
    Address(b"\x02" + b"\xff" * 19),
    Address(b"\xff" * 20),
]

# A few slots, so that writes to the same slot happen often.
SLOT_POOL = [U256(0), U256(1), U256(2), U256((1 << 256) - 1)]


def _slots() -> st.SearchStrategy[U256]:
    return st.one_of(st.sampled_from(SLOT_POOL), u256s())


def _indices() -> st.SearchStrategy[int]:
    # Small indices collide often; large ones exercise the full U32 range.
    return st.one_of(
        st.integers(min_value=0, max_value=6),
        st.integers(min_value=0, max_value=(1 << 32) - 1),
    )


BuilderOp = Tuple[Any, ...]


def _ops() -> st.SearchStrategy[List[BuilderOp]]:
    """Return sequences of builder operations over the address pool."""
    addr = st.sampled_from(ADDR_POOL)
    return st.lists(
        st.one_of(
            st.tuples(
                st.just("storage_write"), addr, _slots(), _indices(), u256s()
            ),
            st.tuples(st.just("storage_read"), addr, _slots()),
            st.tuples(st.just("balance"), addr, _indices(), u256s()),
            st.tuples(st.just("nonce"), addr, _indices(), u64s()),
            st.tuples(
                st.just("code"), addr, _indices(), bytes_data(max_size=8)
            ),
            st.tuples(st.just("touch"), addr),
        ),
        max_size=30,
    )


def _feed(bal: ModuleType, builder: Any, ops: List[BuilderOp]) -> None:
    """Replay a list of operations against a builder."""
    for op in ops:
        kind = op[0]
        if kind == "storage_write":
            _, address, slot, index, value = op
            bal.add_storage_write(
                builder, address, slot, bal.BlockAccessIndex(index), value
            )
        elif kind == "storage_read":
            _, address, slot = op
            bal.add_storage_read(builder, address, slot)
        elif kind == "balance":
            _, address, index, balance = op
            bal.add_balance_change(
                builder, address, bal.BlockAccessIndex(index), balance
            )
        elif kind == "nonce":
            _, address, index, nonce = op
            bal.add_nonce_change(
                builder, address, bal.BlockAccessIndex(index), nonce
            )
        elif kind == "code":
            _, address, index, code = op
            bal.add_code_change(
                builder, address, bal.BlockAccessIndex(index), code
            )
        elif kind == "touch":
            _, address = op
            bal.add_touched_account(builder, address)
        else:
            raise ValueError(f"unhandled op: {kind}")


def _build(bal: ModuleType, tracker: ModuleType, builder: Any) -> Any:
    """Build the list from `builder` over a block that read nothing."""
    block_state = tracker.BlockState(pre_state=State())
    return bal.build_block_access_list(builder, block_state)


def _built(bal: ModuleType, tracker: ModuleType, ops: List[BuilderOp]) -> Any:
    """Feed `ops` into a fresh builder and return the built list."""
    builder = bal.BlockAccessListBuilder()
    _feed(bal, builder, ops)
    return _build(bal, tracker, builder)


def _norm(block_access_list: Any) -> List[Tuple[Any, ...]]:
    """Convert a built list into plain, comparable tuples."""
    out = []
    for account in block_access_list:
        storage_changes = tuple(
            (
                int(slot_changes.slot),
                tuple(
                    (int(c.block_access_index), int(c.new_value))
                    for c in slot_changes.changes
                ),
            )
            for slot_changes in account.storage_changes
        )
        storage_reads = tuple(int(slot) for slot in account.storage_reads)
        balance_changes = tuple(
            (int(c.block_access_index), int(c.post_balance))
            for c in account.balance_changes
        )
        nonce_changes = tuple(
            (int(c.block_access_index), int(c.new_nonce))
            for c in account.nonce_changes
        )
        code_changes = tuple(
            (int(c.block_access_index), bytes(c.new_code))
            for c in account.code_changes
        )
        out.append(
            (
                bytes(account.address),
                storage_changes,
                storage_reads,
                balance_changes,
                nonce_changes,
                code_changes,
            )
        )
    return out


def _model(ops: List[BuilderOp]) -> List[Tuple[Any, ...]]:
    """
    Reference model of the canonical list, written from the EIP-7928 rules
    rather than from the builder's code.
    """
    seen: Set[bytes] = set()
    storage: Dict[bytes, Dict[int, Dict[int, int]]] = {}
    reads: Dict[bytes, Set[int]] = {}
    balances: Dict[bytes, Dict[int, int]] = {}
    nonces: Dict[bytes, Dict[int, int]] = {}
    codes: Dict[bytes, Dict[int, bytes]] = {}

    for op in ops:
        kind = op[0]
        address = bytes(op[1])
        seen.add(address)
        if kind == "storage_write":
            _, _, slot, index, value = op
            by_slot = storage.setdefault(address, {})
            by_slot.setdefault(int(slot), {})[int(index)] = int(value)
        elif kind == "storage_read":
            _, _, slot = op
            reads.setdefault(address, set()).add(int(slot))
        elif kind == "balance":
            _, _, index, balance = op
            balances.setdefault(address, {})[int(index)] = int(balance)
        elif kind == "nonce":
            _, _, index, nonce = op
            nonce_at = nonces.setdefault(address, {})
            key = int(index)
            nonce_at[key] = max(int(nonce), nonce_at.get(key, int(nonce)))
        elif kind == "code":
            _, _, index, code = op
            codes.setdefault(address, {})[int(index)] = bytes(code)
        elif kind == "touch":
            pass
        else:
            raise ValueError(f"unhandled op: {kind}")

    def by_index(changes: Dict[int, Any]) -> Tuple[Any, ...]:
        return tuple((index, changes[index]) for index in sorted(changes))

    out = []
    for address in sorted(seen):
        written = storage.get(address, {})
        out.append(
            (
                address,
                tuple(
                    (slot, by_index(written[slot])) for slot in sorted(written)
                ),
                tuple(sorted(reads.get(address, set()) - set(written))),
                by_index(balances.get(address, {})),
                by_index(nonces.get(address, {})),
                by_index(codes.get(address, {})),
            )
        )
    return out


@given(ops=_ops())
def test_builder_matches_reference_model(
    bal: ModuleType, tracker: ModuleType, ops: List[BuilderOp]
) -> None:
    """
    The built list matches the reference model: last write wins per index,
    the highest nonce wins, read slots that were written are dropped, and
    everything is sorted.
    """
    assert _norm(_built(bal, tracker, ops)) == _model(ops)


@given(ops=_ops(), addr=st.sampled_from(ADDR_POOL))
def test_ensure_account_acts_as_a_touch(
    bal: ModuleType, tracker: ModuleType, ops: List[BuilderOp], addr: Address
) -> None:
    """
    `ensure_account` adds the address with no changes if it is missing,
    keeps everything already recorded, and a second call changes nothing.
    """
    builder = bal.BlockAccessListBuilder()
    _feed(bal, builder, ops)
    bal.ensure_account(builder, addr)
    once = _norm(_build(bal, tracker, builder))
    bal.ensure_account(builder, addr)
    twice = _norm(_build(bal, tracker, builder))
    assert once == _model(ops + [("touch", addr)])
    assert twice == once


@given(ops=_ops())
def test_gas_limit_boundary_is_exact(
    bal: ModuleType, fork: Fork, tracker: ModuleType, ops: List[BuilderOp]
) -> None:
    """
    Validation accepts a list whose addresses plus unique storage keys use
    exactly the block gas limit's item budget, and rejects one gas less.
    """
    # Each account is an item, and so is each slot it writes or reads; the
    # model already drops reads of written slots.
    items = sum(
        1 + len(storage_changes) + len(storage_reads)
        for _, storage_changes, storage_reads, *_ in _model(ops)
    )
    assume(items >= 1)
    built = _built(bal, tracker, ops)

    item_cost = fork.gas_costs().BLOCK_ACCESS_LIST_ITEM
    at_limit = Uint(items * item_cost)
    bal.validate_block_access_list_gas_limit(built, at_limit)

    below = Uint(items * item_cost - 1)
    with pytest.raises(bal.BlockAccessListGasLimitExceededError):
        bal.validate_block_access_list_gas_limit(built, below)


def _make_account(nonce: int, balance: int, code_hash: Any) -> Account:
    return Account(
        nonce=Uint(nonce), balance=U256(balance), code_hash=code_hash
    )


@given(
    start=st.integers(min_value=0, max_value=3),
    values=st.lists(st.integers(min_value=0, max_value=3), max_size=4),
)
def test_writes_sharing_an_index_net_against_its_start(
    bal: ModuleType, tracker: ModuleType, start: int, values: List[int]
) -> None:
    """
    Several merges at one block access index, as the system calls before
    a block's transactions make, record a storage or balance change only
    if the value at the end of the index differs from its start.
    """
    addr = ADDR_POOL[1]
    slot = Bytes32(b"\x07" + b"\x00" * 31)
    block = tracker.BlockState(pre_state=State())
    tx = tracker.TransactionState(parent=block)
    builder = bal.BlockAccessListBuilder()

    builder.block_access_index = bal.BlockAccessIndex(0)
    tracker.set_account(tx, addr, _make_account(1, start, EMPTY_CODE_HASH))
    tracker.set_storage(tx, addr, slot, U256(start))
    tracker.incorporate_tx_into_block(tx, builder)

    builder.block_access_index = bal.BlockAccessIndex(1)
    for value in values:
        tracker.set_account(tx, addr, _make_account(1, value, EMPTY_CODE_HASH))
        tracker.set_storage(tx, addr, slot, U256(value))
        tracker.incorporate_tx_into_block(tx, builder)

    end = values[-1] if values else start
    expected = [] if end == start else [(1, end)]
    (account,) = _norm(bal.build_block_access_list(builder, block))
    _, storage_changes, _, balance_changes, _, _ = account
    at_index_one = [
        (index, value)
        for _, changes in storage_changes
        for index, value in changes
        if index == 1
    ]
    assert at_index_one == expected
    assert [c for c in balance_changes if c[0] == 1] == expected


def _code(value: int) -> bytes:
    return bytes([value]) if value else b""


def _code_hash(value: int) -> Any:
    return keccak256(_code(value)) if value else EMPTY_CODE_HASH


@pytest.mark.parametrize("field", ["balance", "nonce", "code", "storage"])
@given(
    before=st.integers(min_value=0, max_value=3),
    after=st.integers(min_value=0, max_value=3),
    block_wrote_slot=st.booleans(),
)
def test_update_builder_records_only_changed_values(
    bal: ModuleType,
    tracker: ModuleType,
    field: str,
    before: int,
    after: int,
    block_wrote_slot: bool,
) -> None:
    """
    A transaction's balance, nonce, code or storage value is recorded only
    if it differs from the block's value before the transaction, and the
    fields it leaves alone record nothing. A slot the block has not written
    yet starts at zero, and a transaction that changes nothing leaves the
    account out.
    """
    addr = ADDR_POOL[1]
    slot = Bytes32(b"\x09" + b"\x00" * 31)
    other_slot = Bytes32(b"\x0a" + b"\x00" * 31)
    start = before
    recorded_value: Any

    block = tracker.BlockState(pre_state=State())
    tx = tracker.TransactionState(parent=block)
    if field == "balance":
        block.account_writes[addr] = _make_account(0, before, EMPTY_CODE_HASH)
        tx.account_writes[addr] = _make_account(0, after, EMPTY_CODE_HASH)
        recorded_value = U256(after)
    elif field == "nonce":
        block.account_writes[addr] = _make_account(before, 0, EMPTY_CODE_HASH)
        tx.account_writes[addr] = _make_account(after, 0, EMPTY_CODE_HASH)
        recorded_value = U64(after)
    elif field == "code":
        block.account_writes[addr] = _make_account(0, 0, _code_hash(before))
        tx.account_writes[addr] = _make_account(0, 0, _code_hash(after))
        tx.code_writes[_code_hash(after)] = _code(after)
        recorded_value = _code(after)
    elif field == "storage":
        written_slot = slot if block_wrote_slot else other_slot
        block.storage_writes[addr] = {written_slot: U256(before)}
        tx.storage_writes[addr] = {slot: U256(after)}
        if not block_wrote_slot:
            start = 0
        recorded_value = U256(after)
    else:
        raise ValueError(f"unhandled field: {field}")

    builder = bal.BlockAccessListBuilder()
    builder.block_access_index = bal.BlockAccessIndex(2)
    bal.update_builder_from_tx(builder, tx)

    if after == start:
        assert addr not in builder.accounts
        return
    recorded = builder.accounts[addr]
    changes = {
        "balance": [c.post_balance for c in recorded.balance_changes],
        "nonce": [c.new_nonce for c in recorded.nonce_changes],
        "code": [c.new_code for c in recorded.code_changes],
        "storage": [
            c.new_value
            for slot_changes in recorded.storage_changes.values()
            for c in slot_changes
        ],
    }
    assert changes == {
        name: [recorded_value] if name == field else [] for name in changes
    }
