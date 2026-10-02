"""
Properties of the [EIP-7928] block access list builder.

The list must come out in one canonical form, sorted and deduplicated, and
record each change against the state at the start of its block access index.

[EIP-7928]: https://eips.ethereum.org/EIPS/eip-7928
"""

import importlib
from types import ModuleType
from typing import Any, Dict, List, Set, Tuple

import pytest
from ethereum_types.bytes import Bytes, Bytes32
from ethereum_types.numeric import U256, Uint
from hypothesis import assume, given
from hypothesis import strategies as st

from ethereum.crypto.hash import keccak256
from ethereum.state import EMPTY_CODE_HASH, Account, Address
from ethereum.state_mpt import State

from .forks import forks_from
from .strategies import bytes_data, u64s, u256s

pytestmark = pytest.mark.parametrize(
    "fork_name", forks_from("amsterdam"), indirect=True
)

# EIP-7928: "ITEM_COST = 2000".
ITEM_COST = 2000

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


@pytest.fixture(scope="session")
def bal(fork_name: str) -> ModuleType:
    """Return the block access list module of the fork under test."""
    return importlib.import_module(
        f"ethereum.forks.{fork_name}.block_access_lists"
    )


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


@given(ops=_ops(), data=st.data())
def test_build_is_order_independent(
    bal: ModuleType,
    tracker: ModuleType,
    ops: List[BuilderOp],
    data: st.DataObject,
) -> None:
    """
    Operations that never write the same field at the same index build the
    same list, and hash, in any order.
    """
    uniq: Dict[Tuple[Any, ...], BuilderOp] = {}
    for op in ops:
        kind = op[0]
        key: Tuple[Any, ...]
        if kind == "storage_write":
            key = (kind, bytes(op[1]), int(op[2]), int(op[3]))
        elif kind in ("storage_read", "balance", "nonce", "code"):
            key = (kind, bytes(op[1]), int(op[2]))
        elif kind == "touch":
            key = (kind, bytes(op[1]))
        else:
            raise ValueError(f"unhandled op: {kind}")
        uniq[key] = op
    unique_ops = list(uniq.values())
    permuted = data.draw(st.permutations(unique_ops))

    first = _built(bal, tracker, unique_ops)
    second = _built(bal, tracker, permuted)
    assert _norm(first) == _norm(second)
    assert bal.hash_block_access_list(first) == bal.hash_block_access_list(
        second
    )


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
    bal: ModuleType, tracker: ModuleType, ops: List[BuilderOp]
) -> None:
    """
    Validation accepts a list whose addresses plus unique storage keys use
    exactly the block gas limit's item budget, and rejects one gas less.
    """
    built = _built(bal, tracker, ops)
    items = 0
    for acc in built:
        items += 1
        keys = {int(s.slot) for s in acc.storage_changes}
        keys |= {int(x) for x in acc.storage_reads}
        items += len(keys)
    assume(items >= 1)

    at_limit = Uint(items * ITEM_COST)
    bal.validate_block_access_list_gas_limit(built, at_limit)

    below = Uint(items * ITEM_COST - 1)
    with pytest.raises(bal.BlockAccessListGasLimitExceededError):
        bal.validate_block_access_list_gas_limit(built, below)


def _make_account(nonce: int, balance: int, code_hash: Any) -> Account:
    return Account(
        nonce=Uint(nonce), balance=U256(balance), code_hash=code_hash
    )


@given(
    nonce=st.integers(min_value=0, max_value=10),
    balance=st.integers(min_value=0, max_value=1_000),
    code=bytes_data(max_size=8),
)
def test_update_builder_net_zero_records_nothing(
    bal: ModuleType,
    tracker: ModuleType,
    nonce: int,
    balance: int,
    code: Bytes,
) -> None:
    """A transaction that leaves an account as it found it records nothing."""
    addr = ADDR_POOL[0]
    code_hash = keccak256(code) if code else EMPTY_CODE_HASH
    account = _make_account(nonce, balance, code_hash)
    slot = Bytes32(b"\x07" + b"\x00" * 31)

    block = tracker.BlockState(pre_state=State())
    block.account_writes[addr] = account
    block.storage_writes[addr] = {slot: U256(123)}
    tx = tracker.TransactionState(parent=block)
    tx.account_writes[addr] = _make_account(nonce, balance, code_hash)
    tx.storage_writes[addr] = {slot: U256(123)}

    builder = bal.BlockAccessListBuilder()
    builder.block_access_index = bal.BlockAccessIndex(1)
    bal.update_builder_from_tx(builder, tx)

    assert addr not in builder.accounts


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


@pytest.mark.parametrize("field", ["balance", "nonce", "storage"])
@given(
    pre=st.integers(min_value=0, max_value=1_000),
    delta=st.integers(min_value=1, max_value=1_000),
)
def test_update_builder_records_changed_field(
    bal: ModuleType,
    tracker: ModuleType,
    field: str,
    pre: int,
    delta: int,
) -> None:
    """A single changed field is recorded with its value after the tx."""
    addr = ADDR_POOL[1]
    slot = Bytes32(b"\x09" + b"\x00" * 31)
    post = pre + delta

    block = tracker.BlockState(pre_state=State())
    tx = tracker.TransactionState(parent=block)

    if field == "balance":
        block.account_writes[addr] = _make_account(0, pre, EMPTY_CODE_HASH)
        tx.account_writes[addr] = _make_account(0, post, EMPTY_CODE_HASH)
    elif field == "nonce":
        block.account_writes[addr] = _make_account(pre, 0, EMPTY_CODE_HASH)
        tx.account_writes[addr] = _make_account(post, 0, EMPTY_CODE_HASH)
    elif field == "storage":
        block.storage_writes[addr] = {slot: U256(pre)}
        tx.storage_writes[addr] = {slot: U256(post)}
    else:
        raise ValueError(f"unhandled field: {field}")

    builder = bal.BlockAccessListBuilder()
    builder.block_access_index = bal.BlockAccessIndex(2)
    bal.update_builder_from_tx(builder, tx)

    data = builder.accounts[addr]
    if field == "balance":
        assert [int(c.post_balance) for c in data.balance_changes] == [post]
        assert data.nonce_changes == []
    elif field == "nonce":
        assert [int(c.new_nonce) for c in data.nonce_changes] == [post]
        assert data.balance_changes == []
    elif field == "storage":
        u256_slot = U256.from_be_bytes(slot)
        assert list(data.storage_changes) == [u256_slot]
        recorded = data.storage_changes[u256_slot]
        assert [int(c.new_value) for c in recorded] == [post]
    else:
        raise ValueError(f"unhandled field: {field}")


@given(
    cumulative=st.integers(min_value=1, max_value=1_000),
    new_value=st.integers(min_value=1, max_value=1_000),
)
def test_update_builder_slot_absent_from_cumulative(
    bal: ModuleType,
    tracker: ModuleType,
    cumulative: int,
    new_value: int,
) -> None:
    """
    A write to a slot the block has not written yet is compared against
    the pre-state default of zero.
    """
    addr = ADDR_POOL[2]
    cumulative_slot = Bytes32(b"\x01" + b"\x00" * 31)
    new_slot = Bytes32(b"\x02" + b"\x00" * 31)

    block = tracker.BlockState(pre_state=State())
    block.storage_writes[addr] = {cumulative_slot: U256(cumulative)}
    tx = tracker.TransactionState(parent=block)
    tx.storage_writes[addr] = {new_slot: U256(new_value)}

    builder = bal.BlockAccessListBuilder()
    builder.block_access_index = bal.BlockAccessIndex(3)
    bal.update_builder_from_tx(builder, tx)

    recorded = builder.accounts[addr].storage_changes
    u256_slot = U256.from_be_bytes(new_slot)
    assert list(recorded) == [u256_slot]
    assert [int(c.new_value) for c in recorded[u256_slot]] == [new_value]
