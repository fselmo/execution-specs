"""
Properties of the [EIP-7928] Block Access List (BAL) builder.

The BAL records every account and storage location accessed during block
execution along with post-execution values, in a *canonical* form so that
every client hashes the same bytes. EIP-7928 fixes both the construction
rules and the ordering; the amsterdam ``block_access_lists`` module and its
docstrings restate them. These properties are grounded in that prose, so
they cannot merely restate the code they guard.

Normative ordering (EIP-7928 "Ordering and encoding"):

    > Accounts: Lexicographic by address
    > storage_changes: Slots lexicographic by storage key; within each
    > slot, changes by block access index (ascending)
    > storage_reads: Lexicographic by storage key
    > balance_changes, nonce_changes, code_changes: By block access index
    > (ascending)

Read/write exclusivity (EIP-7928):

    > A storage key MUST NOT appear in both `storage_changes` and
    > `storage_reads` for the same account.

and the ``add_storage_read`` docstring:

    > Storage slots that are both read and written will only appear in the
    > storage changes list, not in the storage reads list, as per
    > [EIP-7928].

Per-index deduplication (EIP-7928):

    > Each `block_access_index` MUST appear at most once per change list
    > (`balance_changes`, `nonce_changes`, `code_changes`, and per-slot
    > `StorageChange` list).

with the per-field last-write rules from the builder docstrings:
``add_storage_write`` ("only the final value is kept"), ``add_balance_change``
("only track the final balance"), ``add_nonce_change`` ("the final (highest)
nonce"), ``add_code_change`` ("only record the final state").

Net-zero filtering (EIP-7928):

    > If an account's balance changes during a transaction, but its
    > post-transaction balance is equal to its pre-transaction balance,
    > then the change MUST NOT be recorded in `balance_changes`.

restated by ``update_builder_from_tx`` ("if the pre-tx value equals the
post-tx value, no change is recorded").

Gas-limit bound (EIP-7928):

    > bal_items <= block_gas_limit // ITEM_COST
    > bal_items = storage_keys + addresses

restated by ``validate_block_access_list_gas_limit`` ("addresses + unique
storage keys ... must not exceed ``block_gas_limit //
GAS_BLOCK_ACCESS_LIST_ITEM``").

This module exists only from amsterdam onward; the per-fork fixtures below
skip cleanly on forks that lack it (e.g. osaka).

[EIP-7928]: https://eips.ethereum.org/EIPS/eip-7928
"""

from types import ModuleType
from typing import Any, Dict, List, Set, Tuple

import pytest
from ethereum_types.bytes import Bytes, Bytes32
from ethereum_types.numeric import U64, U256, Uint
from hypothesis import assume, given
from hypothesis import strategies as st

from ethereum.crypto.hash import keccak256
from ethereum.state import EMPTY_CODE_HASH, Account, Address, State

from .strategies import bytes_data, u64s, u256s

# Value asserted directly from EIP-7928 prose ("ITEM_COST = 2000"),
# independent of the spec constant it is compared against.
EIP_7928_ITEM_COST = 2000

# A small, fixed pool of addresses whose sorted order differs from any
# natural insertion order, so a dropped account sort is observable.
ADDR_POOL = [
    Address(b"\x03" + b"\x00" * 19),
    Address(b"\x01" + b"\x00" * 19),
    Address(b"\x02" + b"\xff" * 19),
    Address(b"\xff" * 20),
]

# Small slot pool so per-slot collisions (and per-index dedup) actually
# happen, mixed with the boundary-weighted full range.
SLOT_POOL = [U256(0), U256(1), U256(2), U256((1 << 256) - 1)]


@pytest.fixture(scope="session")
def bal(fork_name: str) -> ModuleType:
    """BAL module of the fork under test (amsterdam onward)."""
    return pytest.importorskip(
        f"ethereum.forks.{fork_name}.block_access_lists"
    )


@pytest.fixture(scope="session")
def tracker(fork_name: str) -> ModuleType:
    """State-tracker module of the fork under test (amsterdam onward)."""
    return pytest.importorskip(f"ethereum.forks.{fork_name}.state_tracker")


def _slots() -> st.SearchStrategy[U256]:
    return st.one_of(st.sampled_from(SLOT_POOL), u256s())


def _indices() -> st.SearchStrategy[int]:
    # A small pool forces same-index collisions (dedup / last-write-wins);
    # the wide draw exercises the U32 sort key.
    return st.one_of(
        st.integers(min_value=0, max_value=6),
        st.integers(min_value=0, max_value=(1 << 32) - 1),
    )


Op = Tuple[Any, ...]


def _ops() -> st.SearchStrategy[List[Op]]:
    """Sequences of builder operations over the fixed address/slot pools."""
    addr = st.sampled_from(ADDR_POOL)
    return st.lists(
        st.one_of(
            st.tuples(st.just("sw"), addr, _slots(), _indices(), u256s()),
            st.tuples(st.just("sr"), addr, _slots()),
            st.tuples(st.just("bal"), addr, _indices(), u256s()),
            st.tuples(st.just("non"), addr, _indices(), u64s()),
            st.tuples(
                st.just("code"), addr, _indices(), bytes_data(max_size=8)
            ),
            st.tuples(st.just("touch"), addr),
        ),
        max_size=30,
    )


def _feed(bal: ModuleType, builder: Any, ops: List[Op]) -> None:
    """Replay a list of operations against a builder."""
    for op in ops:
        kind = op[0]
        if kind == "sw":
            _, a, slot, i, v = op
            bal.add_storage_write(builder, a, slot, bal.BlockAccessIndex(i), v)
        elif kind == "sr":
            _, a, slot = op
            bal.add_storage_read(builder, a, slot)
        elif kind == "bal":
            _, a, i, v = op
            bal.add_balance_change(builder, a, bal.BlockAccessIndex(i), v)
        elif kind == "non":
            _, a, i, n = op
            bal.add_nonce_change(builder, a, bal.BlockAccessIndex(i), n)
        elif kind == "code":
            _, a, i, c = op
            bal.add_code_change(builder, a, bal.BlockAccessIndex(i), c)
        elif kind == "touch":
            _, a = op
            bal.add_touched_account(builder, a)
        else:
            raise ValueError(f"unhandled op: {kind}")


def _built(bal: ModuleType, ops: List[Op]) -> Any:
    """Feed `ops` into a fresh builder and return the built BAL."""
    builder = bal.BlockAccessListBuilder()
    _feed(bal, builder, ops)
    return bal._build_from_builder(builder)


def _norm(block_access_list: Any) -> List[Tuple[Any, ...]]:
    """Normalize a built BAL into comparable plain-Python tuples."""
    out = []
    for acc in block_access_list:
        sc = tuple(
            (
                int(s.slot),
                tuple(
                    (int(c.block_access_index), int(c.new_value))
                    for c in s.changes
                ),
            )
            for s in acc.storage_changes
        )
        sr = tuple(int(x) for x in acc.storage_reads)
        bc = tuple(
            (int(c.block_access_index), int(c.post_balance))
            for c in acc.balance_changes
        )
        nc = tuple(
            (int(c.block_access_index), int(c.new_nonce))
            for c in acc.nonce_changes
        )
        cc = tuple(
            (int(c.block_access_index), bytes(c.new_code))
            for c in acc.code_changes
        )
        out.append((bytes(acc.address), sc, sr, bc, nc, cc))
    return out


def _model(ops: List[Op]) -> List[Tuple[Any, ...]]:
    """
    Independent reference model of the canonical BAL from EIP-7928.

    Restates the EIP rules directly (last write wins per index, highest
    nonce per index, read/write exclusion, lexicographic/index ordering)
    rather than mirroring the builder's control flow.
    """
    seen: Set[bytes] = set()
    sc: Dict[bytes, Dict[int, Dict[int, int]]] = {}
    sr: Dict[bytes, Set[int]] = {}
    bc: Dict[bytes, Dict[int, int]] = {}
    nc: Dict[bytes, Dict[int, int]] = {}
    cc: Dict[bytes, Dict[int, bytes]] = {}

    for op in ops:
        kind = op[0]
        a = bytes(op[1])
        seen.add(a)
        if kind == "sw":
            _, _, slot, i, v = op
            sc.setdefault(a, {}).setdefault(int(slot), {})[int(i)] = int(v)
        elif kind == "sr":
            _, _, slot = op
            sr.setdefault(a, set()).add(int(slot))
        elif kind == "bal":
            _, _, i, v = op
            bc.setdefault(a, {})[int(i)] = int(v)
        elif kind == "non":
            _, _, i, n = op
            per_index = nc.setdefault(a, {})
            key = int(i)
            per_index[key] = max(int(n), per_index.get(key, int(n)))
        elif kind == "code":
            _, _, i, c = op
            cc.setdefault(a, {})[int(i)] = bytes(c)
        elif kind == "touch":
            pass
        else:
            raise ValueError(f"unhandled op: {kind}")

    out = []
    for a in sorted(seen):
        sc_a = sc.get(a, {})
        sc_norm = tuple(
            (
                slot,
                tuple((i, sc_a[slot][i]) for i in sorted(sc_a[slot])),
            )
            for slot in sorted(sc_a)
        )
        sr_norm = tuple(sorted(sr.get(a, set()) - set(sc_a)))
        bc_a = bc.get(a, {})
        bc_norm = tuple((i, bc_a[i]) for i in sorted(bc_a))
        nc_a = nc.get(a, {})
        nc_norm = tuple((i, nc_a[i]) for i in sorted(nc_a))
        cc_a = cc.get(a, {})
        cc_norm = tuple((i, cc_a[i]) for i in sorted(cc_a))
        out.append((a, sc_norm, sr_norm, bc_norm, nc_norm, cc_norm))
    return out


@given(ops=_ops())
def test_builder_matches_reference_model(
    bal: ModuleType, ops: List[Op]
) -> None:
    """
    The built BAL equals an independent reference model of EIP-7928.

    Model-based oracle: the reference restates the EIP's construction rules
    (last-write-wins per index, highest-nonce per index, read/write
    exclusion, canonical ordering) without copying the builder, so agreement
    pins the whole accumulation-and-sort pipeline at once.

    Grounding: EIP-7928 "Ordering and encoding" plus the per-field builder
    docstrings. Non-circular: the model is derived from the EIP prose, not
    from `_build_from_builder`.
    """
    assert _norm(_built(bal, ops)) == _model(ops)


@given(ops=_ops())
def test_accounts_sorted_by_address(bal: ModuleType, ops: List[Op]) -> None:
    """
    Accounts appear in ascending address order.

    EIP-7928: "Accounts: Lexicographic by address"; `_build_from_builder`
    docstring: "Account addresses (lexicographically)".

    Grounding: EIP prose + docstring. Non-circular: checks the observable
    ordering, not the sort call.
    """
    built = _built(bal, ops)
    addrs = [bytes(acc.address) for acc in built]
    assert addrs == sorted(addrs)
    assert len(addrs) == len(set(addrs)), "each address appears exactly once"


@given(ops=_ops())
def test_storage_slots_sorted_within_account(
    bal: ModuleType, ops: List[Op]
) -> None:
    """
    Within an account, storage_changes and storage_reads are slot-sorted.

    EIP-7928: "storage_changes: Slots lexicographic by storage key" and
    "storage_reads: Lexicographic by storage key".

    Grounding: EIP prose + `_build_from_builder` docstring ("Storage slots
    (lexicographically)"). Non-circular: observes the emitted order.
    """
    for acc in _built(bal, ops):
        change_slots = [int(s.slot) for s in acc.storage_changes]
        assert change_slots == sorted(change_slots)
        assert len(change_slots) == len(set(change_slots))

        read_slots = [int(x) for x in acc.storage_reads]
        assert read_slots == sorted(read_slots)
        assert len(read_slots) == len(set(read_slots))


@given(ops=_ops())
def test_change_indices_sorted_and_unique(
    bal: ModuleType, ops: List[Op]
) -> None:
    """
    Every change list is ordered by block_access_index, with no repeats.

    EIP-7928: "balance_changes, nonce_changes, code_changes: By block access
    index (ascending)" and "within each slot, changes by block access index
    (ascending)"; and "Each `block_access_index` MUST appear at most once per
    change list". `_build_from_builder` docstring: "block access indices are
    unique".

    Grounding: EIP prose + docstring. Non-circular: observes emitted indices.
    """

    def check(indices: List[int]) -> None:
        assert indices == sorted(indices)
        assert len(indices) == len(set(indices))

    for acc in _built(bal, ops):
        for slot_change in acc.storage_changes:
            check([int(c.block_access_index) for c in slot_change.changes])
        check([int(c.block_access_index) for c in acc.balance_changes])
        check([int(c.block_access_index) for c in acc.nonce_changes])
        check([int(c.block_access_index) for c in acc.code_changes])


@given(ops=_ops())
def test_read_write_exclusion(bal: ModuleType, ops: List[Op]) -> None:
    """
    No slot appears in both storage_changes and storage_reads.

    EIP-7928: "A storage key MUST NOT appear in both `storage_changes` and
    `storage_reads` for the same account." `add_storage_read` docstring:
    slots "that are both read and written will only appear in the storage
    changes list".

    Grounding: EIP prose + docstring. Non-circular: checks the disjointness
    invariant on the built structure.
    """
    for acc in _built(bal, ops):
        written = {int(s.slot) for s in acc.storage_changes}
        read = {int(x) for x in acc.storage_reads}
        assert written.isdisjoint(read)


@given(
    addr=st.sampled_from(ADDR_POOL),
    slot=_slots(),
    idx=_indices(),
    values=st.lists(u256s(), min_size=1, max_size=6),
)
def test_storage_last_write_wins_per_index(
    bal: ModuleType,
    addr: Address,
    slot: U256,
    idx: int,
    values: List[U256],
) -> None:
    """
    Repeated writes to one slot at one index collapse to the final value.

    `add_storage_write` docstring: "If multiple writes occur to the same slot
    within the same transaction (same `block_access_index`), only the final
    value is kept."

    Grounding: docstring (self-descriptive). Non-circular: asserts the
    emitted value is the last input, a claim independent of the code path.
    """
    builder = bal.BlockAccessListBuilder()
    for v in values:
        bal.add_storage_write(
            builder, addr, slot, bal.BlockAccessIndex(idx), v
        )
    built = _built_from(bal, builder)
    changes = _only_account(built, addr).storage_changes
    assert len(changes) == 1
    assert len(changes[0].changes) == 1
    assert int(changes[0].changes[0].new_value) == int(values[-1])


@given(
    addr=st.sampled_from(ADDR_POOL),
    idx=_indices(),
    nonces=st.lists(u64s(), min_size=1, max_size=6),
)
def test_nonce_highest_wins_per_index(
    bal: ModuleType, addr: Address, idx: int, nonces: List[U64]
) -> None:
    """
    Repeated nonce writes at one index collapse to the highest nonce.

    `add_nonce_change` docstring: "we only track the final (highest) nonce
    per transaction".

    Grounding: docstring. Non-circular: asserts the emitted nonce equals
    max(inputs), independent of the comparison in the code.
    """
    builder = bal.BlockAccessListBuilder()
    for n in nonces:
        bal.add_nonce_change(builder, addr, bal.BlockAccessIndex(idx), n)
    changes = _only_account(_built_from(bal, builder), addr).nonce_changes
    assert len(changes) == 1
    assert int(changes[0].new_nonce) == max(int(n) for n in nonces)


@given(
    addr=st.sampled_from(ADDR_POOL),
    idx=_indices(),
    values=st.lists(u256s(), min_size=1, max_size=6),
)
def test_balance_last_write_wins_per_index(
    bal: ModuleType, addr: Address, idx: int, values: List[U256]
) -> None:
    """
    Repeated balance writes at one index collapse to the final balance.

    `add_balance_change` docstring: "we only track the final balance per
    transaction".

    Grounding: docstring. Non-circular: asserts the emitted balance is the
    last input.
    """
    builder = bal.BlockAccessListBuilder()
    for v in values:
        bal.add_balance_change(builder, addr, bal.BlockAccessIndex(idx), v)
    changes = _only_account(_built_from(bal, builder), addr).balance_changes
    assert len(changes) == 1
    assert int(changes[0].post_balance) == int(values[-1])


@given(ops=_ops(), data=st.data())
def test_build_is_order_independent(
    bal: ModuleType, ops: List[Op], data: st.DataObject
) -> None:
    """
    The built BAL and its hash are independent of operation order.

    The builder "constructs a deterministic access list"
    (`BlockAccessListBuilder`) and `_build_from_builder` "Constructs a
    deterministic block access list by sorting". Once operations that
    collide on the same `(address, field, index)` are de-duplicated (so
    last-write-wins cannot depend on order), any permutation must produce
    byte-identical output.

    Grounding: builder/`_build_from_builder` docstrings (determinism) +
    `hash_block_access_list`. Shape: metamorphic (confluence) + hash
    round-trip. Non-circular: relates two runs, asserting no authored value.
    """
    uniq: Dict[Tuple[Any, ...], Op] = {}
    for op in ops:
        kind = op[0]
        key: Tuple[Any, ...]
        if kind == "sw":
            key = (kind, bytes(op[1]), int(op[2]), int(op[3]))
        elif kind in ("bal", "non", "code"):
            key = (kind, bytes(op[1]), int(op[2]))
        elif kind == "sr":
            key = (kind, bytes(op[1]), int(op[2]))
        elif kind == "touch":
            key = (kind, bytes(op[1]))
        else:
            raise ValueError(f"unhandled op: {kind}")
        uniq[key] = op
    unique_ops = list(uniq.values())
    permuted = data.draw(st.permutations(unique_ops))

    first = _built(bal, unique_ops)
    second = _built(bal, permuted)
    assert _norm(first) == _norm(second)
    assert bal.hash_block_access_list(first) == bal.hash_block_access_list(
        second
    )


@given(ops=_ops(), addr=st.sampled_from(ADDR_POOL))
def test_ensure_account_is_idempotent(
    bal: ModuleType, ops: List[Op], addr: Address
) -> None:
    """
    A redundant `ensure_account` never alters accumulated data.

    `ensure_account` docstring: "This function is idempotent and safe to call
    multiple times for the same address."

    Grounding: docstring. Non-circular: relates the built BAL before and
    after a redundant call rather than asserting a fixed value.
    """
    builder = bal.BlockAccessListBuilder()
    _feed(bal, builder, ops)
    bal.ensure_account(builder, addr)
    once = _norm(bal._build_from_builder(builder))
    bal.ensure_account(builder, addr)
    twice = _norm(bal._build_from_builder(builder))
    assert once == twice


@given(
    addr=st.sampled_from(ADDR_POOL),
    slot=_slots(),
    idx=_indices(),
    value=u256s(),
)
def test_touched_account_preserves_changes(
    bal: ModuleType,
    addr: Address,
    slot: U256,
    idx: int,
    value: U256,
) -> None:
    """
    Marking an account touched never clears its recorded changes.

    `add_touched_account` records access "without any state changes" via the
    idempotent `ensure_account`, so an account that already has changes keeps
    them.

    Grounding: `add_touched_account` / `ensure_account` docstrings.
    Non-circular: relates the built change to itself across a touch.
    """
    builder = bal.BlockAccessListBuilder()
    bal.add_storage_write(
        builder, addr, slot, bal.BlockAccessIndex(idx), value
    )
    bal.add_touched_account(builder, addr)
    changes = _only_account(_built_from(bal, builder), addr).storage_changes
    assert len(changes) == 1
    assert int(changes[0].slot) == int(slot)
    assert int(changes[0].changes[0].new_value) == int(value)


@given(ops=_ops())
def test_gas_limit_boundary_is_exact(bal: ModuleType, ops: List[Op]) -> None:
    """
    Validation accepts at exactly the item budget and rejects one below it.

    EIP-7928: "bal_items <= block_gas_limit // ITEM_COST" with "bal_items =
    storage_keys + addresses" and "ITEM_COST = 2000".
    `validate_block_access_list_gas_limit` docstring: "addresses + unique
    storage keys ... must not exceed ``block_gas_limit //
    GAS_BLOCK_ACCESS_LIST_ITEM``".

    Grounding: EIP prose (the `<=` bound and item formula). Non-circular:
    the item count is recomputed from the EIP definition (addresses + unique
    storage keys), not read back from the validator.
    """
    built = _built(bal, ops)
    items = 0
    for acc in built:
        items += 1
        keys = {int(s.slot) for s in acc.storage_changes}
        keys |= {int(x) for x in acc.storage_reads}
        items += len(keys)
    assume(items >= 1)

    at_limit = Uint(items * EIP_7928_ITEM_COST)
    bal.validate_block_access_list_gas_limit(built, at_limit)

    below = Uint(items * EIP_7928_ITEM_COST - 1)
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
    """
    A transaction whose post-state equals its pre-state records no change.

    EIP-7928: a change whose "post-transaction balance is equal to its
    pre-transaction balance ... MUST NOT be recorded". `update_builder_from_tx`
    docstring: "if the pre-tx value equals the post-tx value, no change is
    recorded".

    Grounding: EIP prose + docstring. Non-circular: constructs a genuine
    no-op transaction and asserts absence, a claim about behaviour.
    """
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
    field=st.sampled_from(["balance", "nonce", "storage"]),
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
    """
    A single changed field is recorded with its post-transaction value.

    `update_builder_from_tx` docstring: "extract balance, nonce, code, and
    storage changes" by comparing writes against cumulative pre-state.

    Grounding: docstring + EIP-7928 (post-state values are recorded).
    Non-circular: the expected post value is the one written into the
    transaction, not read from the builder.
    """
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
    A tx writing a slot the account lacks in cumulative state is compared
    against pre-state (0), not by indexing a missing cumulative key.

    `update_builder_from_tx` compares each write against "the block's
    cumulative state (falling back to `pre_state`)"; when the written slot
    is new to that account, the pre-tx value is the pre-state default (0),
    so a non-zero write is recorded.

    Grounding: `update_builder_from_tx` / `_get_pre_tx_storage` docstrings.
    Non-circular: asserts the post value written into the tx is recorded,
    exercising the cumulative-present-but-key-absent lookup path.
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


def _built_from(bal: ModuleType, builder: Any) -> Any:
    return bal._build_from_builder(builder)


def _only_account(block_access_list: Any, addr: Address) -> Any:
    matches = [
        acc for acc in block_access_list if bytes(acc.address) == bytes(addr)
    ]
    assert len(matches) == 1
    return matches[0]
