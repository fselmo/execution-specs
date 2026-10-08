"""
Model-based test of each fork's `state_tracker`.

A state machine runs account, storage, snapshot and rollback operations on a
`TransactionState` and checks every read against a plain Python model.
"""

import copy
from types import ModuleType
from typing import Dict, List, NamedTuple, Set, Tuple

from ethereum_types.bytes import Bytes, Bytes20, Bytes32
from ethereum_types.numeric import U256, Uint
from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine,
    invariant,
    precondition,
    rule,
    run_state_machine_as_test,
)

from ethereum.crypto.hash import keccak256
from ethereum.state import EMPTY_CODE_HASH, Account
from ethereum.state_mpt import State

from .spec_api import modify_deletes_empty_accounts

# Small pools, so that operations often hit the same account or slot.
ADDRESSES = [Bytes20(bytes([i]) * 20) for i in range(1, 5)]
KEYS = [Bytes32(bytes([i]) * 32) for i in range(1, 4)]
CODE_HASHES = [EMPTY_CODE_HASH, keccak256(b"\x01"), keccak256(b"\x02")]


class ModelAccount(NamedTuple):
    """An account in the model; the defaults make an empty account."""

    nonce: int = 0
    balance: int = 0
    code_hash: bytes = bytes(EMPTY_CODE_HASH)


class StateTrackerMachine(RuleBasedStateMachine):
    """Run a fork's `state_tracker` against a model of accounts."""

    tracker: ModuleType

    def __init__(self) -> None:
        super().__init__()
        block = self.tracker.BlockState(pre_state=State())
        self.tx = self.tracker.TransactionState(parent=block)
        self.accounts: Dict[Bytes20, ModelAccount] = {}
        self.storage: Dict[Bytes20, Dict[Bytes32, int]] = {}
        self.created: Set[Bytes20] = set()
        self.snapshots: List[
            Tuple[object, Dict[Bytes20, ModelAccount], Dict]
        ] = []

    def _account(self, addr: Bytes20) -> ModelAccount:
        """Return the model account, or an empty one if it is absent."""
        return self.accounts.get(addr, ModelAccount())

    def _modify(self, addr: Bytes20, account: ModelAccount) -> None:
        """Write an account, deleting it if it is empty and the fork does."""
        if account == ModelAccount() and modify_deletes_empty_accounts(
            self.tracker
        ):
            self.accounts.pop(addr, None)
            self.storage.pop(addr, None)
        else:
            self.accounts[addr] = account

    @rule(
        addr=st.sampled_from(ADDRESSES),
        nonce=st.integers(0, 5),
        balance=st.integers(0, 10),
        code_hash=st.sampled_from(CODE_HASHES),
    )
    def set_account(
        self, addr: Bytes20, nonce: int, balance: int, code_hash: Bytes32
    ) -> None:
        """Write an account directly, keeping it even when empty."""
        self.tracker.set_account(
            self.tx,
            addr,
            Account(
                nonce=Uint(nonce), balance=U256(balance), code_hash=code_hash
            ),
        )
        self.accounts[addr] = ModelAccount(nonce, balance, bytes(code_hash))

    @rule(addr=st.sampled_from(ADDRESSES))
    def delete_account(self, addr: Bytes20) -> None:
        """Delete an account but keep its storage."""
        self.tracker.set_account(self.tx, addr, None)
        self.accounts.pop(addr, None)

    @rule(addr=st.sampled_from(ADDRESSES))
    def increment_nonce(self, addr: Bytes20) -> None:
        """Increment an account's nonce."""
        self.tracker.increment_nonce(self.tx, addr)
        account = self._account(addr)
        self._modify(addr, account._replace(nonce=account.nonce + 1))

    @rule(addr=st.sampled_from(ADDRESSES), amount=st.integers(0, 10))
    def create_ether(self, addr: Bytes20, amount: int) -> None:
        """Add ether to an account."""
        self.tracker.create_ether(self.tx, addr, U256(amount))
        account = self._account(addr)
        self._modify(addr, account._replace(balance=account.balance + amount))

    @rule(
        sender=st.sampled_from(ADDRESSES),
        recipient=st.sampled_from(ADDRESSES),
        amount=st.integers(0, 10),
    )
    def move_ether(
        self, sender: Bytes20, recipient: Bytes20, amount: int
    ) -> None:
        """Transfer ether between two accounts."""
        if sender not in self.accounts:
            return
        if self.accounts[sender].balance < amount:
            return
        self.tracker.move_ether(self.tx, sender, recipient, U256(amount))
        # The sender is debited before the recipient is credited, which
        # matters when they are the same account or the sender empties.
        debited = self._account(sender)
        self._modify(
            sender, debited._replace(balance=debited.balance - amount)
        )
        credited = self._account(recipient)
        self._modify(
            recipient, credited._replace(balance=credited.balance + amount)
        )

    @rule(
        addr=st.sampled_from(ADDRESSES),
        code=st.sampled_from([b"", b"\x60\x00", b"\x01\x02\x03"]),
    )
    def set_code(self, addr: Bytes20, code: bytes) -> None:
        """Set an account's code."""
        self.tracker.set_code(self.tx, addr, Bytes(code))
        account = self._account(addr)
        self._modify(addr, account._replace(code_hash=bytes(keccak256(code))))

    @precondition(lambda self: bool(self.accounts))
    @rule(
        data=st.data(),
        key=st.sampled_from(KEYS),
        value=st.integers(0, 10),
    )
    def set_storage(
        self, data: st.DataObject, key: Bytes32, value: int
    ) -> None:
        """Set a storage slot on an account that exists."""
        addr = data.draw(st.sampled_from(sorted(self.accounts)))
        self.tracker.set_storage(self.tx, addr, key, U256(value))
        self.storage.setdefault(addr, {})[key] = value

    @rule(addr=st.sampled_from(ADDRESSES))
    def destroy_account(self, addr: Bytes20) -> None:
        """Destroy an account and its storage."""
        self.tracker.destroy_account(self.tx, addr)
        self.accounts.pop(addr, None)
        self.storage.pop(addr, None)

    @rule(addr=st.sampled_from(ADDRESSES))
    def mark_created(self, addr: Bytes20) -> None:
        """Mark an account created in this transaction."""
        self.tracker.mark_account_created(self.tx, addr)
        self.created.add(addr)

    @rule()
    def snapshot(self) -> None:
        """Snapshot the transaction state for rollback."""
        snap = self.tracker.copy_tx_state(self.tx)
        self.snapshots.append(
            (snap, copy.deepcopy(self.accounts), copy.deepcopy(self.storage))
        )

    @precondition(lambda self: bool(self.snapshots))
    @rule()
    def rollback(self) -> None:
        """Roll back to the most recent snapshot."""
        snap, accounts, storage = self.snapshots.pop()
        self.tracker.restore_tx_state(self.tx, snap)
        # `mark_account_created` documents that a rollback keeps the mark.
        self.accounts = accounts
        self.storage = storage

    @invariant()
    def accounts_match(self) -> None:
        """Every account read matches the model."""
        for addr in ADDRESSES:
            actual = self.tracker.get_account_optional(self.tx, addr)
            model = self.accounts.get(addr)
            if model is None:
                assert actual is None, f"{addr!r} should be absent"
            else:
                assert actual is not None, f"{addr!r} should exist"
                assert (
                    ModelAccount(
                        int(actual.nonce),
                        int(actual.balance),
                        bytes(actual.code_hash),
                    )
                    == model
                )

    @invariant()
    def storage_matches(self) -> None:
        """Every storage read matches the model."""
        for addr in ADDRESSES:
            for key in KEYS:
                actual = self.tracker.get_storage(self.tx, addr, key)
                expected = self.storage.get(addr, {}).get(key, 0)
                assert int(actual) == expected

    @invariant()
    def created_matches(self) -> None:
        """The created-accounts set matches the model."""
        assert set(self.tx.created_accounts) == self.created


def test_state_tracker_matches_model(tracker: ModuleType) -> None:
    """The state tracker agrees with the model on every operation sequence."""
    machine = type(
        "StateTrackerMachine", (StateTrackerMachine,), {"tracker": tracker}
    )
    run_state_machine_as_test(
        machine, settings=settings(stateful_step_count=40)
    )
