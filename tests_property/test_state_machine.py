"""
Stateful property test of the per-fork ``state_tracker``.

A Hypothesis ``RuleBasedStateMachine`` drives a fork's ``TransactionState``
operations (account/storage/nonce/balance/code writes, snapshot, rollback)
against an independent Python reference model, asserting after every step that
reads agree and that rollback restores state.

The oracle is the reference model (model-based testing), so this asserts no
hand-authored value and produces no fixture — it cannot poison the canonical
suite. The subtle behaviours it pins are grounded in the source:

- ``modify_state`` destroys an account that becomes empty (zero nonce, zero
  balance, empty code) — the EIP-161 clearing at ``state_tracker.modify_state``
  — whereas a direct ``set_account`` of an empty account leaves it present.
- ``restore_tx_state`` deliberately does *not* roll back ``created_accounts``
  ("the marker is not removed even if the account creation reverts",
  ``state_tracker.mark_account_created``); the model mirrors that carve-out.

MVP scope: a single ``TransactionState`` over an empty pre-state (no
block-layer commit / read-chain layering yet — deferred to a later rule set).
"""

import copy
import importlib
from types import ModuleType
from typing import Dict, List, Optional, Set, Tuple

import pytest
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

# Small fixed pools so collisions/overwrites actually happen.
ADDRESSES = [Bytes20(bytes([i]) * 20) for i in range(1, 5)]
KEYS = [Bytes32(bytes([i]) * 32) for i in range(1, 4)]
CODE_HASHES = [EMPTY_CODE_HASH, keccak256(b"\x01"), keccak256(b"\x02")]

ModelAccount = Tuple[int, int, bytes]  # (nonce, balance, code_hash)
_EMPTY_HASH = bytes(EMPTY_CODE_HASH)


class StateTrackerMachine(RuleBasedStateMachine):
    """Drive a fork's state_tracker against a reference model."""

    tracker: ModuleType  # set per fork by the factory below

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

    # -- model helpers -----------------------------------------------------

    def _modify(self, addr: Bytes20, nonce: int, bal: int, ch: bytes) -> None:
        """Mirror modify_state: write, then clear if the account is empty."""
        if (nonce, bal, ch) == (0, 0, _EMPTY_HASH):
            # modify_state clears an emptied account via destroy_account,
            # which also wipes its storage.
            self.accounts.pop(addr, None)
            self.storage.pop(addr, None)
        else:
            self.accounts[addr] = (nonce, bal, ch)

    def _get(self, addr: Bytes20) -> Optional[ModelAccount]:
        return self.accounts.get(addr)

    # -- rules -------------------------------------------------------------

    @rule(
        addr=st.sampled_from(ADDRESSES),
        nonce=st.integers(0, 5),
        bal=st.integers(0, 10),
        ch=st.sampled_from(CODE_HASHES),
    )
    def set_account(
        self, addr: Bytes20, nonce: int, bal: int, ch: Bytes32
    ) -> None:
        """Write an account directly (empty accounts are kept)."""
        self.tracker.set_account(
            self.tx,
            addr,
            Account(nonce=Uint(nonce), balance=U256(bal), code_hash=ch),
        )
        # Direct set keeps an explicitly-empty account (no clearing).
        self.accounts[addr] = (nonce, bal, bytes(ch))

    @rule(addr=st.sampled_from(ADDRESSES))
    def delete_account(self, addr: Bytes20) -> None:
        """Delete an account via set_account(None) (storage kept)."""
        self.tracker.set_account(self.tx, addr, None)
        self.accounts.pop(addr, None)

    @rule(addr=st.sampled_from(ADDRESSES))
    def increment_nonce(self, addr: Bytes20) -> None:
        """Increment an account's nonce."""
        self.tracker.increment_nonce(self.tx, addr)
        nonce, bal, ch = self._get(addr) or (0, 0, _EMPTY_HASH)
        self._modify(addr, nonce + 1, bal, ch)

    @rule(addr=st.sampled_from(ADDRESSES), amount=st.integers(0, 10))
    def create_ether(self, addr: Bytes20, amount: int) -> None:
        """Add ether to an account."""
        self.tracker.create_ether(self.tx, addr, U256(amount))
        nonce, bal, ch = self._get(addr) or (0, 0, _EMPTY_HASH)
        self._modify(addr, nonce, bal + amount, ch)

    @rule(
        sender=st.sampled_from(ADDRESSES),
        recipient=st.sampled_from(ADDRESSES),
        amount=st.integers(0, 10),
    )
    def move_ether(
        self, sender: Bytes20, recipient: Bytes20, amount: int
    ) -> None:
        """Transfer ether between two accounts."""
        model_sender = self._get(sender)
        # Precondition: move_ether asserts the sender can cover the amount.
        if model_sender is None or model_sender[1] < amount:
            return
        self.tracker.move_ether(self.tx, sender, recipient, U256(amount))
        # Sequential modify_state on sender then recipient (order matters
        # when sender == recipient or an account empties mid-transfer).
        n, b, c = self._get(sender) or (0, 0, _EMPTY_HASH)
        self._modify(sender, n, b - amount, c)
        n, b, c = self._get(recipient) or (0, 0, _EMPTY_HASH)
        self._modify(recipient, n, b + amount, c)

    @rule(
        addr=st.sampled_from(ADDRESSES),
        code=st.sampled_from([b"", b"\x60\x00", b"\x01\x02\x03"]),
    )
    def set_code(self, addr: Bytes20, code: bytes) -> None:
        """Set an account's code."""
        self.tracker.set_code(self.tx, addr, Bytes(code))
        ch = bytes(keccak256(code))
        n, b, _ = self._get(addr) or (0, 0, _EMPTY_HASH)
        self._modify(addr, n, b, ch)

    @precondition(lambda self: bool(self.accounts))
    @rule(
        data=st.data(),
        key=st.sampled_from(KEYS),
        value=st.integers(0, 10),
    )
    def set_storage(
        self, data: st.DataObject, key: Bytes32, value: int
    ) -> None:
        # set_storage asserts the account exists; pick one that does.
        """Set a storage slot on an existing account."""
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
        # created_accounts is intentionally NOT rolled back.
        self.accounts = accounts
        self.storage = storage

    # -- invariants --------------------------------------------------------

    @invariant()
    def accounts_match(self) -> None:
        """Every account read matches the reference model."""
        for addr in ADDRESSES:
            actual = self.tracker.get_account_optional(self.tx, addr)
            model = self._get(addr)
            if model is None:
                assert actual is None, f"{addr!r} should be absent"
            else:
                assert actual is not None, f"{addr!r} should exist"
                assert int(actual.nonce) == model[0]
                assert int(actual.balance) == model[1]
                assert bytes(actual.code_hash) == model[2]

    @invariant()
    def storage_matches(self) -> None:
        """Every storage read matches the reference model."""
        for addr in ADDRESSES:
            for key in KEYS:
                actual = self.tracker.get_storage(self.tx, addr, key)
                expected = self.storage.get(addr, {}).get(key, 0)
                assert int(actual) == expected

    @invariant()
    def created_matches(self) -> None:
        """The created-accounts set matches the model."""
        assert set(self.tx.created_accounts) == self.created


def _machine_for(tracker: ModuleType) -> type:
    machine = type(
        f"StateTrackerMachine_{tracker.__name__}",
        (StateTrackerMachine,),
        {"tracker": tracker},
    )
    return machine


PROPERTY_TEST_FORKS = ["osaka", "amsterdam"]


@pytest.mark.parametrize("fork_name", PROPERTY_TEST_FORKS)
def test_state_tracker_matches_model(fork_name: str) -> None:
    """The state_tracker matches the reference model across op sequences."""
    tracker = importlib.import_module(
        f"ethereum.forks.{fork_name}.state_tracker"
    )
    run_state_machine_as_test(
        _machine_for(tracker),
        settings=settings(max_examples=200, stateful_step_count=40),
    )
