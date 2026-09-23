"""Tests for the BAL reach space derived from the fork's own source."""

from execution_testing.forks import Amsterdam

from ..fuzzer_bridge.bal_reach import (
    alias_cells,
    bal_reach_space,
    entry_kinds,
    entry_reasons,
    outcomes,
    recorders,
)


def test_recorders_come_from_the_tracker_and_only_when_they_record() -> None:
    """
    A recorder writes into a collection; reading one to answer a query is
    not recording. `get_storage` adds to `storage_reads` and only reads
    `storage_writes` to find the value, so it records a read and nothing
    else.
    """
    found = recorders(Amsterdam)
    assert found["get_storage"] == frozenset({"storage_read"})
    assert found["get_account_optional"] == frozenset({"touched"})
    assert found["set_storage"] == frozenset({"storage_write"})
    # Moving whole collections between states is plumbing, not access.
    assert "copy_tx_state" not in found


def test_entry_kinds_are_the_builder_s_own_vocabulary() -> None:
    """
    One account write fans out into the fields `update_builder_from_tx`
    diffs, so the axis carries balance, nonce and code separately rather
    than a single opaque write.
    """
    kinds = entry_kinds(Amsterdam)
    assert kinds == frozenset(
        {
            "balance_change",
            "nonce_change",
            "code_change",
            "storage_read",
            "storage_write",
            "touched_account",
        }
    )


def test_delegate_resolution_is_a_reason() -> None:
    """
    The case a module allow-list silently dropped. EIP-7702 delegation
    resolves code through the tracker, so it puts an address in the list
    and has to be its own cell.
    """
    reasons = entry_reasons(Amsterdam)
    assert "vm.eoa_delegation.resolve_delegated_code_address" in reasons


def test_the_derivation_finds_reasons_a_hand_list_missed() -> None:
    """
    Four the human enumeration omitted, the last being the EIP-8037
    state-gas path. Each is a real call into the tracker.
    """
    reasons = entry_reasons(Amsterdam)
    for missed in (
        "vm.instructions.environment.self_balance",
        "fork.check_transaction",
        "fork.update_sender_state",
        "vm.interpreter.charge_value_transfer_to_non_alive_account",
    ):
        assert missed in reasons


def test_precompile_dispatch_is_not_a_reason() -> None:
    """
    The phantom the hand list invented: precompiles never touch the
    tracker, so a precompile address enters through the ordinary call
    destination access and a row of its own would never be reached.
    """
    reasons = entry_reasons(Amsterdam)
    assert not [r for r in reasons if "precompiled_contracts" in r]


def test_the_list_builder_is_not_a_reason_for_its_own_list() -> None:
    """
    The near-miss behind matching calls by bare name:
    `_get_pre_tx_account` calls `pre_state.get_account_optional(...)`, a
    different object's method that shares a name with the tracker
    function. Counting it made building the list a reason for entering it.
    """
    reasons = entry_reasons(Amsterdam)
    assert not [r for r in reasons if r.startswith("block_access_lists.")]


def test_a_function_reaching_only_through_another_reason_is_not_one() -> None:
    """
    The stop rule. `state_transition` reaches the tracker through
    `process_transaction`, which is already a reason, so attributing the
    access to both would double-count every cell.
    """
    reasons = entry_reasons(Amsterdam)
    assert "fork.process_transaction" in reasons
    assert "fork.state_transition" not in reasons
    assert "fork.apply_body" not in reasons


def test_outcomes_group_so_a_new_exception_cannot_go_missing() -> None:
    """
    A fork's new halt lands in `exceptional_halt` rather than being absent
    from the axis.
    """
    assert outcomes(Amsterdam) == frozenset(
        {"success", "revert", "out_of_gas", "exceptional_halt"}
    )


def test_aliasing_falls_out_of_the_reasons_that_resolved_together() -> None:
    """
    `sender == coinbase` is not a typed case: it is whichever reasons
    landed on one address at one block access index. A pair nobody thought
    of is a cell, not an absence.
    """
    reached = alias_cells(
        {
            "0xcoinbase": [
                "fork.update_sender_state",
                "fork.disburse_gas_fees",
            ],
            "0xlonely": ["vm.instructions.system.call"],
        }
    )
    assert reached == frozenset(
        {("fork.disburse_gas_fees", "fork.update_sender_state")}
    )


def test_the_space_pairs_a_reason_only_with_kinds_it_can_cause() -> None:
    """
    `sload` reads storage and nothing else, so it gets storage-read cells
    and no balance cell. Without that the naive product would enumerate
    cells no case could ever reach.
    """
    cells, pairs = bal_reach_space(Amsterdam)
    sload = {
        (kind, outcome)
        for reason, kind, outcome in cells
        if reason == "vm.instructions.storage.sload"
    }
    assert {kind for kind, _ in sload} == {"storage_read"}
    assert pairs and all(a < b for a, b in pairs)
