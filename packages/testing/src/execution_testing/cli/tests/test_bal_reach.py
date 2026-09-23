"""Tests for the BAL reach space derived from the fork's own source."""

from execution_testing.evm_tools.t8n.evm_trace.bal_observer import (
    BalObservation,
    BalReachObserver,
)
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


def test_every_derived_reason_has_a_witness_family() -> None:
    """
    A reason nobody can confirm is a decision owed. An empty list here
    means every family the fork actually uses is covered; a fork growing
    a reason in a new module fails this and forces the call.
    """
    from ..fuzzer_bridge.bal_reach import unwitnessed

    assert unwitnessed(Amsterdam) == []


def test_an_unwitnessed_reason_cannot_be_counted_reached() -> None:
    """
    The rule `EVENT_WITNESSES` spells out, carried onto this axis: a cell
    subtracted on no evidence reports coverage nothing confirms, and a
    false green never gets worked on the way a gap does.
    """
    from ..fuzzer_bridge.bal_reach import unreached, witness_kind

    assert witness_kind("vm.instructions.storage.sload") == "trace"
    assert witness_kind("fork.process_withdrawals") == "behavioral"
    assert witness_kind("somewhere.new.reason") == ""

    witnessed = ("vm.instructions.storage.sload", "storage_read", "success")
    invented = ("somewhere.new.reason", "storage_read", "success")
    cells, _ = unreached(Amsterdam, [witnessed, invented])
    assert witnessed not in cells
    # The invented one is not in the derived space at all, so the guard
    # is that claiming it changes nothing rather than adding a cell.
    assert invented not in cells


def test_the_tracker_reports_the_whole_space_before_any_case() -> None:
    """
    A fresh run has reached nothing, so the map is the full space -- the
    honest first state for an instrument built before its shapes.
    """
    from ..fuzzer_bridge.signature_baseline import NoveltyTracker

    tracker = NoveltyTracker()
    cells, pairs = bal_reach_space(Amsterdam)
    assert len(tracker.unreached_bal_cells(Amsterdam)) == len(cells)
    assert len(tracker.unreached_bal_aliases(Amsterdam)) == len(pairs)
    tracker.observe_bal(
        cells=[("vm.instructions.storage.sload", "storage_read", "success")]
    )
    assert len(tracker.unreached_bal_cells(Amsterdam)) == len(cells) - 1


def test_the_space_record_is_trendable_and_starts_at_zero_reached() -> None:
    """
    The baseline the first BAL shapes are measured against, written before
    they exist. `cells_reached` is explicitly zero rather than absent, so
    the first non-zero entry is visibly the observation source landing and
    not a change in what the field means.
    """
    import json

    from ..fuzzer_bridge.signature_baseline import (
        bal_space_record,
        render_bal_space,
    )

    record = bal_space_record(Amsterdam)
    cells, pairs = bal_reach_space(Amsterdam)
    assert record["kind"] == "bal-space"
    assert record["cells"] == len(cells)
    assert record["alias_pairs"] == len(pairs)
    assert record["cells_reached"] == 0
    assert record["generator_version"] and record["eels_commit"]
    json.dumps(record)  # one reach-log line
    assert "reasons" in render_bal_space(record)


def _observed_fills(seeds: range, spec: object = None) -> list:
    """Fill real cases with the observer on; one observation per case."""
    import contextlib
    import io
    import warnings

    from ..fuzzer_bridge import campaign as mod
    from ..fuzzer_bridge.bal_reach import observer_spec
    from ..fuzzer_bridge.generator import generate_fuzzer_output

    mod._init_fill_worker("Amsterdam")
    fork, eels = mod._FILL["fork"], mod._FILL["eels"]
    eels.bal_reach = spec or observer_spec(fork)
    observations = []
    for seed in seeds:
        eels.last_bal_observation = None
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    mod.fill_case(
                        generate_fuzzer_output(fork, seed), fork, eels
                    )
        except Exception:  # noqa: BLE001 - an unfillable seed observes nothing
            continue
        observations.append(eels.last_bal_observation)
    return observations


def test_every_recorder_binding_the_fork_imports_is_wrapped() -> None:
    """
    The recorders are imported by name, so a binding the hook does not
    replace is a quarter of the calls going nowhere with no error. The
    bindings that must exist are read off the fork's own imports rather
    than listed, and an import inside a function body -- which no
    module-level wrapping can reach -- fails here rather than silently.
    """
    import ast

    from ..fuzzer_bridge.bal_reach import (
        TRACKER_MODULE,
        _fork_package,
        _module_asts,
        recorders,
    )

    names = set(recorders(Amsterdam))
    expected = {(TRACKER_MODULE, name) for name in names}
    lazy = []
    for module, tree in _module_asts(_fork_package(Amsterdam)).items():
        top_level = set(tree.body)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            if not (node.module or "").endswith(TRACKER_MODULE):
                continue
            for alias in node.names:
                if alias.name not in names:
                    continue
                if node in top_level:
                    expected.add((module, alias.asname or alias.name))
                else:
                    lazy.append((module, alias.name))
    assert not lazy, f"recorders imported inside functions: {lazy}"
    (observation,) = _observed_fills(range(710000, 710001))
    assert expected <= observation.bindings


def test_no_recorder_call_goes_unattributed() -> None:
    """
    The runtime witness for the derivation: every recorder call's first
    frame outside the tracker is a derived reason. The kill check drops
    one reason from the spec, and its calls must then surface as
    unattributed rather than be credited to a reason further up the
    stack, which is what a looser rule would do without complaint.
    """
    import dataclasses

    from ..fuzzer_bridge.bal_reach import observer_spec

    observations = _observed_fills(range(710000, 710010))
    assert observations
    assert all(not o.unattributed for o in observations)

    spec = observer_spec(Amsterdam)
    dropped = "vm.instructions.storage.sload"
    blind = dataclasses.replace(spec, reasons=spec.reasons - {dropped})
    missed = _observed_fills(range(710000, 710010), blind)
    assert any(dropped in o.unattributed for o in missed)


def test_a_frame_that_runs_no_code_still_gets_its_outcome() -> None:
    """
    A call into an account with no code emits no `EvmStop`, so the trace
    never closes its frame; the frame's own `error` says how it ended.
    Dropping those would lose plain value transfers into accounts.
    """
    observations = _observed_fills(range(710000, 710030))
    assert sum(o.closed_by_state for o in observations) > 0
    assert all(o.unresolved == 0 for o in observations)


def test_fees_join_the_transaction_they_were_charged_for() -> None:
    """
    `TransactionEnd` is traced before the fees are disbursed, so fee
    entries arrive after their transaction has closed. Both phases belong
    to the same transaction, so per case they must show the same outcomes;
    a broken late join would leave the fee entries all `success`.
    """
    observations = _observed_fills(range(710000, 710060))

    def outcomes(observation: BalObservation, reason: str) -> set:
        return {
            outcome
            for r, kind, outcome in observation.cells
            if r == reason and kind == "touched_account"
        }

    non_success = False
    for observation in observations:
        sender = outcomes(observation, "fork.update_sender_state")
        fees = outcomes(observation, "fork.disburse_gas_fees")
        assert sender == fees
        non_success |= bool(sender - {"success"})
    assert non_success, "no failing transaction in range; widen the seeds"


def test_the_wrapping_is_undone_when_the_fill_returns() -> None:
    """The hook must not leak into fills that did not ask for it."""
    import importlib

    tracker = importlib.import_module("ethereum.forks.amsterdam.state_tracker")
    storage = importlib.import_module(
        "ethereum.forks.amsterdam.vm.instructions.storage"
    )
    _observed_fills(range(710000, 710001))
    assert tracker.get_storage.__name__ == "get_storage"
    assert storage.get_storage is tracker.get_storage


def test_the_observation_record_carries_the_cross_check() -> None:
    """
    The reach-log line for the runtime half: unattributed calls are the
    number that must be zero, and the frame-state fallback is counted so
    it reads as a number rather than a silent default.
    """
    import json

    from ..fuzzer_bridge.bal_reach import entry_reasons
    from ..fuzzer_bridge.signature_baseline import bal_observation_record

    record = bal_observation_record(Amsterdam, range(710000, 710010))
    json.dumps(record)
    assert record["kind"] == "bal-observed"
    assert record["unattributed"] == {}
    assert record["unresolved"] == 0
    assert 0 < record["cells_reached"] <= record["cells"]
    assert set(record["reasons_never_observed"]) <= set(
        entry_reasons(Amsterdam)
    )


def test_only_one_recorder_can_be_called_and_record_nothing() -> None:
    """
    Derived from where each recorder's recording statements sit:
    `destroy_storage` records only under a branch, while `set_storage`'s
    guarded initialisation sits beside an unconditional write.
    """
    from ..fuzzer_bridge.bal_reach import conditional_recorders

    assert conditional_recorders(Amsterdam) == frozenset({"destroy_storage"})


def test_a_destroy_with_nothing_pending_is_not_a_storage_read() -> None:
    """
    The fee-path phantom: a zero-tip credit to an empty coinbase destroys
    it, and the destroy finds no pending writes, so nothing is read. The
    positive is a destroy that does turn a pending write into a read.
    """
    import importlib
    from types import SimpleNamespace

    from ..fuzzer_bridge.bal_reach import observer_spec

    tracker = importlib.import_module("ethereum.forks.amsterdam.state_tracker")
    observer = BalReachObserver(observer_spec(Amsterdam))
    address = b"\x00" * 19 + b"\x0f"

    def state(pending: dict) -> SimpleNamespace:
        return SimpleNamespace(
            storage_writes=pending,
            storage_reads=set(),
            account_reads=set(),
            account_writes={},
        )

    _, nothing = observer.observe_call(
        "destroy_storage", tracker.destroy_storage, (state({}), address), {}
    )
    assert nothing == set()

    pending = state({address: {b"\x01" * 32: 7}})
    _, read = observer.observe_call(
        "destroy_storage", tracker.destroy_storage, (pending, address), {}
    )
    assert read == {"storage_read"}
    assert (address, b"\x01" * 32) in pending.storage_reads


def test_a_real_destroy_of_pending_writes_is_still_a_read() -> None:
    """
    The positive on real execution for the conditional check: an account
    destroyed at the end of its transaction with writes still pending
    (created and self-destructed in one transaction) has those writes
    enter the list as reads, and that must survive the check that removed
    the empty-destroy phantom.
    """
    observations = _observed_fills(range(0, 100))
    reads = {
        cell
        for observation in observations
        for cell in observation.cells
        if cell[0] == "fork.process_transaction" and cell[1] == "storage_read"
    }
    assert reads, "no destroyed pending write in range; widen the seeds"
