# Spec-ambiguity findings

A running log of behaviours the EIP prose does not determine, surfaced by
property-mining runs (`/mine-properties`, third triage track). Each entry
records the behaviour, what EELS implements (cited), what the prose fails to
say, and the minimal question an author would need to answer. EELS's choice
is pinned by docstring-tier (self-descriptive) properties where noted, so a
later prose decision that contradicts it reads as "update the spec", never
"the spec was always right".

Nothing here is posted externally by tooling; findings are relayed to EIP
authors by maintainers.

## EIP-8037 (state creation gas) — mined 2026-07-21

Verified against source before recording. Pinning properties live in
`tests_property/test_eip8037_state_gas.py`.

### 1. Delegation state-gas surviving top-frame failure

- **Behaviour**: whether the `NEW_ACCOUNT` / `AUTH_BASE` state gas charged
  for applied EIP-7702 authorizations is refilled when the top frame later
  reverts or halts — given the delegations themselves persist through that
  failure.
- **EELS's choice**: not refilled. `commit_state_gas` marks it
  non-refillable after `set_delegation`
  (`amsterdam/vm/interpreter.py:362-371`, `vm/gas.py:409-440`); a later
  failure restores only to the post-commit baseline. Pre-dispatch failures
  roll everything back via `restore_state_gas_to_entry`.
- **Prose gap**: EIP-8037's halts/reverts section says a failing frame's
  state gas "is refilled", with no carve-out for state that survives the
  failure. The entire commit/baseline mechanism has no counterpart in the
  EIP.
- **Question for the author**: when a transaction with applied EIP-7702
  authorizations reverts or halts in its top frame, is the authorization
  state-gas refilled, given the delegations persist?

### 2. Rollback of a frame with net-negative state gas

- **Behaviour**: a frame can refill more state gas than it charged (e.g.
  clearing a storage slot an ancestor frame created), pushing the reservoir
  above its frame-entry level. What happens to that excess refill when the
  frame reverts and the state change earning it is undone?
- **EELS's choice**: the rollback re-charges it — `restore_state_gas`
  resets the reservoir *down* to the baseline (`vm/gas.py:443-465`), so the
  refill is reversed along with the state change that earned it.
- **Prose gap**: EIP-8037 only says charged state gas "is refilled" on
  rollback; it never addresses reversing refills whose state change rolled
  back.
- **Question for the author**: on frame rollback, is the frame's state-gas
  accounting restored to its entry value (undoing refills received within
  the frame), or are only charges refilled?

### 3. Negative net state gas at block accounting

- **Behaviour**: a transaction's net `execution_state_gas_used` can be
  negative (refills exceeding charges). The EIP's block accounting
  (`block_state_gas_used += tx_state_gas`) has no clamp, so a negative
  contribution would reduce the block's state gas used — consensus-relevant
  for block validity and the base-fee update.
- **EELS's choice**: clamp per transaction at settlement —
  `settled_state_gas_used = Uint(max(0, state_gas_used))`
  (`vm/gas.py:settle_transaction_gas`) — and feed the *clamped* value into
  `regular_gas_used`.
- **Prose gap**: the EIP acknowledges refills decrement the counter but
  never states whether a negative per-transaction value enters block
  accounting unclamped, nor which value enters the regular-gas formula.
- **Question for the author**: may `tx_state_gas` be negative in
  `block_output.block_state_gas_used += tx_state_gas`, or is it clamped to
  zero per transaction — and does the clamped or unclamped value enter the
  regular-gas calculation?

### 4. Child frames' share of the state gas reservoir

- **Behaviour**: how much of the `state_gas_reservoir` a `CALL*`/`CREATE*`
  child frame receives, and whether the child's remaining reservoir returns
  to the parent on success.
- **EELS's choice**: the child receives the parent's **entire** reservoir
  (`drain_state_gas_reservoir`, `vm/gas.py:602-623` — "there is no
  all-but-one-64th rule for state gas") and the parent reabsorbs it
  unconditionally on return (`vm/__init__.py::incorporate_child`) —
  observationally a transaction-shared pool.
- **Prose gap** (verified against the published EIP text): the
  Specification never states the child's reservoir share; the success rule
  enumerates returned `gas_left` and merged `state_gas_from_gas_left` but
  not the reservoir's return; no sentence says whether the 63/64 rule
  applies to state gas. The halt rule ("exactly the reservoir's value at
  the start of the child frame") presupposes a child reservoir without
  defining it.
- **Question for the author**: should the Specification state explicitly
  that call/create forward the entire `state_gas_reservoir` to the child
  (the all-but-one-64th rule applying to regular gas only), and that on
  success the child's remaining reservoir returns to the parent in full?
- Pinned at docstring tier in `tests_property/test_frame_gas_lifecycle.py`
  (reservoir clauses of the drain and round-trip properties).
