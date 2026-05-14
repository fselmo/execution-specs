# CALL family code-path catalog

Canonical enumeration of every code path through the `CALL`, `CALLCODE`,
`DELEGATECALL`, and `STATICCALL` opcodes. Each row has a stable id used by
the matrix-parametrized driver at `tests/opcodes/call/test_call_family.py`
and by `scripts/audit_codepath_coverage.py`.

This document is the **single source of truth** for the matrix. Adding a code
path means: (1) add a row here, (2) extend the matrix in the driver, (3) extend
`expected_call()` to compute the per-fork expectation. Removing a row means the
same in reverse, plus a migration note explaining what client-observable
behavior the dropped row used to cover.

## Axes

The matrix is the Cartesian product (filtered by `filter_combinations`) of:

| Axis          | Values (id)                                                                     |
| ------------- | ------------------------------------------------------------------------------- |
| `opcode`      | `CALL` / `CALLCODE` / `DELEGATECALL` (Homestead+) / `STATICCALL` (Byzantium+)   |
| `target_kind` | `eoa` / `contract` / `precompile` / `empty` / `self` / `7702` (Prague+)         |
| `ctx`         | `normal` / `static` (Byzantium+) / `init` (always)                              |
| `value_kind`  | `zero` / `nonzero` / `all-balance` / `more-than-balance`                        |
| `ret_layout`  | `no-mem` / `expand-32` / `huge-offset-zero-size` / `overlap-args` / `truncate`  |
| `args_layout` | `no-mem` / `expand-32` / `huge-offset-zero-size`                                |
| `gas_variant` | `sufficient` / `stipend-only` / `oog-pre` / `oog-mid` / `gas-shortage-by-1`     |

Sourced from `fork.call_opcodes()`, so opcodes that did not yet exist at a
given fork are not emitted. Same for precompiles (`fork.precompiles()`) when
`target_kind = precompile`.

## Cross-axis constraints (filter_combinations)

| Predicate | Reason |
| --------- | ------ |
| `ctx == static and value_kind != zero` | Static context forbids nonzero value |
| `opcode in (STATICCALL, DELEGATECALL) and value_kind != zero` | Opcode signature has no value arg |
| `target_kind == 7702 and fork < Prague` | EIP-7702 introduced delegation |
| `target_kind == self and opcode == DELEGATECALL` | Identical to a no-op in most paths; covered by a single targeted row, not the matrix |

## Behaviour catalog

Each row maps to a parametrize id of the form
`<opcode>-target=<target>-ctx=<ctx>-value=<value>-ret=<ret_layout>-args=<args_layout>-gas=<gas_variant>`.
Only rows where behavior diverges from the matrix default need an
entry here; the rest are covered structurally by the matrix.

### Gas behavior

| ID                            | Behavior                                                                                                                | Fork(s) | Currently covered by                                                              |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------- | --------------------------------------------------------------------------------- |
| `gas/base-cost`               | Bare opcode cost (no value, no expansion, warm target where applicable)                                                 | All     | implicit in every test that asserts gas                                           |
| `gas/value-stipend-added`     | When `value > 0`, callee receives an extra `CALL_STIPEND` (2300) on top of forwarded gas                                | All     | `test_value_transfer_gas_calculation*`                                            |
| `gas/value-stipend-early-revert` | Early revert path (insufficient sender balance) still expands memory before reverting                                | All     | `test_call_memory_expands_on_early_revert` (Berlin+ only — extend to all forks)   |
| `gas/cold-account-access`     | First call to an address pays `COLD_ACCOUNT_ACCESS_COST` (2600)                                                         | Berlin+ | `test_call_insufficient_balance` (warming behavior)                               |
| `gas/warm-account-access`     | Subsequent call pays `WARM_STORAGE_READ_COST` (100)                                                                     | Berlin+ | implicit                                                                          |
| `gas/new-account-cost`        | When sending value to non-existent / empty account, pays `NEW_ACCOUNT` (25000)                                          | All     | `test_value_transfer_gas_calculation*`                                            |
| `gas/insufficient-balance`    | Value transfer with sender balance < value — call pushes 0, no value moved, warming still occurs                        | All     | `test_call_insufficient_balance` (Berlin+ only — extend to all forks)             |
| `gas/oog-before-pushes`       | Caller runs out of gas before pushing args — opcode never executes                                                      | All     | not directly covered                                                              |
| `gas/oog-mid-call`            | Callee OOG mid-execution — caller observes return 0, return data empty                                                  | All     | not directly covered                                                              |
| `gas/shortage-by-1`           | Pre-Byzantium: gas allowance off-by-1 vs Homestead's mandatory `+1`                                                     | Homestead only | `test_value_transfer_gas_calculation_homestead`                            |

### Argument-region behavior

| ID                                | Behavior                                                                                                       | Fork(s) | Currently covered by                                       |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------- | ------- | ---------------------------------------------------------- |
| `args/no-mem`                     | Pass `args_size=0, args_offset=0`; no memory touched                                                           | All     | implicit                                                   |
| `args/expand-32`                  | Pass 32 bytes from a region that requires memory growth                                                        | All     | implicit                                                   |
| `args/huge-offset-zero-size`      | `args_offset=2**100, args_size=0` — must not trigger expansion                                                 | All     | `test_call_large_args_offset_size_zero` (Berlin+ only)     |

### Return-region behavior

| ID                                | Behavior                                                                                                       | Fork(s) | Currently covered by                                                              |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------- | ------- | --------------------------------------------------------------------------------- |
| `ret/no-mem`                      | `ret_size=0`                                                                                                   | All     | implicit                                                                          |
| `ret/expand-32`                   | `ret_size=32` into fresh memory                                                                                | All     | implicit                                                                          |
| `ret/huge-offset-zero-size`       | `ret_offset>memsize, ret_size=0` — must not expand                                                             | All     | `test_call_large_offset_mstore` (Berlin+ only — extend to all forks)              |
| `ret/truncate-callee-output`      | Callee returns N bytes, caller's `ret_size < N` — only first `ret_size` written, RETURNDATASIZE reflects full N | Byzantium+ | not directly covered                                                            |
| `ret/overlap-args`                | `ret_offset` overlaps `args_offset` region                                                                     | All     | not directly covered                                                              |

### Target-kind behavior

| ID                              | Behavior                                                                                                    | Fork(s)    | Currently covered by                                              |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------- | ---------- | ----------------------------------------------------------------- |
| `target/eoa`                    | Subcall to a plain EOA returns 1, no code executed, value moved if applicable                               | All        | implicit                                                          |
| `target/contract`               | Subcall to a contract — code runs in subcontext per opcode semantics                                        | All        | implicit                                                          |
| `target/precompile`             | Subcall to a precompile (parametrized over `fork.precompiles()`)                                            | All        | `test_staticcall_*_precompile`                                    |
| `target/empty`                  | Subcall to account with `balance=0, code=∅, nonce=0` — EIP-161 deletion semantics                           | All        | implicit (touch/ tests)                                           |
| `target/self`                   | Caller subcalls its own address                                                                             | All        | not directly covered                                              |
| `target/7702-delegated`         | Subcall to account that has an EIP-7702 delegation (code = `0xef0100‖address`)                              | Prague+    | `tests/prague/eip7702_set_code_tx/` (separate tests)              |
| `target/7702-delegated-to-precompile` | Delegated indirection lands on a precompile address                                                   | Prague+    | not directly covered                                              |
| `target/7702-self-delegation`   | Account delegates to itself                                                                                  | Prague+    | not directly covered                                              |

### Context behavior

| ID                          | Behavior                                                                                              | Fork(s)    | Currently covered by                                           |
| --------------------------- | ----------------------------------------------------------------------------------------------------- | ---------- | -------------------------------------------------------------- |
| `ctx/normal`                | Top-level or non-static call chain                                                                    | All        | implicit                                                       |
| `ctx/static`                | Inside a STATICCALL — state-modifying suboperations must revert                                       | Byzantium+ | `test_staticcall_*`                                            |
| `ctx/static-nested-call`    | STATICCALL → CALL (no value): permitted; STATICCALL → CALL (value): reverts                           | Byzantium+ | `test_staticcall_reentrant_call_to_precompile`                 |
| `ctx/init`                  | Caller is currently running init code (constructor)                                                   | All        | `test_staticcall_call_to_precompile_from_contract_init`        |

### Recursion / depth

| ID                       | Behavior                                                                                  | Fork(s) | Currently covered by             |
| ------------------------ | ----------------------------------------------------------------------------------------- | ------- | -------------------------------- |
| `depth/max-1024`         | Subcall at depth 1024 — fails, parent observes return 0, all gas forwarded is consumed     | All     | not directly covered             |
| `depth/just-under`       | Subcall at depth 1023 — succeeds; checks no off-by-one                                    | All     | not directly covered             |

### Fork-introduced behaviors

| ID                                  | Behavior                                                                                                          | Introduced                | Currently covered by                                                  |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------- | --------------------------------------------------------------------- |
| `fork/homestead-delegatecall`       | DELEGATECALL opcode exists; preserves `msg.sender` and `msg.value` from parent                                    | Homestead (EIP-7)         | `test_value_transfer_gas_calculation_homestead` (via fork.call_opcodes) |
| `fork/tangerine-150-reprice`        | All *CALL repriced to 700; only `GAS - GAS/64` forwarded                                                          | Tangerine Whistle (EIP-150) | not directly covered                                                |
| `fork/spurious-dragon-empty-acct`   | Empty-account stipend rules changed (EIP-161 / EIP-158)                                                           | Spurious Dragon           | not directly covered                                                  |
| `fork/byzantium-staticcall`         | STATICCALL opcode exists; sub-context cannot modify state                                                         | Byzantium (EIP-214)       | all of `tests/byzantium/eip214_staticcall/`                           |
| `fork/byzantium-returndata`         | RETURNDATASIZE / RETURNDATACOPY usable after any *CALL                                                            | Byzantium                 | implicit                                                              |
| `fork/berlin-cold-warm`             | EIP-2929 cold/warm gas accounting on target address                                                                | Berlin                    | `test_call_insufficient_balance`                                      |
| `fork/berlin-2930-access-list`      | Pre-warming via access-list reduces first-call cost to warm                                                       | Berlin (EIP-2930)         | `tests/berlin/eip2930_access_list/`                                   |
| `fork/cancun-6780-selfdestruct`     | Subcall that SELFDESTRUCTs: only deletes if in same tx as creation                                                | Cancun (EIP-6780)         | `tests/cancun/eip6780_selfdestruct/`                                  |
| `fork/prague-7702-delegation`       | Code = `0xef0100‖addr` triggers delegation lookup                                                                  | Prague (EIP-7702)         | `tests/prague/eip7702_set_code_tx/`                                   |
| `fork/amsterdam-7708-eth-log`       | Nonzero-value subcall emits an ETH-transfer log                                                                    | Amsterdam (EIP-7708)      | `tests/amsterdam/eip7708_eth_transfer_logs/test_burn_logs.py`         |
| `fork/amsterdam-7928-bal-touched`   | Subcall participants (target, caller-on-value, EIP-7702 delegation indirection) appear in the block access list  | Amsterdam (EIP-7928)      | `tests/amsterdam/eip7928_block_level_access_lists/`                   |

### Regression rows (specific bugs reproduced)

| ID                                          | Bug being reproduced                                                                                                       | Currently covered by                                  |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| `regression/ethjs-3194-stipend-pre-add`     | EthereumJS pre-added stipend to remaining gas instead of new frame                                                         | `test_value_transfer_gas_calculation*`                |
| `regression/eth-tests-683-reentrant-static` | STATICCALL → CALL precompile reentrance regression                                                                          | `test_staticcall_reentrant_call_to_precompile`        |
| `regression/large-offset-zero-size-mstore`  | Faulty EVM expanded memory on CALL with ret_size=0 + large ret_offset                                                       | `test_call_large_offset_mstore`                       |
| `regression/early-revert-memory-expansion`  | Value-transfer revert path skipped memory expansion                                                                          | `test_call_memory_expands_on_early_revert`            |

## Mapping table (old → new id)

Used by `scripts/audit_codepath_coverage.py`. Every existing test case must
map to one new parametrize id (or be explicitly documented as dropped with a
rationale).

| Old (file::function::parametrize_id)                                                                                              | New parametrize id                                                            | Notes                                              |
| --------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | -------------------------------------------------- |
| `tests/frontier/opcodes/test_call.py::test_call_large_offset_mstore`                                                              | `CALL-target=eoa-ctx=normal-value=zero-ret=huge-offset-zero-size-args=no-mem-gas=sufficient` | covered as a row in the matrix; tagged `regression/large-offset-zero-size-mstore` |
| `tests/frontier/opcodes/test_call.py::test_call_memory_expands_on_early_revert`                                                   | `CALL-target=eoa-ctx=normal-value=nonzero-ret=expand-32-args=no-mem-gas=insufficient-balance` | tagged `regression/early-revert-memory-expansion`  |
| `tests/frontier/opcodes/test_call.py::test_call_large_args_offset_size_zero[CALL]`                                                 | `CALL-target=eoa-ctx=normal-value=zero-ret=no-mem-args=huge-offset-zero-size-gas=sufficient`  | with_all_call_opcodes — each opcode is one row     |
| `tests/frontier/opcodes/test_call.py::test_call_large_args_offset_size_zero[CALLCODE]`                                             | `CALLCODE-target=eoa-ctx=normal-value=zero-ret=no-mem-args=huge-offset-zero-size-gas=sufficient` |                                                  |
| `tests/frontier/opcodes/test_call.py::test_call_large_args_offset_size_zero[DELEGATECALL]`                                         | `DELEGATECALL-target=eoa-ctx=normal-value=zero-ret=no-mem-args=huge-offset-zero-size-gas=sufficient` |                                              |
| `tests/frontier/opcodes/test_call.py::test_call_large_args_offset_size_zero[STATICCALL]`                                           | `STATICCALL-target=eoa-ctx=normal-value=zero-ret=no-mem-args=huge-offset-zero-size-gas=sufficient` |                                                |
| `tests/frontier/opcodes/test_call_and_callcode_gas_calculation.py::test_value_transfer_gas_calculation[*-gas_shortage=0]`           | `<opcode>-target=empty-ctx=normal-value=nonzero-ret=no-mem-args=no-mem-gas=sufficient`        | gas_shortage=0 → sufficient gas; called account is new |
| `tests/frontier/opcodes/test_call_and_callcode_gas_calculation.py::test_value_transfer_gas_calculation[*-gas_shortage=1]`           | `<opcode>-target=empty-ctx=normal-value=nonzero-ret=no-mem-args=no-mem-gas=gas-shortage-by-1` | gas_shortage=1 → insufficient gas by 1             |
| `tests/frontier/opcodes/test_call_and_callcode_gas_calculation.py::test_value_transfer_gas_calculation_byzantium[*]`                | (same as above, restricted to Byzantium–Berlin range)                                          | matrix runs across all valid forks automatically   |
| `tests/frontier/opcodes/test_call_and_callcode_gas_calculation.py::test_value_transfer_gas_calculation_homestead[*-gas_shortage=2]` | new id `<opcode>-...-gas=homestead-allowance-off-by-1`                                         | unique Homestead path — `gas_variant` extended     |
| `tests/byzantium/eip214_staticcall/test_staticcall.py::test_staticcall_reentrant_call_to_precompile[*-zero_value]`                  | `STATICCALL-target=precompile-ctx=static-nested-call-value=zero-...`                          | nested-call ctx                                    |
| `tests/byzantium/eip214_staticcall/test_staticcall.py::test_staticcall_reentrant_call_to_precompile[*-nonzero_value]`               | filtered out by `(ctx==static, value!=zero)`                                                   | only valid when nested CALL inside STATICCALL has value=0; the value!=0 case asserts a revert and is kept as a dedicated row |
| `tests/byzantium/eip214_staticcall/test_staticcall.py::test_staticcall_call_to_precompile[*-*]`                                     | `STATICCALL-target=precompile-ctx=static-value=zero-...`                                       |                                                  |
| `tests/byzantium/eip214_staticcall/test_staticcall.py::test_staticcall_nested_call_to_precompile[*-*]`                              | `STATICCALL-target=precompile-ctx=static-nested-call-...`                                      |                                                  |
| `tests/byzantium/eip214_staticcall/test_staticcall.py::test_staticcall_call_to_precompile_from_contract_init[*-CREATE]`              | `STATICCALL-target=precompile-ctx=init-value=zero-...` × create_opcode=CREATE                  | `ctx=init` × create_opcode axis                    |
| `tests/byzantium/eip214_staticcall/test_staticcall.py::test_staticcall_call_to_precompile_from_contract_init[*-CREATE2]`             | same with `create_opcode=CREATE2`                                                              | filtered to `fork >= Constantinople`               |
| `tests/berlin/eip2929_gas_cost_increases/test_call.py::test_call_insufficient_balance`                                              | `CALL-target=eoa-ctx=normal-value=nonzero-ret=no-mem-args=no-mem-gas=insufficient-balance` (Berlin+ asserts cold→warm; matrix expectations encode this per fork) | extend to all forks; tag `regression/insufficient-balance-still-warms` |

## Out of scope (covered by other tests, not migrated here)

- `tests/frontier/scenarios/scenarios/call_combinations.py` and
  `double_call_combinations.py`: combinatorial **integration** tests, not opcode-targeted.
  Catalog separately when the scenarios pattern is itself reviewed.
- BAL tests under `tests/amsterdam/eip7928_block_level_access_lists/`:
  these test the BAL machinery, not CALL semantics. They will consume the
  `block_access_list` field of `CallExpected` once the matrix lands, but they
  remain their own test file.
- EIP-7702 tests under `tests/prague/eip7702_set_code_tx/`: same story — the
  matrix exercises `target_kind=7702-delegated`, but the delegation-protocol
  tests stay separate.
- Benchmark tests under `tests/benchmark/`: outside opcode-semantics scope.

## How to extend

When a new fork introduces a code path that affects CALL semantics:

1. Add a row to the **Fork-introduced behaviors** table above with the new id.
2. If the path requires a new value on an existing axis, extend the axis
   (e.g., add `target_kind=7702-delegated-to-eof` if EOF lands). Add the
   `pytest.param(..., marks=valid_from("…"))` to the driver.
3. If the path requires a wholly new axis (rare), add the axis to the **Axes**
   table and to the driver's parametrize stack. Also extend
   `expected_call(...)` to read the new param.
4. Add cross-axis filters to **Cross-axis constraints** if combinations are
   structurally impossible.
5. Update `scripts/audit_codepath_coverage.py` if the matrix would otherwise
   leave any pre-existing test case unmapped.
