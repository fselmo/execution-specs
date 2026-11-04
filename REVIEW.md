# Property suite review

A review of `tests_property/` as it stood on `feat/spec-property-suite`, and what this branch did with each property. Drop this file before the branch goes upstream.

## Rules applied

- **KEEP**: a real invariant (a bound, a conservation, a round trip, an order independence), a cross-fork equivalence of something an EIP did not change, or a model-vs-spec check against the framework or a reference model written from the EIP.
- **DROP**: a property that restates the spec's formula in a second form and can only pass or fail together with it, a property over the interpreter or the state transition (orchestration, where shrinking does not help), or one eels-fuzz already checks differentially.
- **MERGE**: two properties, or two suites, that check the same thing.

## Classification

40 properties on the old branch: 28 kept, 6 merged and 6 dropped. Of the merged, three moved into another suite unchanged in substance, two became one, and one became a case of a new property.

| Suite | Property | Verdict | Reason |
|---|---|---|---|
| `test_forks.py` | `test_every_spec_package_is_tested` | KEEP | Guards the fork axis itself: a spec package no framework fork reaches would silently drop out of every property. |
| `test_gas.py` | `test_memory_gas_cost` | KEEP | Spec against the framework's memory calculator, now up to 2\*\*64 bytes. |
| `test_gas.py` | `test_memory_extension` | KEEP | Invariant (memory grows to the furthest non-empty range) plus the framework's cost, now with stack-word offsets up to 2\*\*256. |
| `test_gas.py` | `test_base_fee_per_gas` | KEEP | Spec against the framework's base fee calculator; base fee now reaches 2\*\*256. |
| `test_gas.py` | `test_blob_gas_price` | KEEP | Spec against the framework's blob price calculator. |
| `test_gas.py` | `test_excess_blob_gas` | KEEP | Spec against the framework, around the target and the EIP-7918 reserve. |
| `test_gas.py` | `test_blob_fee` | KEEP | Blob gas and fee against the framework for every transaction type. |
| `test_transaction_gas.py` | `test_minimum_gas_limit_boundary` | KEEP | Intrinsic cost boundary on both sides against the framework, every type. |
| `test_transaction_gas.py` | `test_gas_limit_cap_boundary` | KEEP | EIP-7825/8037 cap on both sides. |
| `test_transaction_gas.py` | `test_intrinsic_execution_gas_cap_boundary` | KEEP | EIP-7825 cap on intrinsic execution gas, both sides. |
| `test_transaction_gas.py` | `test_calldata_floor_cap_boundary` | KEEP | EIP-7623 floor against the cap, both sides. |
| `test_gas_meter.py` | `test_restore_returns_to_the_last_commit` | KEEP | Round trip: a rollback undoes exactly what followed the commit. |
| `test_gas_meter.py` | `test_halted_frame_leaves_the_reservoir_whole` | KEEP | Invariant: a halt without a commit never touches the reservoir. |
| `test_gas_meter.py` | `test_restore_to_entry_undoes_the_commit` | KEEP | Round trip to frame entry. |
| `test_gas_meter.py` | `test_gas_meter_matches_model` | KEEP | Model-vs-spec (a reservoir model from EIP-8037) with a conservation invariant on regular gas. |
| `test_frame_gas_lifecycle.py` | `test_restore_child_gas_undoes_withhold_and_drain` | MERGE | Round trip on the meter; moved to `test_gas_meter.py`. |
| `test_frame_gas_lifecycle.py` | `test_value_adds_only_the_stipend_to_the_child_grant` | MERGE | A relation between runs of `calculate_message_call_gas`; moved to `test_gas_meter.py`. |
| `test_frame_gas_lifecycle.py` | `test_call_runs_out_of_gas_only_on_its_own_costs` | MERGE | The EIP-150 bound on the call charge; moved to `test_gas_meter.py`. |
| `test_frame_gas_lifecycle.py` | `test_call_that_never_enters_its_child_refunds_both_grants` | DROP | Builds a real `Evm` and runs `CALL`: interpreter tier. The fills that test early call failures cover it. |
| `test_frame_gas_lifecycle.py` | `test_child_round_trips_conserve_both_gas_dimensions` | DROP | Its expected values restate `incorporate_child`'s merge (`reservoir_pooled`, `spill_pooled`, `repaid`), so it passes or fails with it. |
| `test_block_access_list.py` | `test_builder_matches_reference_model` | KEEP | Model-vs-spec against a model written from EIP-7928. |
| `test_block_access_list.py` | `test_ensure_account_acts_as_a_touch` | KEEP | Idempotence, against the model. |
| `test_block_access_list.py` | `test_gas_limit_boundary_is_exact` | KEEP | The item budget on both sides, item cost from the framework. |
| `test_block_access_list.py` | `test_writes_sharing_an_index_net_against_its_start` | KEEP | Invariant: several merges at one index record only the net change. |
| `test_block_access_list.py` | `test_update_builder_records_only_changed_values` | KEEP | The same rule at the transaction entry point, per field. |
| `test_state_machine.py` | `test_state_tracker_matches_model` | KEEP | Model-vs-spec state machine over the state tracker, every fork. |
| `test_rlp.py` | `test_transaction_types_match_the_framework` | KEEP | Cross-check of each fork's type list. |
| `test_rlp.py` | `test_transaction_encoding_matches_the_framework` | KEEP | Round trip and framework encoding; now aimed at the 56-byte long-prefix edge. |
| `test_rlp.py` | `test_transaction_list_prefix_boundary` | DROP | Pins the `ethereum-rlp` library's prefix rule, which `tests/json_loader/test_rlp.py` covers with the ethereum/tests vectors; the round trip now aims at the same edge. |
| `test_rlp.py` | `test_header_encoding_follows_the_rlp_rules` | DROP | Re-derives the RLP rules over a dataclass's field order; every blockchain fixture's block hash is checked by clients in `consume` and in eels-fuzz campaigns. |
| `test_rlp.py` | `test_receipt_encoding_follows_the_rlp_rules` | DROP | eels-fuzz compares the receipts root against every client on every case. |
| `test_signatures.py` | `test_signing_matches_the_framework` | DROP | Every fill and every eels-fuzz case signs with the framework and recovers with the spec; the differential compares the resulting rejections. |
| `test_signatures.py` | `test_high_s_signatures_are_rejected_from_eip_2` | KEEP | Cross-fork rule on both sides of EIP-2. |
| `test_signatures.py` | `test_zero_r_or_s_is_rejected` | MERGE | Into `test_signature_values_past_their_bounds_are_rejected`, which covers every range check in recovery. |
| `test_signatures.py` | `test_replay_protected_signing_matches_the_worked_example` | KEEP | Known-answer vector from EIP-155. |
| `test_trie.py` | `test_root_is_insertion_order_independent` | KEEP | Invariant. |
| `test_trie.py` | `test_insert_then_delete_restores_root` | MERGE | With the next one, into `test_setting_the_default_deletes`. |
| `test_trie.py` | `test_storing_default_equals_absence` | MERGE | Same rule (setting the default deletes). |
| `test_trie.py` | `test_copy_preserves_root_and_isolates_mutation` | KEEP | Invariant. |
| `test_trie.py` | `test_known_root` | KEEP | No other trie vector runs in this repository. |

Merges: `test_frame_gas_lifecycle.py` is gone (three properties to `test_gas_meter.py`, two dropped), the trie pair became one property, and the zero-`r`/`s` test became one case of the signature bounds property.

## Re-aimed at leaf functions

New properties, each a table of cases that pin one rule on both sides (the last value that passes and the first that fails), from a random input built to pass:

- `test_transaction_admission.py`: `check_transaction` from EIP-7928 on. A random transaction in a block built to fit it exactly (the framework's `signer_minimum_balance`, base fees at the transaction's caps, exactly enough execution, state and blob gas) is admitted; 23 cases break or approach nonce, balance, fee cap, priority fee, blob fee, block capacity in all three dimensions, sender code, the EIP-2681 nonce limit, init code size, blob count and version, contract creation and empty authorizations.
- `test_header_validation.py`: `validate_header` from Paris on. A child built from the framework's base fee and excess blob gas calculators is valid; 19 cases cover number, timestamp, gas used, the gas limit step and minimum, base fee, excess blob gas, extra data, difficulty, nonce, ommers hash and parent hash.
- `test_signatures.py::test_signature_values_past_their_bounds_are_rejected`: every range check in sender recovery and the EIP-155 chain id, at the first value past the bound and beyond.
- `test_rlp.py::test_decoding_rejects_unknown_types`: every byte in the EIP-2718 type range that is not one of the fork's types, and the empty encoding.

Every `@given` suite now steers with `aim_at` (Hypothesis `target()`) toward its guards and toward the top of 64-bit and 256-bit fields; the labels are in the code. The two state machines (`test_gas_meter.py`, `test_state_machine.py`) have none, because a rule runs many times per example and `target()` takes each label once.

Two things the new properties turned up, neither a spec bug:

- The framework's `minimum_block_gas_limit()` is 50,000 from Amsterdam on, because it adds the item budget an empty block's access list needs; the header rule is still the Yellow Paper's 5,000. `test_header_validation.py` uses the literal, with a comment.
- `signer_minimum_balance()` reads a zero gas price or fee cap as unset and asserts, so the admission property draws fee caps from 1.

The blob and set-code `TransactionTypeContractCreationError` guard cannot be reached from an encoding: the spec types `to` as an address for those transactions, so decoding rejects an empty `to` first. The admission cases build that transaction on the spec's object.

## Premises in the leaf functions

Every guarded `raise` in Bogota's leaf functions, as `execution_verifier.premises.collect_premises` on `verifier/design` reads them: `vm.gas`, `block_access_lists`, and in `transactions` and `fork` the functions that validate a transaction, recover its sender, price it, admit it and validate a header. "Reached" means the raise line ran in at least one property (coverage.py over `pytest tests_property -k Bogota`). Before: 11 of 49. After: 49 of 49. This list is the seed of the premise registry.

| Function | Line | Raises | Guard | Before | After |
|---|---|---|---|---|---|
| `block_access_lists.validate_block_access_list_gas_limit` | 888 | `BlockAccessListGasLimitExceededError` | `bal_items > block_gas_limit // GasCosts.BLOCK_ACCESS_LIST_ITEM` | yes | yes |
| `fork.calculate_base_fee_per_gas` | 389 | `InvalidBlock` | `not check_gas_limit(block_gas_limit, parent_gas_limit)` | no | yes |
| `fork.validate_header` | 446 | `InvalidBlock` | `header.number < Uint(1)` | no | yes |
| `fork.validate_header` | 450 | `InvalidBlock` | `header.excess_blob_gas != excess_blob_gas` | no | yes |
| `fork.validate_header` | 453 | `InvalidBlock` | `header.gas_used > header.gas_limit` | no | yes |
| `fork.validate_header` | 462 | `InvalidBlock` | `expected_base_fee_per_gas != header.base_fee_per_gas` | no | yes |
| `fork.validate_header` | 464 | `InvalidBlock` | `header.timestamp <= parent_header.timestamp` | no | yes |
| `fork.validate_header` | 466 | `InvalidBlock` | `header.number != parent_header.number + Uint(1)` | no | yes |
| `fork.validate_header` | 468 | `InvalidBlock` | `len(header.extra_data) > 32` | no | yes |
| `fork.validate_header` | 470 | `InvalidBlock` | `header.difficulty != 0` | no | yes |
| `fork.validate_header` | 472 | `InvalidBlock` | `header.nonce != b'\x00\x00\x00\x00\x00\x00\x00\x00'` | no | yes |
| `fork.validate_header` | 474 | `InvalidBlock` | `header.ommers_hash != EMPTY_OMMER_HASH` | no | yes |
| `fork.validate_header` | 478 | `InvalidBlock` | `header.parent_hash != block_parent_hash` | no | yes |
| `fork.check_transaction` | 570 | `InsufficientBalanceError` | `Uint(sender_account.balance) < max_gas_fee + Uint(tx.value)` | no | yes |
| `fork.check_transaction` | 575 | `InvalidSenderError` | `sender_account.code_hash != EMPTY_CODE_HASH and (not is_valid_delegation(sender_code))` | no | yes |
| `transactions.decode_transaction` | 571 | `InvalidBlock` | `len(tx) == 0` | no | yes |
| `transactions.decode_transaction` | 583 | `TransactionTypeError` | `not (192 <= tx[0] <= 254)` | no | yes |
| `transactions.validate_transaction` | 635 | `NonceOverflowError` | `U256(tx.nonce) >= U256(U64.MAX_VALUE)` | no | yes |
| `transactions.validate_transaction` | 638 | `InitCodeTooLargeError` | `tx.to == Bytes0(b'') and len(tx.data) > MAX_INIT_CODE_SIZE` | no | yes |
| `transactions.validate_transaction` | 641 | `TransactionGasLimitExceededError` | `tx.gas > GasCosts.TX_MAX_TOTAL_GAS_LIMIT` | yes | yes |
| `transactions.validate_transaction` | 645 | `PriorityFeeGreaterThanMaxFeeError` | `tx.max_fee_per_gas < tx.max_priority_fee_per_gas` | no | yes |
| `transactions.validate_transaction` | 652 | `NoBlobDataError` | `blob_count == 0` | no | yes |
| `transactions.validate_transaction` | 654 | `BlobCountExceededError` | `blob_count > BLOB_COUNT_LIMIT` | no | yes |
| `transactions.validate_transaction` | 659 | `InvalidBlobVersionedHashError` | `blob_versioned_hash[0:1] != VERSIONED_HASH_VERSION_KZG` | no | yes |
| `transactions.validate_transaction` | 665 | `TransactionTypeContractCreationError` | `not isinstance(tx.to, Address)` | no | yes |
| `transactions.validate_transaction` | 669 | `EmptyAuthorizationListError` | `not any(tx.authorizations)` | no | yes |
| `transactions.validate_transaction` | 674 | `InsufficientTransactionGasError` | `intrinsic_gas > tx.gas` | yes | yes |
| `transactions.validate_transaction` | 676 | `InsufficientTransactionGasError` | `intrinsic.calldata_floor > tx.gas` | yes | yes |
| `transactions.validate_transaction` | 678 | `InsufficientTransactionGasError` | `intrinsic.execution > GasCosts.TX_MAX_GAS_LIMIT` | yes | yes |
| `transactions.validate_transaction` | 682 | `InsufficientTransactionGasError` | `intrinsic.calldata_floor > GasCosts.TX_MAX_GAS_LIMIT` | yes | yes |
| `transactions.calculate_effective_gas_price` | 827 | `InsufficientMaxFeePerGasError` | `tx.max_fee_per_gas < base_fee_per_gas` | no | yes |
| `transactions.calculate_effective_gas_price` | 838 | `InvalidBlock` | `tx.gas_price < base_fee_per_gas` | no | yes |
| `transactions.check_nonce` | 857 | `NonceMismatchError` | `sender_nonce > Uint(tx.nonce)` | no | yes |
| `transactions.check_nonce` | 859 | `NonceMismatchError` | `sender_nonce < Uint(tx.nonce)` | no | yes |
| `transactions.chain_id` | 873 | `InvalidSignatureError` | `tx.v < U256(35)` | no | yes |
| `transactions.chain_id` | 877 | `InvalidSignatureError` | `tx_chain_id > U256(U64.MAX_VALUE)` | no | yes |
| `transactions.recover_sender` | 899 | `InvalidSignatureError` | `U256(0) >= r or r >= SECP256K1N` | yes | yes |
| `transactions.recover_sender` | 901 | `InvalidSignatureError` | `U256(0) >= s or s > SECP256K1N // U256(2)` | yes | yes |
| `transactions.recover_sender` | 921 | `InvalidSignatureError` | `tx.y_parity not in (U256(0), U256(1))` | no | yes |
| `transactions.recover_sender` | 927 | `InvalidSignatureError` | `tx.y_parity not in (U256(0), U256(1))` | no | yes |
| `transactions.recover_sender` | 933 | `InvalidSignatureError` | `tx.y_parity not in (U256(0), U256(1))` | no | yes |
| `transactions.recover_sender` | 939 | `InvalidSignatureError` | `tx.y_parity not in (U256(0), U256(1))` | no | yes |
| `vm.gas.check_gas` | 376 | `OutOfGasError` | `evm.gas_meter.gas_left < amount` | yes | yes |
| `vm.gas.charge_gas_from_meter` | 392 | `OutOfGasError` | `gas_meter.gas_left < amount` | yes | yes |
| `vm.gas.charge_state_gas_from_meter` | 436 | `OutOfGasError` | `not (Uint(gas_meter.state_gas_left) + Uint(gas_meter.gas_left) >= amount)` | yes | yes |
| `vm.gas.check_max_fee_per_blob_gas` | 1033 | `InsufficientMaxFeePerBlobGasError` | `Uint(max_fee_per_blob_gas) < blob_gas_price` | no | yes |
| `vm.gas.check_block_gas_capacity` | 1082 | `GasUsedExceedsLimitError` | `min(GasCosts.TX_MAX_GAS_LIMIT, tx_gas) > execution_gas_available` | no | yes |
| `vm.gas.check_block_gas_capacity` | 1085 | `GasUsedExceedsLimitError` | `tx_gas > state_gas_available` | no | yes |
| `vm.gas.check_block_gas_capacity` | 1088 | `BlobGasLimitExceededError` | `tx_blob_gas > blob_gas_available` | no | yes |

## CrossHair

`just test-spec-properties-crosshair` runs the suite with the `crosshair` profile (100 examples, the `hypothesis-crosshair` backend, the opt-in `crosshair` dependency group). It is not wired into CI.

On Bogota (83 tests) it took 15 min 20 s at 4 workers and found no counterexample. Probes, each false at one input that random draws miss, show what the solver reasons through in this spec. Each "yes" came within 15 examples; each "no" ran 200 without a hit.

| Kind of code | Probe | Found it |
|---|---|---|
| Python `int` | a quadratic in the input | yes |
| `Uint` arithmetic | `calculate_memory_gas_cost` | yes |
| `U256` wrapping | `wrapping_add` | yes |
| `Bytes` | equality with a constant | yes |
| Frozen dataclasses | `replace` on a `Header` | yes |
| RLP | `rlp.encode` of a `Uint` | yes |
| keccak256 | equality of two hashes | no |
| Input-dependent loop | `calculate_blob_gas_price` (`fake_exponential`) | no |

So it works on the leaf arithmetic and on the dataclasses the spec builds from it, and chokes where a hash or a loop sits between the input and the branch: keccak (parent hashes, signing hashes, code hashes, trie roots), the blob price's Taylor loop, and secp256k1 recovery, which runs in C. Properties that pass through those run concretely and gain nothing over random draws, at roughly 30 times the cost per example (Bogota: 224 s for 200 examples per test in one process under the `ci` profile, against 920 s on 4 workers for 100 under `crosshair`).
