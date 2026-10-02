# Held-out v26: baseline and survivors

**At generator v26, 48 of 83 tested mutants are killed (58%).** 12 are invalid: they crash EELS on every seed. 7 more crash wherever they are reached. Of the 35 survivors, 6 are out of the t8n lane's reach altogether, 27 need a case shape that reaches them (a motif), and 2 need their difference made visible.

## By version and half

The set is split into a tuning half and an evaluation half (`split.json`, seed 26, 51 each, every stratum split evenly), frozen before any new motif. Motifs may be aimed only at tuning-half survivors, so the evaluation half is the measure of what a version buys on mutants nobody tuned for. **The evaluation half is untouchable:** no motif, witness or observability change may be motivated by an evaluation-half mutant, 92 and 30 included, and no motif's axis may be widened to cover one. Its survivors are reported, never targeted. Mutants that crash wherever reached (`crashes_wherever_reached.json`) and invalid ones are left out of both rates.

| version | tuning killed | tuning self-check kills | evaluation killed | evaluation self-check kills |
| --- | --- | --- | --- | --- |
| v20 generator | 21/41 (51%) | — | 24/40 (60%) | — |
| v26 (baseline) | 22/41 (54%) | — | 26/41 (63%) | — |
| v27 (maximum nonce) | 20/41 (49%) | — | 26/41 (63%) | — |
| v28 (requests) | 23/41 (56%) | — | 29/41 (71%) | — |
| v30 (arithmetic, largest initcode, delegated dispatch) | 26/41 (63%) | — | 28/41 (68%) | — |
| v31 with the EELS import leg | 27/41 (66%) | +3 (71, 77, 78) | 29/41 (71%) | +2 (72, 76) |

"Killed" is a differential kill. A self-check kill is EELS refusing, on its own block import, a block it filled as valid; it is scored in its own column, so a version's differential rate stays comparable with the rows above. The two columns are disjoint.

**Generalization.** The v20 generator on this set kills 45 of 102, where v26 kills 48. Of the mutants it was not built for, v21–v26 bought four kills (25, 29, 74 and 91) and lost one (30). On the evaluation half the gain is 24 of 40 to 26 of 41. The v20 generator has one more invalid mutant in the evaluation half. The motifs were aimed at v20's survivors, and what carried over to other mutants is small.

v28 is the first version to move the evaluation half. The requests motif was aimed at tuning survivors 49, 53, 58 and 59, and killed 49, 58 and 59. It also killed three evaluation mutants in the same code: 48 (the deposit-request branch), and 56 and 57 (the deposit's withdrawal-credentials and signature slices). 53 turns out to crash wherever it is reached: its subtraction of two byte strings raises `TypeError` on each of the 8 seeds that queue a builder exit. It moves to that category, and every row above is scored with it there.

v30, which includes v29, kills its three tuning targets: 60 on 21 seeds, 80 on 15 and 99 on 2. It moves nothing in the evaluation half, and loses 74 there, which v28 killed on 2 seeds. v20's set holds at 23 kills with none lost. Motif work pauses here: from v21 to v30, the evaluation half gained only where a motif's own code covered it, in v28's deposits and requests.

**The import leg** (v31) reaches the six block-import mutants the t8n lane never evaluates. It kills the three tuning ones, 71, 77 and 78, on all 300 seeds, and two of the three evaluation ones: 72 on all 300 and 76 on 294. 73 survives, as expected: it loosens `header.timestamp <= parent_header.timestamp` to `<`, which differs only for a block whose timestamp equals its parent's, and no generated block has one. v32's timestamp negative builds exactly that block, and with 73 applied its import witness fails, refused at the state root instead of the timestamp check; that is the engine campaign's witness, not a held-out measurement. Differentially, v31 gains 23 and 74 over v30, each killed on one or two seeds before, and loses nothing.

v27 loses two tuning kills, 23 and 101. Each was killed on 1 of 300 seeds at v26, which is sampling noise, not a regression.

**On v20's rates.** Every motif from v21 to v26 was built for a survivor in v20's set, so v20's rates rose from 19/27 to 23/25 on the very mutants the work was tuned on. They measure progress on a training set. v20's set is a regression check from here on, and its kill rate is not quoted as progress; at v27 it holds at 23 kills with no losses. The generalization check, the v20 generator on this set, is what says how much of that work carries over to mutants it was not built for.

## Setup

- **Set:** `held_out_v26.json`, 102 mutants frozen at v26 before any measurement, across 13 strata (see `AMSTERDAM_STRATA`). It uses v20's anchoring: a mutant is its construct, and a construct that occurs twice in a module is not drawn for a function-limited stratum.
- **Runs:** seeds 0–299, generator v26, per-seed scoring, against geth `1.17.6-unstable-aa1f2fcf` (glamsterdam-devnet-8).
- **Survivor diagnostic:** `mutate --held-out ... --liveness` on the 42 mutants that neither diverged nor crashed on every seed.

## Per stratum

Ordered by survivors a generator change could fix.

| stratum | killed | needs a motif | needs observability | block import only | crashes wherever reached | invalid |
| --- | --- | --- | --- | --- | --- | --- |
| blocks-withdrawals | 1 | 1 | 0 | 6 | 0 | 2 |
| system-calls | 2 | 5 | 0 | 0 | 0 | 1 |
| state-gas | 8 | 3 | 1 | 0 | 2 | 0 |
| requests | 0 | 4 | 0 | 0 | 0 | 0 |
| delegation | 6 | 3 | 0 | 0 | 1 | 0 |
| bal-builder | 7 | 2 | 0 | 0 | 0 | 5 |
| transaction | 5 | 2 | 0 | 0 | 0 | 1 |
| evm-environment | 0 | 2 | 0 | 0 | 2 | 0 |
| evm-arithmetic | 1 | 2 | 0 | 0 | 1 | 0 |
| bal-tracker | 9 | 1 | 0 | 0 | 0 | 2 |
| evm-system-ops | 4 | 1 | 0 | 0 | 1 | 0 |
| evm-interpreter | 2 | 0 | 1 | 0 | 0 | 1 |
| evm-gas | 3 | 1 | 0 | 0 | 0 | 0 |
| **all** | **48** | **27** | **2** | **6** | **7** | **12** |

## Tuning survivors that no motif can kill

- **59** is reachable after all, and v28 kills it (7 of 300 seeds). It was recorded here as a layout check a canonical deposit contract never trips, which was wrong. 59 mutates the start of the slice that extracts a deposit's signature, `data[signature_offset + 32 : ...]`, which every canonical deposit runs, so a mis-sliced signature changes the requests hash. The first break-it-once ran it against a witness that checked only that the hash was not empty; against the exact hash it fails the deposit case alone.
- **63, the authorization's `r` range check**, is equivalent. `secp256k1_recover` rejects every `r` the check does (zero, the curve order and above) with the same `InvalidSignatureError`, so no case can tell the mutant apart.
- **70, the base fee's `parent_gas_used > parent_gas_target`**, is equivalent. `calculate_base_fee_per_gas` handles equality in the branch before it and returns, so the mutated `>=` only ever sees unequal values, where it agrees with `>`.
- **01, the BAL item limit's `>`**, is unreachable by construction. The limit is `block_gas_limit // 2000` items, and every way to add an item costs more execution gas than 2000: a cold storage read 2100, a cold account access 2600, an authorization over 5,800. The only items that cost no gas are a fixed handful: the coinbase, the system contracts, and the consensus layer's 16 withdrawals at most. So at any gas limit a block holds at most about `block_gas_limit // 2100` items plus a few dozen, below the limit. The check is a backstop that gas already enforces.

## Survivors, ranked by stratum

**Requests and system calls (9, all unreached).** No generated case produces a request, so the request paths never run:
- 48, 49, 51 and 53 in `process_general_purpose_requests`: deposit, withdrawal-request, consolidation and builder-exit request data.
- 56–59, all of `requests.py`'s deposit parsing.

Killing them needs transactions that queue EIP-7002 withdrawal requests and EIP-7251 consolidations with their system contracts, plus deposit-contract logs. This is the largest unreached surface in the set. 55, the system call's state-gas allowance (`STORAGE_SET * SYSTEM_MAX_SSTORES`), changes its value on every seed without changing execution: the allowance never binds.

**Blocks and withdrawals (7).** Six are header or block checks in `validate_header` and `execute_block`: block number, timestamp, gas used against the limit, RLP size, receipt root and requests hash (71, 72, 73, 76, 77, 78). The t8n lane never runs them, because a transition tool builds a block rather than importing one. Only a block-import lane reaches them, so they are the engine lane's to kill, not a motif's. The seventh, 70, needs a parent block whose gas used is exactly its target, the base-fee boundary.

**State gas (4 survivors, 2 crash).**
- 35 is the reservoir branch's `>=`: a state charge exactly equal to the reservoir. That is v21's motif moved into the reservoir.
- 32 is `check_block_gas_capacity`'s execution-gas side: v24's near-full block, filled with execution gas instead of state gas.
- 39 is `restore_state_gas_to_entry`: its value differs on 5 seeds and its execution on none.
- 30, `repay_state_gas_spill`'s repayment sign, changes the execution on 27 seeds without a compared difference, and crashes on 23: it needs observability.
- 27 and 37, also in `repay_state_gas_spill`, crash wherever they change anything.

**Delegation (3).**
- 63 and 66 are the authority signature's `r` and `s` range checks: no generated authorization carries an out-of-range signature.
- 60, a delegated address already in the accessed set, is never evaluated.
- 65 crashes wherever reached.

**BAL builder (2).**
- 01 is the BAL gas limit's `>`: a block whose item count equals exactly `block_gas_limit // BLOCK_ACCESS_LIST_ITEM`.
- 11 is `add_nonce_change` meeting an existing change: one account's nonce changing twice in one transaction, such as a creator making two CREATEs.

**Transaction (2).** 44, `check_transaction`'s `is_create or tx.value > 0`, and 46, `tx_chain_id is not None`, change their value on every seed without changing execution.

**Classic EVM (6 survivors, 4 crash).**
- 80: an initcode of exactly `MAX_INIT_CODE_SIZE`.
- 87 and 88: RETURNDATACOPY, reached on 4 seeds.
- 96: `calculate_message_call_gas`, value only.
- 99: MULMOD, never evaluated.
- 100: SIGNEXTEND at byte 31.
- 81, 86, 89 and 98 crash wherever reached.

**Observability (2).** 92, the top frame's `execution_gas_grant - gas_left`, changes the traced execution on 249 of 300 seeds and is never killed. That is the largest unobserved difference in the set, and the first to look at. 30 is above.

## Crashes wherever reached

27, 37, 53 (found at v28), 65, 81, 86, 89 and 98. 37 changes the execution only on the seeds where it crashes (159 of the 226 that reach it). Everywhere else its value differs and the execution does not.

## Archive

The per-version summaries and the liveness output left git at `ba860b5c07`. The server keeps them under `campaigns/reports/held-out-archive/`, and `git archive ba860b5c07 docs/fuzzing/held-out-v26` rebuilds them.
