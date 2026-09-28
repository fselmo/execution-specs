# Held-out v20 survivors: what each one needs

Of the 8 survivors, 4 need a case shape that reaches them (a motif), 1 needs its difference made visible, and 3 are out of scope. Mutant 23 is on a line of its own: it crashes wherever it is reached, so it is neither a survivor nor a target for a motif.

## Method

`mutate --held-out ... --liveness` measures each survivor on seeds 0–299, generator v20, using EELS alone. `liveness.txt` has the raw output. It works at two levels:

1. **Value.** The mutant's site is rewritten to evaluate both the original and the mutated expression and to return the original. The count is how often the two values differ.
2. **Execution.** On the seeds where the value differed, the real mutant runs under a full EIP-3155 trace. Its trace, every block result and the post-state are compared with the unmutated spec's.

The second level matters because a value can differ without the execution changing. `2**64 - 1` differs from `2**64 + 1` on every evaluation, yet no generated nonce comes near either value.

## Split

| # | site | value differs | execution differs | needs |
| --- | --- | --- | --- | --- |
| 01 | `charge_state_gas_from_meter`: `state_gas_left + gas_left >= amount` → `>` | 0 of 9,205 evaluations (290 seeds) | — | motif: state-gas charge equal to exactly the gas left |
| 02 | `calculate_total_blob_gas`: `PER_BLOB * n` → `//` | never evaluated | — | blobs (out of scope) |
| 04 | `calculate_excess_blob_gas`: `MAX - TARGET` → `+` | never evaluated | — | blobs (out of scope) |
| 06 | `check_block_gas_capacity`: `limit - state_gas_used` → `+` | 380 of 1,468 (162 seeds) | 0 of 162 seeds | motif: near-full block where the state-gas check binds |
| 09 | `create_evm`: `not account_deployable(...)` → `account_deployable(...)` | never evaluated | — | motif: CREATE collision onto code or a nonce |
| 18 | `create`: `+ init_code_gas` → `-` | 103 of 110 (22 seeds) | 12 of 22 seeds | **observability**: the charge changes the execution, and nothing compared shows it |
| 19 | `generic_create`: nonce cap `2**64 - 1` → `2**64 + 1` | 1,898 of 1,898 (101 seeds) | 0 of 101 seeds | maximum nonces (out of scope) |
| 20 | `selfdestruct`: `gas_cost + account_write_gas` → `-` | 0 of 665 (78 seeds) | — | motif: SELFDESTRUCT that pays the account-write surcharge (dead beneficiary, nonzero balance) |
| 23 | `create`: `b"\x00" * expand_by` → `//` | 91 of 91 (14 seeds) | crashes on all 14 | its own category, crashes wherever reached: no case can kill it, and it stays out of the motif work |

## Corrections to the first report

- **20 is SELFDESTRUCT, not a call.** The surcharge is non-zero only when the beneficiary is dead and the frame's balance is not zero. None of the 78 seeds that reach the site met that condition.
- **18 is reached.** A motif alone will not kill it. On 12 seeds the smaller charge changes the traced execution, and still no compared field differs. That fits a creating frame that ends by consuming all its gas. The fix is a witness that survives the frame, such as a `GAS` reading stored after the `CREATE` returns.
- **06 is reached, but its decision never flips.** The value is computed in every block. The comparison it feeds decides nothing unless the block is close to its state-gas limit.
