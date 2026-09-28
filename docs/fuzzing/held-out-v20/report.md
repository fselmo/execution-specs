# Held-out differential baseline, generator v20

**Kill rate: 13 of 21 tested mutants (62%).** 8 survived, and 11 more crashed EELS itself, so they measure nothing.

## Setup

- **Mutants:** 32, frozen with `mutate --freeze-held-out` into `held_out_v20.json` in this directory: 8 per stratum across gas arithmetic (`vm/gas.py`), frame handling (`vm/interpreter.py`), call paths (`vm/instructions/system.py`) and the state tracker (`state_tracker.py`).
- **Runs:** each mutant through `fuzz diff` on seeds 0–299, generator v20, spec at `8cbd21987`.
- **Reference client:** geth master `920c07774c65` (stock t8n).
- **Clean baseline:** 300 of 300 compared and agreed, with 0 tool-rejected, 0 runner errors and 0 not compared. The opcode-count fix has removed the t8n refusals.
- **Where it ran:** a separate worktree with its own environment. A held-out run writes each mutant into the spec source it runs from, so running it in the live campaign's checkout would feed mutated spec to that campaign.

## Results

| stratum | killed | survived | spec crash | kill rate (tested) |
| --- | --- | --- | --- | --- |
| gas-arithmetic | 3 | 4 | 1 | 3/7 |
| frame-handling | 4 | 1 | 3 | 4/5 |
| call-paths | 3 | 3 | 2 | 3/6 |
| state-tracker | 3 | 0 | 5 | 3/3 |
| **all** | **13** | **8** | **11** | **13/21 (62%)** |

Every tested mutant was compared on all 300 seeds: none were refused, none had runner errors, none were uncompared. The per-mutant table is in `table.md`; `results.json` has every mutant with its outcome, and its summary or crash log.

**Spec crash** means the mutated spec raises inside EELS before any comparison happens: a `KeyError` on the beacon-roots address, an `OverflowError`, `TypeError`, `AssertionError` or a bare traceback (`crashes/NN.log`, rerun with full output). Any fill kills these trivially, so they belong in neither the numerator nor the denominator.

**Scoring problem.** `held_out_report` counts any non-zero exit as a kill. That would score all 11 crashes as kills and report 24/32 (75%). It should separate crashes, meaning a non-zero exit without a summary, from kills, meaning `diverged` > 0.

## Survivors: where the generator is blind

| # | where | mutation | what a killing case needs |
| --- | --- | --- | --- |
| 01 | gas.py | state-gas-affordable check `>=` → `>` | a charge equal to exactly the state gas plus execution gas left |
| 02 | gas.py | blob gas `PER_BLOB * n` → `//` | blob transactions (4844 is out of the generator's scope) |
| 04 | gas.py | blob schedule `MAX - TARGET` → `+` | blob transactions |
| 06 | gas.py | `block_gas_limit - block_state_gas_used` → `+` | a block near its limit, where the remaining-gas check binds |
| 09 | interpreter.py | `not account_deployable(...)` → `account_deployable(...)` | a CREATE onto an address that is not deployable: a collision, or existing code or nonce |
| 18 | system.py | CREATE cost `+ init_code_gas` → `-` | CREATE with initcode large enough for the initcode word cost to change the outcome |
| 19 | system.py | nonce cap `2**64 - 1` → `2**64 + 1` | an account at the maximum nonce (the generator's nonces start at 0, 1 or 3) |
| 20 | system.py | `gas_cost + account_write_gas` → `-` | a call whose account-write surcharge decides whether it succeeds |

Four of the eight, 02, 04, 19 and possibly 06, are outside the generator's reach by construction: no blobs, no maximum nonces, and no near-full blocks. The rest are exact-boundary cases, which the generator reaches only by chance: 01, 18 and 20 are gas amounts equal to a threshold, and 09 is a CREATE collision.

Weak kills, 3–5 hits in 300 (10, 11 and 13, all in frame handling), are paths the generator reaches rarely. They're worth targeting too.

## Reproducing

From a worktree of the spec (not the campaign's checkout):

```
uv run mutate --held-out held_out_v20.json --oracle differential \
  --fork Amsterdam --client <geth master evm> --diff-count 300 --workers 8
```

Use the per-mutant summaries rather than the stock report's totals, because of the scoring problem above.

## Files

- `held_out_v20.json`: the frozen set, 32 mutants anchored on construct.
- `results.json`: one row per mutant, with its outcome (`killed`, `survived` or `spec-crash`), its counts and a path to its evidence.
- `summaries/NN.json`: the `fuzz diff --summary-json` of each of the 21 tested mutants.
- `crashes/NN.log`: the full `fuzz diff` output of each of the 11 spec-crash mutants, traceback included. Run with `-j 8`, a crash aborts the pool before any divergence is printed. Mutant 26, run with a single worker on 3 seeds, printed a BAL-hash divergence on its second seed before crashing, so a crash does not mean the mutant was unreachable. It means the run produced no comparison to score.
