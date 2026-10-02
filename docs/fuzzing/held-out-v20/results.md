# Held-out v20

**At v26, 23 of 26 tested mutants are killed (88%).** 4 are invalid: they crash EELS on every seed. 20 and 23 crash wherever they are reached, so no case can kill them and they are counted apart; v27 found the same of 19, a survivor in the table below (`crashes_wherever_reached.json`). Every motif from v21 to v26 was built for a survivor in this set, so these rates measure progress on a training set; from v27 on the set is a regression check, and `held-out-v26/` measures what carries over.

## Setup

- **Set:** `held_out_v20.json`, 32 mutants frozen with `mutate --freeze-held-out`, 8 per stratum across gas arithmetic (`vm/gas.py`), frame handling (`vm/interpreter.py`), call paths (`vm/instructions/system.py`) and the state tracker (`state_tracker.py`).
- **Runs:** seeds 0–299 through `fuzz diff`, scored per seed: a seed whose reference raises compares nothing, and the mutant is scored on the rest. Reference: geth `1.17.6-unstable-aa1f2fcf` (glamsterdam-devnet-8), which agrees with EELS on 300 of 300 seeds on the clean spec.
- **Where:** a worktree of its own. A held-out run writes each mutant into the spec source it runs from.

## By version

| version | motif added | killed | survived | invalid | kill rate |
| --- | --- | --- | --- | --- | --- |
| v20 | — | 19 | 8 | 4 | 19/27 (70%) |
| v21 | state charge equal to the gas left | 21 | 5 | 4 | 21/26 |
| v22 | SELFDESTRUCT funding a dead account | 20 | 6 | 4 | 20/26 |
| v23 | creation transactions onto occupied addresses | 22 | 4 | 4 | 22/26 |
| v24 | a block's state gas filled, then one more rejected | 22 | 4 | 4 | 22/26 |
| v25 | gas stored after every creation | 22 | 4 | 4 | 22/26 |
| v26 | creations that succeed | 23 | 3 | 4 | 23/26 (88%) |

The first run, before per-seed scoring, reported 13 of 21: one crashing seed ended a mutant's run, so 11 mutants went untested. 03, 12 and 31 are killed by rejection only: the mutated spec rejects a block geth accepts, and no field diverges.

## What is left

- **02 and 04** need blobs, which are out of the generator's scope.
- **19** (the nonce cap `2**64 - 1` → `+ 1`) differs only at the highest nonce, where it raises `OverflowError` (v27).
- **20** (`gas_cost + account_write_gas` → `-` in SELFDESTRUCT) underflows a `Uint` on every surcharge paid, from v22, whose motif first reached it.
- **23** (`b"\x00" * expand_by` → `//` in CREATE) raises `TypeError` wherever CREATE extends memory.

## Reproducing

```
uv run mutate --held-out docs/fuzzing/held-out-v20/held_out_v20.json \
  --oracle differential --fork Amsterdam --client <geth evm> \
  --diff-count 300 --workers 8 --held-out-summaries <dir>
```

## Archive

The per-version summaries, crash logs, the per-mutant table, the liveness output and the earlier reports left git at `ba860b5c07`. The server keeps them under `campaigns/reports/held-out-archive/`, and `git archive ba860b5c07 docs/fuzzing/held-out-v20` rebuilds them.
