# Held-out v20, rescored per seed

**Kill rate: 19 of 27 tested mutants (70%).** 8 survived. 4 are invalid: they crash EELS on every seed. One more, mutant 23, crashes wherever it is reached, so it is counted on a line of its own. The earlier 13/21 counted each spec-crash mutant as untested in full, because one crashing seed ended the run.

## What changed

`fuzz diff` now evaluates each seed on its own. An exception that escapes the reference's transition, or its measuring fill, crashes that seed only. A crashed seed compares nothing, and the mutant is scored on the seeds it did not crash on. The frozen set, `held_out_v20.json`, is unchanged.

The 21 mutants tested before keep their scores. None of them crashed on any seed. Mutant 10's one EELS error does not change its kill, which four other seeds' divergences decide.

## The 11 former spec crashes

These were rerun with the per-seed scoring on seeds 0–299, generator v20, at `a54f6d9c1e`. Their summaries are in `rescored/`.

The reference client differs from the original run. It was geth `1.17.6-unstable-aa1f2fcf` (glamsterdam-devnet-8) on a laptop, where the original run used geth master `920c07774c65` on the server. On the clean spec, this build agrees with EELS on 300 of 300 seeds, the same as the original baseline.

| # | stratum | compared | crashed | diverged | outcome |
| --- | --- | --- | --- | --- | --- |
| 03 | gas-arithmetic | 197 | 103 | 197 | killed, by rejection only |
| 08 | frame-handling | 0 | 300 | 0 | invalid |
| 12 | frame-handling | 64 | 236 | 64 | killed, by rejection only |
| 14 | frame-handling | 0 | 300 | 0 | invalid |
| 17 | call-paths | 291 | 9 | 85 | killed |
| 23 | call-paths | 286 | 14 | 0 | crashes wherever reached |
| 26 | state-tracker | 298 | 2 | 136 | killed |
| 27 | state-tracker | 0 | 300 | 0 | invalid |
| 28 | state-tracker | 242 | 58 | 14 | killed |
| 29 | state-tracker | 0 | 300 | 0 | invalid |
| 31 | state-tracker | 197 | 103 | 197 | killed, by rejection only |

**Killed, by rejection only** means that on every seed compared, the mutated spec rejected a block or transaction that geth accepted, and no field diverged. That is a verdict, not a crash: the spec reports the rejection through its transition's result. Any fill of a valid transaction kills these mutants. Without them the kill rate is 16/27.

Mutant 23 (`b"\x00" * extend_memory.expand_by` → `//`) crashes on each of the 14 seeds that reach it, and has no effect on the rest (`survivors.md`). It is not invalid, because it runs on the seeds that do not reach it. It is not a survivor either, because no case can kill it: a seed that reaches it crashes, and a crash is not a kill. It is kept out of the kill rate and out of the motif work.

## Totals

| stratum | killed | survived | crashes wherever reached | invalid | kill rate (tested) |
| --- | --- | --- | --- | --- | --- |
| gas-arithmetic | 4 | 4 | 0 | 0 | 4/8 |
| frame-handling | 5 | 1 | 0 | 2 | 5/6 |
| call-paths | 4 | 3 | 1 | 0 | 4/7 |
| state-tracker | 6 | 0 | 0 | 2 | 6/6 |
| **all** | **19** | **8** | **1** | **4** | **19/27 (70%)** |

## Reproducing

```
uv run mutate --held-out docs/fuzzing/held-out-v20/held_out_v20.json \
  --held-out-index 3 --held-out-index 8 ... --oracle differential \
  --fork Amsterdam --client <geth evm> --diff-count 300 --workers 8 \
  --held-out-summaries <dir>
```

## Update after v22

Mutant 20, a survivor here, crashes wherever it is reached. That became visible once v22 reached it: 16 of 16 reached seeds raised `OverflowError` at v25, because the mutated subtraction underflows an unsigned `Uint`. It is now counted beside 23. See `progress.md`.
