# Held-out v20 across generator versions

The frozen set, `held_out_v20.json`, unchanged, measured at each version that added a motif for one of its survivors. Every run covers seeds 0–299 against geth `1.17.6-unstable-aa1f2fcf` (glamsterdam-devnet-8), with per-seed scoring. The summaries are in `by-version/vNN/`.

## Totals

Mutants 20 and 23 are counted apart, as crashing wherever reached (see below). The kill rate is over the mutants tested.

| version | motif added | killed | survived | invalid | kill rate |
| --- | --- | --- | --- | --- | --- |
| v20 (rescored) | — | 19 | 8 | 4 | 19/27 |
| v21 | state charge equal to the gas left | 21 | 5 | 4 | 21/26 |
| v22 | SELFDESTRUCT funding a dead account | 20 | 6 | 4 | 20/26 |
| v23 | creation transactions onto occupied addresses | 22 | 4 | 4 | 22/26 |
| v24 | a block's state gas filled, then one more rejected | 22 | 4 | 4 | 22/26 |
| v25 | gas stored after every creation | 22 | 4 | 4 | 22/26 (85%) |

The v20 row counts 20 as a survivor, and 23 apart: nothing reached 20 until v22.

## The targeted survivors

Each cell is diverged seeds out of 300.

| # | target | v21 | v22 | v23 | v24 | v25 |
| --- | --- | --- | --- | --- | --- | --- |
| 01 | state charge equal to the gas left | 22 | 16 | 24 | 25 | 27 |
| 09 | creation onto code or a nonce | 0 | 0 | 39 | 49 | 44 |
| 06 | block state-gas capacity | 0 | 0 | 0 | 7 | 8 |
| 18 | CREATE initcode charge | 2 | 0 | 2 | 0 | 0 |
| 20 | SELFDESTRUCT surcharge | crashes on 1 | crashes on 11 | crashes on 18 | crashes on 15 | crashes on 16 |

Each of 01, 09 and 06 is killed from the version that added its motif onward. At v24, mutant 06 also crashed on 6 seeds: the measuring fill ran the case's rejected final block, which the mutant accepts. The measurement now stops at the measured block, and at v25 those seeds are tested.

## What is left

- **02, 04 and 19** need blobs or a maximum nonce, which are out of scope.
- **20 crashes wherever reached.** The mutant turns `gas_cost + account_write_gas` into a subtraction that goes below zero in a `Uint`. Every SELFDESTRUCT that pays the surcharge therefore raises `OverflowError`: 16 of 16 reached seeds at v25. The v22 motif reaches it, and a crash is not a kill. It joins 23 as a category of its own.
- **23 crashes wherever reached**, as before.
- **18 is not an observability gap after all.** At v25 its execution differs on 14 of 18 seeds, and the GAS stored after the creation should show that. It doesn't, because every frame that executes a CREATE in 300 seeds ends in an exceptional halt, which reverts the stored reading. Most of them run out of gas at the CREATE itself, because the palette's random size operands make it unaffordable. Killing 18 needs a CREATE whose frame completes: a helper that creates from a drawn small initcode size, stores GAS and stops. That is a motif, not a witness.
