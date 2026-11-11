# Mutation Testing

Mutation testing checks the tests rather than the spec. It makes one small edit to a spec function, such as `>` turned into `>=` or a guard removed, and runs the tests that claim to cover that function. If they still pass, the edit "survived", and either the tests miss a behavior or the edit cannot change behavior at all.

## Running It

```console
just mutate bal                         # the property tests that cover the BAL builder
just mutate bal --oracle fixtures       # the area's filled EEST fixtures instead
just mutate bal tx-admission --sample 40
just mutate --list                      # mutants per area
just mutate bal --rerun 3f2a9c01b7d4    # exactly these mutants again
```

`just mutate` mutates the spec package of the latest fork; pass `--fork` for another. Results go to `.just/mutate/<Fork>/results-<oracle>.jsonl`, and a rerun skips the mutants already there, so an interrupted run resumes. The command ends with a table per area and one line per survivor, naming the other forks whose copy of the function is the same code, which share the result.

Each worker imports a private copy of `src/` through `PYTHONPATH`, so the checkout is never edited and stays usable while a run is going. A sample with `--sample N` depends only on the area and `--seed`, so an area's sample is the same whatever other areas a run includes.

## Areas and Oracles

An area in `src/ethereum_spec_tools/mutate/areas.py` names the spec functions to mutate and the tests that cover them. Keep an area to the functions its tests claim to cover: a mutant elsewhere measures nothing.

| Oracle       | What runs for each mutant                                                                                                                                                    | Speed                    |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| `properties` | the area's modules under `tests_property/`, at the `ci` profile, `-x`                                                                                                        | seconds to a few minutes |
| `fixtures`   | the area's EEST tests, filled once from the unmutated spec, imported by the mutated spec through `tests/json_loader`, so a mutant that changes any filled result is killed | seconds                  |

## Operators

| Operator        | Edit                                                                                                    |
| --------------- | ------------------------------------------------------------------------------------------------------- |
| `compare`       | `<` and `<=`, `==` and `!=`, `in` and `not in`, ...                                                     |
| `binop`         | `+` and `-`, `*` and `//`, `<<` and `>>`, ...                                                           |
| `boolop`        | `and` and `or`                                                                                          |
| `drop-operand`  | one operand of an `and` or `or` removed                                                                 |
| `drop-not`      | `not x` becomes `x`                                                                                     |
| `constant`      | an integer one up or down, a boolean flipped                                                            |
| `drop-guard`    | an `if ...: raise` that never fires, or an `ensure(...)` removed                                        |
| `drop-call`     | a call made for its effect removed: a gas charge, a balance move, a block access list entry, ...       |
| `wrapping`      | `wrapping_add` and `wrapping_sub` swapped, or a wrapping method turned into the checked operator        |
| `integer-type`  | `U256(...)`, `Uint(...)` and `U64(...)` conversions swapped                                             |
| `gas-constant`  | a `GasCosts` or `StateGasCosts` member swapped for its neighbor in the class                            |
| `previous-fork` | a function replaced whole by the fork before's copy, where they differ: the fork's change lost          |

No mutant is made inside a docstring, an f-string or a type annotation, since those edits cannot change behavior.

## Reading Survivors

A survivor is a test gap only if the edit can change behavior. Common equivalent mutants:

- a comparison at a point where both sides give the same result, such as `after <= before` against `after < before` when equal sizes cost nothing either way;
- a guard that a check elsewhere makes redundant, such as a signature range that `secp256k1_recover` rejects on its own;
- a default that no reachable input uses, such as a field every header of the fork carries;
- a rewrite that writes the same value, such as keeping the higher of two equal nonces.

When a survivor is equivalent, record it in the area's `notes` with the reason, keyed by the function and the edit (`Mutant.construct`), so later runs report it apart even after the file's lines move. When it is not, it is a test to write: as a property in `tests_property/`, or as an EEST test when only a filled fixture can show it.
