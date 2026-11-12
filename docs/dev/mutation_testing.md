# Mutation Testing

Mutation testing checks the tests rather than the spec. It makes one small edit to a spec function, such as `>` turned into `>=` or a guard removed, and runs the tests that claim to cover that function. If they still pass, the edit "survived", and either the tests miss a behavior or the edit cannot change behavior at all. Line coverage says a test ran the code; a killed mutant says a test would notice that code being wrong.

## Running It

```console
just mutate bal                         # the property tests that cover the BAL builder
just mutate bal --oracle fixtures       # the area's filled EEST fixtures instead
just mutate bal tx-admission --sample 40
just mutate --list                      # mutants per area
just mutate bal --rerun 3f2a9c01b7d4    # exactly these mutants again
```

`just mutate` mutates the spec package of the latest fork; pass `--fork` for another. Results go to `.just/mutate/<Fork>/results-<oracle>.jsonl`, and a rerun skips the mutants already there, so an interrupted run resumes; results from another state of the checkout are set aside, not reused.

Before any mutant runs, each area's tests run once on the unmutated spec, under coverage. They must pass, so a failing test or a selection that matches nothing stops the run instead of counting every mutant as killed. A mutant on a line those tests never executed is reported as not reached without being run. A mutant is killed only when tests ran and failed. One that fails on a `TypeError`, `NameError` or `AttributeError` is reported as crashed and kept out of the killed count: the edit broke the code's shape, so the first test to run it fails whatever it asserts. One that exceeds ten times the baseline's time is reported as timed out, which is usually a loop that no longer ends.

The command ends with a table per area and one line per survivor, naming the other forks whose copy of the function is the same code, which share the result.

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
| `drop-guard`    | an `if ...: raise` that never fires                                                                     |
| `drop-call`     | a call made for its effect removed: a gas charge, a balance move, a block access list entry, ...       |
| `drop-update`   | an in-place update removed, such as `evm.gas_left -= amount`                                            |
| `skip-loop`     | a `for` loop over nothing, or a `while` that never runs                                                 |
| `wrapping`      | `wrapping_add` and `wrapping_sub` swapped, or a wrapping method turned into the checked operator        |
| `gas-constant`  | a `GasCosts` or `StateGasCosts` member swapped for its neighbor in the class                            |
| `previous-fork` | a function replaced whole by the fork before's copy, where they differ: the fork's change lost          |

No mutant is made inside a docstring, an f-string or a type annotation, since those edits cannot change behavior. An operator expression spliced into a larger one is parenthesized, so the edit is the one its operator names.

## Reading Survivors

The summary lists two kinds of gap apart. A mutant that never ran needs a test that reaches the code. A mutant that ran and went unnoticed needs an assertion: the tests execute the line and check nothing it decides.

A survivor is a test gap only if the edit can change behavior. Common equivalent mutants:

- a comparison at a point where both sides give the same result, such as `after <= before` against `after < before` when equal sizes cost nothing either way;
- a guard that a check elsewhere makes redundant, such as a signature range that `secp256k1_recover` rejects on its own;
- a default that no reachable input uses, such as a field every header of the fork carries;
- a rewrite that writes the same value, such as keeping the higher of two equal nonces.

When a survivor is equivalent, record it in the area's `notes` with the reason, keyed by the function and the edit (`Mutant.construct`), so later runs report it apart even after the file's lines move. A note should say why no input can tell the two apart; "unlikely" is a gap, not an equivalence. When it is not, it is a test to write: as a property in `tests_property/`, or as an EEST test when only a filled fixture can show it.
