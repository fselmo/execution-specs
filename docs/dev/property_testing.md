# Property Testing

The tests under `tests/` check that a client reproduces a fixed, hand-written result. The property suite in `tests_property/` checks the spec itself: it uses [Hypothesis](https://hypothesis.readthedocs.io/) to generate many inputs for a spec function and asserts a rule that must hold for all of them.

The suite runs as plain pytest and produces no fixtures, so `fill` never collects it.

## Running the Suite

```console
just test-spec-properties
just test-spec-properties --hypothesis-profile=nightly
just test-spec-properties tests_property/test_block_access_list.py
```

| Profile     | Examples per property | Randomized |
| ----------- | --------------------- | ---------- |
| `ci`        | 200 (default)         | no         |
| `dev`       | 200                   | yes        |
| `nightly`   | 5000                  | yes        |
| `crosshair` | 100                   | solver     |

The `ci` profile is derandomized, so a failure reproduces on every run and Hypothesis prints a `@reproduce_failure` blob for it. Once a failure is fixed, keep its input as an `@example(...)` on the test so it stays covered.

The `crosshair` profile hands input generation to the [CrossHair](https://github.com/pschanely/hypothesis-crosshair) solver, which looks for inputs that take each branch rather than drawing them at random. It needs the opt-in `crosshair` dependency group and is meant for a nightly run, not as a CI gate:

```console
just test-spec-properties-crosshair -k Bogota
```

## Forks

Every test that uses the `fork` fixture runs once per fork of the testing framework (`execution_testing.forks`) that has a spec package, so a new fork is tested without edits. The spec module fixtures (`gas`, `transactions`, `blocks`, `tracker`, `bal`, ...) depend on `fork` and load that fork's package. Test ids carry the fork name, so `-k Osaka` runs one fork. The only forks left out are blob-parameter-only forks not yet scheduled, whose framework schedule is for testing only; `test_forks.py` fails if any other spec package goes untested.

A test that needs a feature states it with `requires` from `tests_property/forks.py`, asking the framework rather than naming forks. A condition that no fork meets fails collection:

```python
@requires(lambda fork: fork.header_bal_hash_required())
```

Forks are full copies of each other, so spec names and signatures drift between them. `execution_verifier.properties.spec_api` builds spec objects and calls spec functions the same way on every fork, and converts the framework's `Transaction` into the spec's class for that fork. A property that would need a large bridge for old forks gates on a feature instead.

The strategies in `execution_verifier.properties.strategies` weight every number toward the values where the protocol changes its answer: zero, one, word boundaries and type maxima.

## Writing a Property

A property's expected result must come from outside the code under test. In order of preference:

- the framework's calculator for the same fork, such as `fork.memory_expansion_gas_calculator()` or `fork.transaction_intrinsic_cost_calculator()`, compared with the spec function on random inputs; the framework's fork definitions are maintained apart from `src/` and import nothing from it;
- the framework's own model of an object, such as a `Transaction` whose `rlp()`, signing hash and sender the spec must reproduce;
- a protocol value from a `fork.*()` accessor; a value no accessor provides is a literal with its EIP or the Yellow Paper named beside it;
- a small reference model written from the EIP, such as the block access list model in `test_block_access_list.py`;
- a relation between two runs, such as the same result for inputs in any order, or a refund undoing a charge.

Copying the spec's formula into the test only proves the spec agrees with itself, so such tests do not belong here.

A rule about a limit is checked on both sides: the last input that passes and the first that fails.

## Aiming at a Boundary

A property over a function that rejects input should reach each of its rejections. Where the boundary depends on several drawn values, such as a balance against a transaction's maximum cost, steer the search toward it with `aim_at`, which wraps Hypothesis's [`target()`](https://hypothesis.readthedocs.io/en/latest/reference/api.html#hypothesis.target):

```python
aim_at(block.sender_balance, MAX_U256, "minimum balance near 2**256")
```

Hypothesis keeps the examples that land closest to the edge and mutates them further, so more of the budget goes to both sides of it. Aim at the edge of a rule (a cap, a fee, a step) and at the top of 64-bit and 256-bit fields, where an implementation that stores the value in a fixed-width integer could overflow.
