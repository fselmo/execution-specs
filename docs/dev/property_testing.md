# Property Testing

The tests under `tests/` check that a client reproduces a fixed, hand-written result. The property suite in `tests_property/` checks the spec itself: it uses [Hypothesis](https://hypothesis.readthedocs.io/) to generate many inputs for a spec function and asserts a rule that must hold for all of them.

The suite runs as plain pytest and produces no fixtures, so `fill` never collects it.

## Running the Suite

```console
just test-spec-properties
just test-spec-properties --hypothesis-profile=nightly
just test-spec-properties tests_property/test_eip7928_bal.py
```

| Profile   | Examples per property | Randomized |
| --------- | --------------------- | ---------- |
| `ci`      | 200 (default)         | no         |
| `dev`     | 200                   | yes        |
| `nightly` | 5000                  | yes        |

The `ci` profile is derandomized, so a failure reproduces on every run and Hypothesis prints a `@reproduce_failure` blob for it. Once a failure is fixed, keep its input as an `@example(...)` on the test so it stays covered.

## Forks

Each test runs on the latest fork and its parent, both taken from the spec's fork list; blob-parameter-only forks are passed over. A module that tests a feature added by a later EIP parametrizes `fork_name` with `forks_from("<fork>")` from `tests_property/forks.py`, so it runs on every tested fork from the one that introduced the feature. A tested fork in that range that lacks the feature fails the test rather than skipping it, and a feature with no tested fork fails collection. A rule that only one past fork follows names that fork with `past_fork("<fork>")`, so it keeps running after newer forks land.

## Writing a Property

A property's expected result must come from outside the code under test. Good sources are:

- a value or rule stated in the EIP or the Yellow Paper, such as a cap of `2**24` gas;
- a small reference model written from the EIP, such as the block access list model in `test_eip7928_bal.py`;
- a relation between two runs, such as the same result for inputs in any order, or a refund undoing a charge;
- a running total kept by the test alongside the code it checks.

Copying the spec's formula into the test only proves the spec agrees with itself, so such tests do not belong here.

A rule about a limit is checked on both sides: the last input that passes and the first that fails.

Shared strategies and builders live in `tests_property/strategies/`:

| Module         | Contents                                                       |
| -------------- | -------------------------------------------------------------- |
| `base.py`      | boundary-weighted integers, addresses, byte strings, trie keys |
| `builders.py`  | a builder for every transaction type a fork defines            |
| `gas_meter.py` | helpers for driving an EIP-8037 gas meter directly             |
