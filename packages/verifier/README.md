# The `ethereum-execution-verifier` Package

Verification tooling beside the [Ethereum Execution Layer Specifications (EELS)](https://github.com/ethereum/execution-specs). The spec under `src/ethereum` stays the readable, normative Python it is today: nothing here edits, annotates or instruments it. Each tool asks one question about the spec and uses the testing framework (`execution_testing`) as its independent reference.

The package provides:

- `execution_verifier.properties`: the library behind the property suite in `tests_property/`: Hypothesis strategies weighted toward the values where the protocol changes its answer, `aim_at` to steer a search toward a rule's boundary, and `spec_api`, which builds spec objects and calls spec functions the same way on every fork.

The suite itself, and how to write a property, is described in [`docs/dev/property_testing.md`](../../docs/dev/property_testing.md).
