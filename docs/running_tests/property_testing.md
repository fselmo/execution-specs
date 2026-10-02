# Property Testing

The conformance suite under `tests/` asks one question: does a client reproduce
a frozen, hand-authored result? The tools on this page ask whether the spec
itself obeys laws that must hold for *every* input and every block.

One rule governs them: **a property's assertion comes from outside the code it
tests.** Nothing here authors an expected post-state. Every oracle is a stated
law, another fork, or the EIP prose.

## Why opt-in flags and separate commands

- **Fixtures are a shared artifact.** Every client team consumes `fill`
  output, so nothing here may change a fixture or fail a fill by default.
  `--invariant-checks` is off by default and warn-only: violations become
  warnings plus an `invariant_violations` entry in the fixture's `_info`
  metadata; the fixture bytes are identical either way.
- **Property tests are not fixtures.** `fill` collects `tests/`, so Hypothesis
  tests live in `tests_property/` and run as plain pytest via
  `just test-spec-properties`.

## The layers

| Layer          | Command                     | Oracle                   | Finds                              |
| -------------- | --------------------------- | ------------------------ | ---------------------------------- |
| Property tests | `just test-spec-properties` | EIP / Yellow Paper prose | a component violating a stated law |
| Invariants     | `fill --invariant-checks`   | chain laws               | spec or framework bugs on any test |
| Manifest       | `uv run eip-manifest`       | —                        | what a fork changed, per EIP       |

## Property tests (`tests_property/`)

Plain pytest with Hypothesis. Every module is parametrized over
`PROPERTY_TEST_FORKS` (`osaka`, `amsterdam`) through the `fork_name` fixture and
imports the fork's modules by name; where calling conventions differ between
forks, the test carries a small explicit adapter.

```console
just test-spec-properties
just test-spec-properties --hypothesis-profile=nightly
```

| Profile   | Behaviour                                                          |
| --------- | ------------------------------------------------------------------ |
| `ci`      | default; derandomized so runs reproduce, 200 examples per property |
| `dev`     | randomized exploration for local runs                              |
| `nightly` | 5000 examples, randomized                                          |

A found regression is pinned as an explicit `@example(...)` on the failing test.

**Grounding rule.** A property's assertion must come from outside the code it
tests: EIP prose, the Yellow Paper, or an independent reference model.
Transcribing the EELS formula into a test is circular and proves nothing. Each
property's docstring records its grounding.

| Theme                 | Modules                                                                                            |
| --------------------- | -------------------------------------------------------------------------------------------------- |
| Spec components       | `test_rlp`, `test_trie`, `test_numeric`, `test_gas`, `test_intrinsic_cost`, `test_signatures`      |
| Stateful              | `test_state_machine` — `RuleBasedStateMachine` driving the state tracker against a reference model |
| EIP-mined (Amsterdam) | `test_eip7825`, `test_eip7928_bal`, `test_eip8037_state_gas`, `test_frame_gas_lifecycle`           |
| Manifest-driven       | `test_archetype_header_field`, `test_manifest_covariant` — one body, every fork transition         |

Shared Hypothesis strategies (addresses, byte data, sized integers) live in
`tests_property/strategies/`.

## `fill --invariant-checks`

Checks every filled block against laws that hold regardless of what the test
exercises, using the transition tool's own output:

- **Ether conservation** — total ether changes only by issuance (withdrawals,
  pre-merge rewards) minus protocol burns (base fee, blob fee).
- **Gas accounting** — block gas used ≤ gas limit; receipt cumulative gas is
  strictly increasing and sums to the block total.
- **Nonce monotonicity** — nonces never decrease; each sender's nonce advances
  by at least its accepted transactions.

Violations are emitted as `InvariantViolationWarning` and written to the
fixture's `_info` metadata as `invariant_violations`. Two flows are known to be
unmodeled and will trigger legitimately: `SELFDESTRUCT` with the destroyed
account as beneficiary (the balance burns), and a same-block destroy plus
re-credit (the nonce resets to 0). Modeling them is the precondition for making
the checker default-on.

## EIP change manifest (`uv run eip-manifest`)

```console
uv run eip-manifest --from Osaka --to Amsterdam
```

A fork object is already a machine-readable description of the protocol: the
`BaseFork` predicate surface, the `GasCosts` dataclass, opcode / precompile /
system-contract sets, and the calculator methods each EIP mixin overrides.
Diffing two adjacent forks yields, by construction, what the newer fork
changed, classified by kind (`GAS_CONSTANT`, `PRECOMPILE_ADDED`,
`FEATURE_ENABLED`, `FORMULA_CHANGED`, `BOUND_ADDED`, …) and attributed to the
EIP mixin that introduced it.

The manifest is a **targeting system, not an oracle** — it says where to look,
never what the answer is. Its consumers:

- `with_each_change(kind)` (`eip_properties/covariant.py`) — parametrize one
  property body over every matching change across every adjacent fork pair.
  A new fork is covered the moment it exists.
- `interaction_pairs()` — EIPs that override the *same* formula method compose
  by construction; the composed behaviour is a surface neither EIP's prose
  necessarily determines.
- `added_precompiles()` (`eip_properties/targeting.py`) — the precompiles a
  fork introduced, as addresses.

Known limits: when several EIPs co-override a value, attribution is a candidate
*set*; some fork-level scalars are unattributed.

## Mining properties with an agent (`/mine-properties`)

The `.claude/commands/mine-properties.md` skill runs the loop the layers above
were built to support: analyze an EIP (via the manifest) or a module, propose
properties grounded in prose, write them as Hypothesis tests, measure them with
`mutate --oracle properties` (from eels-fuzz, run in this checkout), and triage each into one of three tracks —
spec defect, coverage gap, or *spec ambiguity* (the prose does not determine
the behaviour). Ambiguities are recorded in
[`spec_ambiguity_findings.md`](../dev/spec_ambiguity_findings.md) with EELS's
current choice cited, and are never promoted to normative.

## Where things live

| Path                                                                        | Contents                                             |
| --------------------------------------------------------------------------- | ---------------------------------------------------- |
| `tests_property/`                                                           | Hypothesis suite and shared strategies               |
| `execution_testing/specs/invariants.py`                                     | invariant definitions                                |
| `execution_testing/cli/pytest_commands/plugins/filler/invariant_checker.py` | the `fill` flag                                      |
| `execution_testing/evm_tools/t8n/evm_trace/bal_witness.py`                  | the trace-stream witness the BAL check compares with |
| `execution_testing/eip_properties/`                                         | manifest, covariant marker, structural observables   |
| `docs/dev/testing_paradigm_design.md`                                       | the gap analysis and design behind all this          |
