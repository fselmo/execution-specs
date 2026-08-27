# Property, Fuzz, and Mutation Testing

The conformance suite under `tests/` asks one question: does a client reproduce
a frozen, hand-authored result? The tools on this page ask three others:

- Does the spec obey laws that must hold for *every* block?
- Would *any* test notice if the spec were wrong in a small way?
- Does a client agree with the spec on inputs nobody hand-wrote?

One rule governs all of them: **the generator chooses inputs, EELS computes
outputs.** Nothing here authors an expected post-state. Every oracle is a
stated law, another implementation, or the spec itself.

## Why opt-in flags and separate commands

- **Fixtures are a shared artifact.** Every client team consumes `fill`
  output, so nothing here may change a fixture or fail a fill by default.
  `--invariant-checks` is off by default and warn-only: violations become
  warnings plus an `invariant_violations` entry in the fixture's `_info`
  metadata; the fixture bytes are identical either way.
- **Exploration is not conformance.** `fuzz`, `fuzz-differential`, `mutate`,
  `fuzz-distill`, and `eip-manifest` are separate `uv run` commands because
  they are slow (mutation re-runs a suite per mutant), need external binaries
  (a client `t8n`), or produce findings rather than fixtures. None of that
  belongs in the `fill` hot path.
- **Property tests are not fixtures.** `fill` collects `tests/`, so Hypothesis
  tests live in `tests_property/` and run as plain pytest via
  `just test-spec-properties`.

## The layers

Each layer uses the ones below it as its oracle or its input.

| Layer          | Command                      | Oracle                      | Finds                                    |
| -------------- | ---------------------------- | --------------------------- | ---------------------------------------- |
| Property tests | `just test-spec-properties`  | EIP / Yellow Paper prose    | a component violating a stated law       |
| Invariants     | `fill --invariant-checks`    | chain laws                  | spec or framework bugs on any test       |
| Fuzzing        | `uv run fuzz`                | invariants                  | crashes and violations on generated input|
| Differential   | `uv run fuzz-differential`   | a client transition tool    | self-consistent bugs (mispriced constant)|
| Mutation       | `uv run mutate`              | the tests themselves        | mutants no test kills (coverage gaps)    |
| Distillation   | `uv run fuzz-distill`        | —                           | turns a corpus case into a reviewable test|
| Manifest       | `uv run eip-manifest`        | —                           | what a fork changed, per EIP             |

## Property tests (`tests_property/`)

Plain pytest with Hypothesis. Every module is parametrized over
`PROPERTY_TEST_FORKS` (`osaka`, `amsterdam`) through the `fork_name` fixture and
imports the fork's modules by name; where calling conventions differ between
forks, the test carries a small explicit adapter.

```console
just test-spec-properties
just test-spec-properties --hypothesis-profile=nightly
```

| Profile   | Behaviour                                                         |
| --------- | ----------------------------------------------------------------- |
| `ci`      | default; derandomized so runs reproduce, 200 examples per property |
| `dev`     | randomized exploration for local runs                             |
| `nightly` | 5000 examples, randomized                                         |

A found regression is pinned as an explicit `@example(...)` on the failing test.

**Grounding rule.** A property's assertion must come from outside the code it
tests: EIP prose, the Yellow Paper, or an independent reference model.
Transcribing the EELS formula into a test is circular and proves nothing. Each
property's docstring records its grounding.

| Theme                  | Modules                                                                 |
| ---------------------- | ----------------------------------------------------------------------- |
| Spec components        | `test_rlp`, `test_trie`, `test_numeric`, `test_gas`, `test_intrinsic_cost`, `test_signatures` |
| Stateful               | `test_state_machine` — `RuleBasedStateMachine` driving the state tracker against a reference model |
| EIP-mined (Amsterdam)  | `test_eip7825`, `test_eip7928_bal`, `test_eip8037_state_gas`, `test_frame_gas_lifecycle` |
| Manifest-driven        | `test_archetype_header_field`, `test_manifest_covariant` — one body, every fork transition |

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

The same checker is the oracle for `uv run fuzz` and for `mutate --oracle fill`.

## How fuzzing works

### 1. Generation is a pure function of the seed

A case (`FuzzerOutput`: funded EOAs with deterministic keys, contracts with
generated bytecode, transactions with correct per-sender nonces) is fully
determined by `(fork, GENERATOR_VERSION, seed)`. A seed alone reproduces a case.
`GENERATOR_VERSION` is bumped whenever generation logic changes, so old seeds
are never silently reinterpreted and every corpus entry records the version
that produced it.

Bytecode generation is **stack-aware**: it tracks a virtual stack height and
pushes operands before each opcode, so programs execute real logic instead of
reverting on the first underflow. Dynamic jumps are excluded (without a
control-flow model they land on invalid destinations). Each contract also gets
`STATICCALL`s into the fork's precompiles — at least one per contract, plus an
occasional probe just past the precompile address range — and stores the
success flag and `RETURNDATASIZE` to storage so a divergence in either shows in
the post-state, not only in gas. Precompiles the fork *newly added* are
up-weighted (`eip_properties/targeting.py`, fed by the manifest): a fresh curve
operation is where a consensus bug hides, not decade-old `ecrecover`.

### 2. Execution through EELS

```console
uv run fuzz --fork Osaka --count 500 --corpus corpus/
```

Each case becomes a `BlockchainTest` and is filled in-process through the
reference spec; every block is checked against the invariants above. A crash
or a violation is an *interesting* case.

| Option          | Default | Purpose                                              |
| --------------- | ------- | ---------------------------------------------------- |
| `--fork`        | —       | fork to fuzz                                         |
| `--seed-start`  | `0`     | first seed; with `--count` defines a reproducible range |
| `--count`       | `100`   | number of seeds                                      |
| `--corpus DIR`  | none    | save interesting cases here as `FuzzerOutput` JSON   |
| `--no-minimize` | off     | skip delta-debugging of saved cases                  |

### 3. Minimization and the corpus

Interesting cases are shrunk by delta-debugging (`ddmin`) over the case's
structure — drop transactions, drop non-sender accounts, truncate contract
code — keeping only reductions that preserve a "still interesting" predicate.
The result is saved as plain `FuzzerOutput` JSON (`<Fork>_<label>_seed<N>.json`),
the fuzzer bridge's native input format, so existing tooling consumes it
unchanged.

### 4. Differential: EELS versus a client

```console
go build -o ./build/bin/evm ./cmd/evm        # in a go-ethereum checkout
uv run fuzz-differential --fork Osaka --evm-bin path/to/evm --count 2000 \
    --workers 8 --corpus divergences/
```

Each case runs through EELS in-process *and* the client's `t8n`. The results
are compared field by field — `state_root`, `receipts_root`, `logs_hash`,
`gas_used`, `withdrawals_root`, `blob_gas_used`, `requests_hash`,
`block_access_list_hash` — plus the set of rejected transactions. One side
failing where the other succeeds is a divergence; both failing is agreement.
Divergences are minimized with a "still diverges" predicate and saved to the
corpus.

This is the only layer that catches a *self-consistent* bug: a mispriced gas
constant passes every fixture EELS filled and every invariant, but a client
disagrees.

| Option          | Default | Purpose                                                    |
| --------------- | ------- | ---------------------------------------------------------- |
| `--evm-bin`     | —       | client transition tool (geth's `evm`)                      |
| `--workers N`   | `1`     | process pool; output order is deterministic regardless    |
| `--seed-start`, `--count`, `--corpus`, `--no-minimize` | | as for `fuzz` |

### 5. Distillation into a reviewable test

```console
uv run fuzz-distill divergences/Osaka_divergence_seed42.json tests/osaka/test_finding.py \
    --reason "geth/EELS state root divergence on identity precompile gas"
```

Renders a corpus case as a `BlockchainTestFiller` module with explicit
accounts, transactions, and a provenance docstring (seed, generator version,
reason). The rendering is faithful rather than idiomatic because it must
reproduce the original execution; `post` is left empty for the reviewer. Once
reviewed it fills like any other test — a transient finding becomes a permanent
fixture.

### 6. Fuzzing inside an ordinary test

The generator's strategies are public, so a normal seed-parametrized test can
fuzz without any of the commands above:

```python
from execution_testing.fuzzing import fuzzed_bytecode, fuzzed_calldata

@pytest.mark.valid_from("Osaka")
@pytest.mark.parametrize("seed", range(8))
def test_fuzzed_contract_execution(state_test, pre, seed):
    rng = random.Random(seed)
    contract = pre.deploy_contract(code=fuzzed_bytecode(rng))
    tx = Transaction(
        sender=pre.fund_eoa(),
        to=contract,
        gas_limit=1_000_000,
        data=fuzzed_calldata(rng),
    )
    state_test(env=Environment(), pre=pre, post={}, tx=tx)
```

`post={}` lets EELS compute the state; `fill --invariant-checks` validates it.
See `tests/fuzzing/test_fuzzed_execution.py`.

## Mutation testing (`uv run mutate`)

Asks the inverse question of every other layer: if the spec were *wrong* in
this one small way, does any test notice?

```console
uv run mutate --module src/ethereum/forks/osaka/vm/gas.py \
    --oracle properties --test tests_property/test_gas.py
uv run mutate --module src/ethereum/forks/osaka/vm/gas.py \
    --oracle fill --fork Osaka --test tests/frontier/opcodes
```

Each mutant is a single operator swap (comparison, arithmetic, boolean) spliced
into the source; the oracle runs; the source is restored — also on `SIGTERM`.
Constant tweaks are opt-in (`--include-constants`) because they are numerous
and noisy.

| Verdict            | Meaning                                                      |
| ------------------ | ------------------------------------------------------------ |
| `killed (tests)`   | the oracle failed                                            |
| `killed (invariant only)` | no test failed but an invariant violation appeared (`fill` oracle) |
| `killed (timeout)` | the run exceeded `--timeout` (an infinite loop is a kill)    |
| `survived`         | nothing distinguished the mutant from the spec — a gap       |

| Option                | Purpose                                                                 |
| --------------------- | ----------------------------------------------------------------------- |
| `--oracle fill`       | targeted `fill` with invariant checks; measures the conformance suite   |
| `--oracle properties` | `tests_property/`; faster, measures the property suite                  |
| `--test PATH`         | what to run (repeatable); `-x` makes kills cheap, survivors pay full cost |
| `--max-mutants N`, `--seed` | deterministic sample of the mutant set                            |
| `--timeout S`         | per-run limit, default 600                                              |

Two caveats. Mutation measures *teeth*, not correctness: a property can kill
mutants and still be wrongly grounded, so human review of grounding stays. And
nothing else may read `src/` during a run — you would observe a mutant. After
any abnormal exit, `git diff src/` before trusting the tree.

The kill-delta of `--oracle properties` before and after adding a property is
the objective validity signal for a mined property.

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
- `fuzz_precompile_targets()` — the generator's up-weighting of new precompiles.

Known limits: when several EIPs co-override a value, attribution is a candidate
*set*; some fork-level scalars are unattributed.

## Mining properties with an agent (`/mine-properties`)

The `.claude/commands/mine-properties.md` skill runs the loop the layers above
were built to support: analyze an EIP (via the manifest) or a module, propose
properties grounded in prose, write them as Hypothesis tests, measure them with
`mutate --oracle properties`, and triage each into one of three tracks —
spec defect, coverage gap, or *spec ambiguity* (the prose does not determine
the behaviour). Ambiguities are recorded in
[`spec_ambiguity_findings.md`](./spec_ambiguity_findings.md) with EELS's
current choice cited, and are never promoted to normative.

## Where things live

| Path                                                       | Contents                                   |
| ---------------------------------------------------------- | ------------------------------------------ |
| `tests_property/`                                          | Hypothesis suite and shared strategies     |
| `execution_testing/specs/invariants.py`                    | invariant definitions                      |
| `execution_testing/cli/pytest_commands/plugins/filler/invariant_checker.py` | the `fill` flag             |
| `execution_testing/cli/fuzzer_bridge/`                     | generator, engine, corpus, differential, distill |
| `execution_testing/fuzzing/strategies.py`                  | public `fuzzed_bytecode` / `fuzzed_calldata` |
| `execution_testing/cli/mutation/`                          | mutant enumeration and runner              |
| `execution_testing/eip_properties/`                        | manifest, covariant marker, structural observables, fuzz targeting |
| `docs/dev/testing_paradigm_design.md`                      | the gap analysis and design behind all this |
