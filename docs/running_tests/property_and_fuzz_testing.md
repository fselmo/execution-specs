# Property, Fuzz, and Mutation Testing

The conformance suite under `tests/` asks one question: does a client reproduce
a frozen, hand-authored result? The tools on this page ask three others:

- Does the spec obey laws that must hold for *every* block?
- Would *any* test notice if the spec were wrong in a small way?
- Do clients agree with the spec — and with each other — on inputs nobody
  hand-wrote?

One rule governs all of them: **the generator chooses inputs, EELS computes
outputs.** Nothing here authors an expected post-state. Every oracle is a
stated law, another implementation, or the spec itself.

## Why opt-in flags and separate commands

- **Fixtures are a shared artifact.** Every client team consumes `fill`
  output, so nothing here may change a fixture or fail a fill by default.
  `--invariant-checks` is off by default and warn-only: violations become
  warnings plus an `invariant_violations` entry in the fixture's `_info`
  metadata; the fixture bytes are identical either way.
- **Exploration is not conformance.** `fuzz`, `mutate`, and `eip-manifest`
  are separate `uv run` commands because they are slow (mutation re-runs a
  suite per mutant), need client binaries, or produce findings rather than
  fixtures. None of that belongs in the `fill` hot path.
- **Property tests are not fixtures.** `fill` collects `tests/`, so Hypothesis
  tests live in `tests_property/` and run as plain pytest via
  `just test-spec-properties`.
- **Client setup is per checkout, not per command.** Which clients to compare,
  where their binaries are, and what to run live in a gitignored `fuzz.yaml`,
  so a run is `fuzz diff --campaign NAME` rather than a chain of paths.

## The layers

Each layer uses the ones below it as its oracle or its input.

| Layer          | Command                     | Oracle                      | Finds                                     |
| -------------- | --------------------------- | --------------------------- | ----------------------------------------- |
| Property tests | `just test-spec-properties` | EIP / Yellow Paper prose    | a component violating a stated law        |
| Invariants     | `fill --invariant-checks`   | chain laws                  | spec or framework bugs on any test        |
| Fuzzing        | `uv run fuzz run`           | invariants                  | crashes and violations on generated input |
| Differential   | `uv run fuzz diff`          | other clients, then EELS    | self-consistent bugs (mispriced constant) |
| Mutation       | `uv run mutate`             | the tests themselves        | mutants no test kills (coverage gaps)     |
| Distillation   | `uv run fuzz distill`       | —                           | turns a corpus case into a reviewable test|
| Manifest       | `uv run eip-manifest`       | —                           | what a fork changed, per EIP              |

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

The same checker is the oracle for `fuzz run` and for `mutate --oracle fill`.

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
control-flow model they land on invalid destinations).

On top of the walk, snippets are injected that reproduce the frame shapes
real consensus bugs have taken, each storing a witness to storage so a
divergence shows in the post-state, not only in gas:

- **Calls into precompiles** — at least one per contract, as `STATICCALL` or
  as value-bearing `CALL`/`CALLCODE`, plus an occasional probe just past the
  precompile address range. Precompiles the fork *newly added* are up-weighted
  (`eip_properties/targeting.py`, fed by the manifest): a fresh curve operation
  is where a consensus bug hides, not decade-old `ecrecover`.
- **Calls into sibling contracts and the contract itself** — every kind
  (`CALL`, `CALLCODE`, `DELEGATECALL`, `STATICCALL`), so nested frames,
  recursion, and reverting or halting children arise naturally. Gas is drawn
  from a set straddling the stipend and typical precompile costs, so calls
  fail about as often as they succeed.
- **A halting child, then a cold state charge** — a call with too little gas
  for any state work, followed by a fresh `SSTORE` and a value transfer to a
  fresh account; a child settled wrongly only shows when the parent spends.
- **`CREATE2` self-replication** — a gas-keyed `SSTORE`, then the contract
  deploys a copy of its own code, which recurses until the 63/64 rule starves
  it: many independent reverting frames in one transaction.
- **Calls into a selfdestructing helper** — a contract whose code is
  `ORIGIN SELFDESTRUCT`; under `CALLCODE`/`DELEGATECALL` the caller
  schedules its own destruction.

Every body ends with an **observation epilogue** (`GAS`, `RETURNDATASIZE`
and `SELFBALANCE` stored to fixed slots) so internal gas or return-data
differences become state-root differences. The palette also covers
`CREATE`/`CREATE2`, transient storage, logs, `EXTCODE*`/`BALANCE`,
`BLOBHASH` and `MCOPY`, and transaction gas limits include the EIP-7825 cap,
budgeted so a block never exceeds its gas limit.

### 2. Execution through EELS

```console
uv run fuzz run --fork Osaka --count 500 --corpus corpus/
```

Each case becomes a `BlockchainTest` and is filled in-process through the
reference spec; every block is checked against the invariants above. A crash
or a violation is an *interesting* case.

| Option          | Default | Purpose                                                 |
| --------------- | ------- | ------------------------------------------------------- |
| `--fork`        | —       | fork to fuzz                                            |
| `--seed-start`  | `0`     | first seed; with `--count` defines a reproducible range |
| `--count`       | `100`   | number of seeds                                         |
| `--corpus DIR`  | none    | save interesting cases here as `FuzzerOutput` JSON      |
| `--no-minimize` | off     | skip delta-debugging of saved cases                     |

### 3. Minimization and the corpus

Interesting cases are shrunk by delta-debugging (`ddmin`) over the case's
structure — drop transactions, drop non-sender accounts, truncate contract
code — keeping only reductions that preserve a "still interesting" predicate.
The result is saved as plain `FuzzerOutput` JSON (`<Fork>_<label>_seed<N>.json`),
the fuzzer bridge's native input format, so existing tooling consumes it
unchanged.

### 4. Differential: clients against each other, EELS as the judge

Declare the clients once in a gitignored `fuzz.yaml` at the repository root:

```yaml
clients:
  - name: geth
    build: {ref: master}            # known recipe: cloned, built, cached by commit
  - name: geth-pr
    build: {recipe: geth, ref: pr/1234}
  - name: evmone
    path: ~/src/evmone/build/bin/evmone-t8n
campaigns:
  amsterdam:
    fork: Amsterdam
    clients: [geth, geth-pr, evmone]
    count: 2000
    workers: 8
    corpus: divergences/
```

```console
uv run fuzz clients            # source · binary · version, per client
uv run fuzz clients --update   # re-resolve refs, build new commits
uv run fuzz diff --campaign amsterdam
uv run fuzz diff --fork Osaka --client path/to/evm --count 300 -j 6
```

A client is a binary on disk or a source build. Builds are cloned under
`~/.cache/eels-fuzz/<name>` (or `$EELS_FUZZ_CACHE`), the ref resolved to a
commit, and each commit built at most once into its own directory; switching
branches never rebuilds what exists. Any t8n wrapper EEST ships is detected
from the binary (`evm`, `evmtool`, `nethtest`, `evmone-t8n`, ...). EEST reads
the client off the `--version` line, which echoes the binary's *name*, so a
built artifact must carry the canonical name — known recipes handle that.

A run then does four things:

1. **Manifest.** Prints and, with a corpus, writes `manifest.json`: the spec
   commit, each client's version line, the generator version, fork, and seed
   range. A divergence without provenance is a rumor.
2. **Baseline gate.** Every client must agree with EELS on a fixed set of seeds
   (far above any campaign's range). A client that does not is stale — built
   before the spec's latest change — and the run stops naming it
   (`stale clients: evm: 3/10`) rather than producing a wall of false
   divergences. `--no-baseline` skips it.
3. **Tiered comparison.** With two or more clients, each case runs the natives
   first; EELS runs only when they disagree, and then settles who is wrong.
   Fields compared: `state_root`, `receipts_root`, `logs_hash`, `gas_used`,
   `withdrawals_root`, `blob_gas_used`, `requests_hash`,
   `block_access_list_hash`, and the set of rejected transactions. One tool
   failing where another succeeds is a divergence; every tool failing is
   agreement. `--no-tiering` runs EELS on every case.
4. **Majority view and localization.** Each divergence names the minority
   — a tie sides with EELS — so the report says *who* disagrees, not only
   that someone does, and lists the accounts on which the minority's
   post-state differs from EELS (`fuzz replay` prints them in full).
   Divergent cases are minimized under a predicate that preserves the
   original (field, minority) signature, so a reduction cannot drift onto
   an unrelated bug, and saved as
   `<fork>_divergence_seed<N>_<field>_<minority>.json`.

Tiering is off by default: on today's small generated cases it saves about
5% (300 seeds), because each client call is a subprocess spawn and that
dominates the per-case cost. `--tiering` enables it; the gain grows with case
size, where the Python interpreter's per-opcode cost takes over.

| Option                                   | Purpose                                                    |
| ---------------------------------------- | ---------------------------------------------------------- |
| `--campaign NAME`                        | fork, clients, and run size from `fuzz.yaml`               |
| `--config PATH`                          | a `fuzz.yaml` other than the nearest one                   |
| `--client PATH` (repeatable)             | clients by binary; adds to or replaces the campaign's      |
| `--fork`, `--count`, `--seed-start`, `-j`| override the campaign                                      |
| `--baseline-seeds N`, `--no-baseline`    | size of the stale-client check (default 20), or skip it    |
| `--tiering`                              | natives first, EELS only on their disagreement             |
| `--summary-json PATH`                    | machine-readable counts, first divergent seed, field tally |
| `--corpus DIR`, `--no-minimize`          | as for `fuzz run`                                          |

This is the only layer that catches a *self-consistent* bug: a mispriced gas
constant passes every fixture EELS filled and every invariant, but a client
disagrees. It is also the only layer that catches a *client* bug — every other
layer tests the spec.

### 5. Campaigns: hours against every client's fixture runner

`fuzz diff` spawns a t8n per client per case and needs a t8n wrapper; it is
the localization tool. Detection at width goes through the path clients
already run for conformance: a campaign fills generated cases through EELS
into fixture files of `--batch` cases and hands each file to every client's
standalone fixture runner (`evm blocktest`, `evmone-blockchaintest`,
`evmtool block-test`, `nethtest`) — one process per file per client, all
clients concurrently. A runner rejecting a fixture is a disagreement with
EELS. Pin every build to the devnet branch the clients are being tested on:

```yaml
clients:
  - name: geth
    build: {recipe: geth, ref: glamsterdam-devnet-8}
  - name: erigon
    build: {recipe: erigon, ref: glamsterdam-devnet-8}
  - name: besu
    build: {recipe: besu, ref: glamsterdam-devnet-8}
  - name: nethermind
    build: {recipe: nethermind, ref: glamsterdam-devnet-8}
  - name: evmone
    build: {recipe: evmone, ref: master}
campaigns:
  devnet:
    fork: Amsterdam
    clients: [geth, erigon, besu, nethermind, evmone]
```

Builds use whatever toolchains the shell has: Go ≥ 1.24 with cgo (erigon),
the JDK besu's Gradle toolchain asks for (25 on the devnet branches — set
`JAVA_HOME`, also when running the campaign, since `evmtool` starts a JVM),
the .NET SDK band nethermind's `global.json` pins (10.0.3xx), and CMake +
C++20 (evmone).

```console
uv run fuzz clients --update          # clone and build each ref once
tmux new -s fuzz
uv run fuzz campaign devnet --hours 8 --fill-workers 24
```

Each batch produces one verdict per client per fixture:

- every client passes — *agreed*;
- every client fails — *all-fail*: EELS or the generated block is suspect,
  so it is counted, never reported as a client finding;
- some fail — a *divergence*; each failing client is judged on its own.

A divergence produces one **signature per failing client**:
`(client, error line)` with hashes and numbers stripped, so a bug that fires
thousands of times is one row with a count. Per-client keying matters when
two bugs co-occur — two clients both failing one case (common when both
touch the block access list) become two rows, each with its own text, not
one joint row wearing one client's error. The first case of each new
signature is bundled under `corpus/<client>--<slug>-<digest>/`: `case.json`
(replay or distill it as usual), `fixture.json`, every client's verdict, and
`minimized.json` with `--minimize` (reduced while *that* client still
fails). The first batch doubles as the baseline: a client failing more than
half of it is stale and the run stops naming it (`--no-baseline`).

A signature already understood — a bug that is filed, or a client known to
lag the spec — is listed under `known:` in the campaign so it is counted but
never bundled or minimized again, keeping the findings table to what is new:

```yaml
campaigns:
  devnet:
    fork: Amsterdam
    clients: [geth, erigon, besu, nethermind]
    known:
      - {client: besu, reason: "chain header mismatch"}
```

`reason` is a substring matched against the normalized error; `client` is
optional (any client when omitted). Known signatures render in a separate
"Known (suppressed)" section of the report. The signature scheme is
versioned in `state.json`; resuming a state written under an older scheme
keeps its seed range and counts but recounts signatures afresh.

`state.json` and `report.md` are rewritten after every batch, so Ctrl-C or a
dead tmux leaves a valid report and rerunning the same command resumes;
`--fresh` starts over. `--count` is a seed range from the campaign's
`seed_start`; `--hours` is a budget per invocation. The report records the
spec commit, each client's version line, counts per class, failures per
client, and the signature table.

| Option                    | Purpose                                                        |
| ------------------------- | -------------------------------------------------------------- |
| `--hours H` / `--count N` | budget; one is required                                        |
| `--batch N`               | cases per fixture file and per runner invocation (default 200) |
| `--fill-workers W`        | EELS fill processes; filling is the throughput floor           |
| `--output DIR`            | state, report, corpus, fixtures (default `campaigns/NAME`)     |
| `--minimize`              | ddmin each new signature's case                                |
| `--keep-fixtures`         | keep every batch file, not only the bundled ones               |
| `--no-baseline`, `--fresh`| skip the stale-client gate; discard saved state                |

The runner binaries must carry their canonical names (`evm`, `evmtool`,
`nethtest`, `evmone-blockchaintest`), which the recipes ensure. When
`validate` lands (execution-specs #2622) the campaign will hand files to it
instead of driving each runner itself.

### 6. Replaying one case

```console
uv run fuzz replay divergences/Amsterdam_divergence_seed42.json --campaign amsterdam
```

Re-runs a saved case through EELS and every client and prints each compared
field per tool with the minority marked. Exits 1 on disagreement, so a fixed
client can be re-checked from a script.

### 7. Distillation into a reviewable test

```console
uv run fuzz distill divergences/Amsterdam_divergence_seed42.json tests/amsterdam/test_finding.py \
    --reason "nethermind/EELS gas_used divergence on spilled state gas at halt"
```

Renders a corpus case as a `BlockchainTestFiller` module with explicit
accounts, transactions, and a provenance docstring (seed, generator version,
reason). The rendering is faithful rather than idiomatic because it must
reproduce the original execution; `post` is left empty for the reviewer. Once
reviewed it fills like any other test — a transient finding becomes a permanent
fixture.

### 8. Fuzzing inside an ordinary test

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

| Verdict                   | Meaning                                                            |
| ------------------------- | ------------------------------------------------------------------ |
| `killed (tests)`          | the oracle failed                                                  |
| `killed (invariant only)` | no test failed but an invariant violation appeared (`fill` oracle) |
| `killed (timeout)`        | the run exceeded `--timeout` (an infinite loop is a kill)          |
| `survived`                | nothing distinguished the mutant from the spec — a gap             |

| Option                      | Purpose                                                                  |
| --------------------------- | ------------------------------------------------------------------------ |
| `--oracle fill`             | targeted `fill` with invariant checks; measures the conformance suite    |
| `--oracle properties`       | `tests_property/`; faster, measures the property suite                   |
| `--test PATH`               | what to run (repeatable); `-x` makes kills cheap, survivors pay full cost |
| `--max-mutants N`, `--seed` | deterministic sample of the mutant set                                   |
| `--timeout S`               | per-run limit, default 600                                               |

Two caveats. Mutation measures *teeth*, not correctness: a property can kill
mutants and still be wrongly grounded, so human review of grounding stays. And
nothing else may read `src/` during a run — you would observe a mutant. After
any abnormal exit, `git diff src/` before trusting the tree.

The kill-delta of `--oracle properties` before and after adding a property is
the objective validity signal for a mined property.

### Measuring generator reach with shapes

```console
uv run mutate --shape child-read-rollback --shape child-spill-credit \
    --shape precompile-value-callcode-refund \
    --oracle differential --fork Amsterdam --campaign amsterdam
```

A *shape* is a reviewed, multi-file edit to the spec that models the
mechanism of a bug a client actually shipped (reads dropped when a child
frame reverts; spilled state gas credited back along a halt chain; a failed
value-bearing `CALLCODE` into a precompile refunded). Applying it makes EELS
the wrong side, so a clean client must catch it: the kill rate per shape is
the generator's *reach* for that bug class, and it is measured before and
after every generator change. Shapes are anchored on exact spec text and
fail loudly when the spec moves. Under the `fill` or `properties` oracle the
same command asks whether the suites would have caught the class.

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
[`spec_ambiguity_findings.md`](../dev/spec_ambiguity_findings.md) with EELS's
current choice cited, and are never promoted to normative.

## Where things live

| Path                                                                        | Contents                                                           |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `tests_property/`                                                           | Hypothesis suite and shared strategies                             |
| `execution_testing/specs/invariants.py`                                     | invariant definitions                                              |
| `execution_testing/cli/pytest_commands/plugins/filler/invariant_checker.py` | the `fill` flag                                                    |
| `execution_testing/cli/fuzzer_bridge/cli.py`                                | the `fuzz` command group                                           |
| `execution_testing/cli/fuzzer_bridge/config.py`, `clients.py`               | `fuzz.yaml` model; client sources and the build cache              |
| `execution_testing/cli/fuzzer_bridge/differential.py`                       | multi-client comparison, tiering, majority view                    |
| `execution_testing/cli/fuzzer_bridge/baseline.py`, `run_manifest.py`        | stale-client gate; provenance record                               |
| `execution_testing/cli/fuzzer_bridge/campaign.py`, `runners.py`             | long-running campaigns; whole-file client fixture runners          |
| `execution_testing/cli/fuzzer_bridge/`                                      | generator, engine, corpus, distill                                 |
| `execution_testing/fuzzing/strategies.py`                                   | public `fuzzed_bytecode` / `fuzzed_calldata`                       |
| `execution_testing/cli/mutation/`                                           | mutant enumeration and runner                                      |
| `execution_testing/eip_properties/`                                         | manifest, covariant marker, structural observables, fuzz targeting |
| `docs/dev/testing_paradigm_design.md`                                       | the gap analysis and design behind all this                        |
