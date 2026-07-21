# Testing Paradigm Expansion: Properties, Fuzzing, and Agentic Support

Working design document for the `experiments/testing-paradigm` branch.

Inspired by Anthropic's property-based-testing work (an agent infers
correctness properties from code and documentation, writes Hypothesis tests,
self-reflects to filter false positives, and rubric-ranks bug reports —
achieving 86% validity on top-ranked reports), this document answers the
question: **what aren't we doing that we should be doing?**

It covers the gap analysis, the target ("north star") architecture, a phased
roadmap, and the governing principles. A first proof-of-concept slice
(property test suite + fill-time invariant checker) lands alongside this
document.

## Current state (what exists today)

- **EELS is the in-process oracle.** The default `t8n` during `fill` imports
  `ethereum_spec_tools.evm_tools.t8n.T8N` directly
  (`client_clis/clis/execution_specs.py`); the spec computes every expected
  post-state.
- **`fuzzer_bridge` exists but only imports.** `cli/fuzzer_bridge/` converts
  external fuzzer JSON (`FuzzerOutput` DTOs) into `BlockchainTest` fixtures
  via `blockchain_test_from_fuzzer`. Nothing in-repo generates those DTOs.
- **Differential machinery exists but is idle at scale.** Nine client
  transition-tool wrappers (`client_clis/clis/`), a trace-comparator ladder
  (`client_clis/trace_comparators.py`), and the `--verify-traces` plugin
  (`plugins/filler/verify_traces.py`) exist; no harness drives generated
  inputs through them.
- **Coverage is measured, not used.** `fill` runs `--cov=ethereum
  --cov-branch` and gates at 85% on the `eels_base_coverage` subset; the
  signal feeds nothing.
- **State and trie are now shared modules.** `ethereum.state` and
  `ethereum.merkle_patricia_trie` are centralized on this branch; fork
  directories remain WET copies for everything else (blocks, transactions,
  vm). Cross-fork differential reasoning applies to the per-fork surface.
- **No Hypothesis, no invariant checking, no corpus lifecycle, no agentic
  tooling.** All randomness in the repo is deterministically seeded static
  data.

## The nine gaps

Ordered roughly by value-per-effort. Each names the seam that makes it
tractable.

### 1. No invariant checking on fills

Every filled test computes post-states via EELS, but nothing asserts the
chain's global laws: ether conservation (sum of balances vs. issuance,
withdrawals, and burned fees), header `gas_used` consistency with receipts,
nonce monotonicity, refund caps, base-fee formula, BAL completeness. Bugs
like the calldata-floor fix (`c74f1a67b6`) are exactly the class an
always-on invariant layer catches early.

**Fix:** pure check functions applied at the `BuiltBlock` seam
(`specs/blockchain.py` — holds header, t8n `Result`, transactions, and both
allocs per block) and the equivalent point in `StateTest`. Violations flow
out via `FillResult.metadata` (which `fill` already writes into fixture
`_info`). Warn-only first; hard-fail per fork once each fork's ledger checks
clean. Runs on **every** filled test forever, not just fuzz runs.

### 2. No property-based testing of spec components

RLP roundtrip, trie insert/delete/root order-independence, integer wrapping
and byte-conversion roundtrips, memory-expansion gas closed form, intrinsic
cost floors (EIP-7623), sign-and-recover roundtrips: classic property
targets, none tested as properties.

**Fix:** `hypothesis` in the test dependency group; a `tests_property/` root
(separate from `tests/` so the filler never collects it) with a shared
strategy library over spec domain types. Deterministic CI profile
(`derandomize=True`); found regressions checked in as `@example(...)`.

### 3. Generation infrastructure exists but nothing generates

**Fix:** a generator emitting `FuzzerOutput` DTOs in two layers: a seeded
structural generator (`random.Random(seed)`, deterministically derived EOA
keys, weighted bytecode built with the existing `vm/` Opcode machinery) as
the reproducible workhorse, identified by `(fork, generator_version, seed)`;
and a Hypothesis strategy wrapper for shrinking. Minimization as ddmin over
the DTO (drop transactions/accounts, truncate code) against a "still fails"
predicate. Interesting cases persist as FuzzerOutput JSON — already the
bridge's native input.

### 4. No differential testing at scale

The consensus-split-finding capability (highest-impact bug class) is fully
plumbed and unused. External efforts (goevmlab/FuzzyVM found consensus
crashes; Fluffy re-found 10 of 11 known consensus bugs in 12 hours with
multi-transaction differential fuzzing) live outside this repo, and their
finds never become frozen fixtures.

**Fix:** a `fuzz` pytest command mirroring `fill`: per-seed items →
generate → run through EELS in-process *and* client t8ns → compare
result-level first (post-state root, receipts root, per-tx gas, rejection
sets), then the trace-comparator ladder. Dedup divergences by hashing the
normalized first-diverging trace line (op/depth/error-class only).

**Tiered execution is the key design move:** native clients
(evmone/geth statetest, 10^4–10^5 exec/s) pre-filter for cross-client
disagreement; EELS (10^1–10^3 tx/s under PyPy) adjudicates only flagged or
structurally interesting cases. This routes around EELS throughput as the
bottleneck and buys roughly three orders of magnitude more adversarial
input volume against clients.

### 5. WET fork copies are an unused free oracle

Fork directories are complete copies, so "fork N and fork N+1 must differ
only per the scheduled EIP set" is directly checkable: run identical
generated inputs through both fork modules in-process, diff post-states,
and validate every divergence against an expected-diff manifest derived
from the fork's EIP list. This turns "did the fork copy break something"
and "did EIP X leak outside its intended surface" into a CI gate that arms
automatically whenever a new fork directory is created. Cheapest of the big
wins; needs no clients.

### 6. Coverage is measured but never used as a signal

**Fix, three tiers:** (a) coverage.py dynamic contexts per seed → greedy
set-cover → distilled corpus, plus a report of what fuzzing reaches that
hand-written tests do not; (b) Hypothesis `target()` on a new-edge counter
via `sys.monitoring` scoped to `ethereum.*` (the Justfile already sets
`COVERAGE_CORE=sysmon`); (c) optional HypoFuzz nightly for the property
suite. Cheaper novelty signals worth using at full speed: `OpcodeCount`
(the EELS t8n supports it), exception-class novelty, gas histograms.
Mutation testing of EELS ("does any fixture kill this mutant of the gas
formula?") — a much stronger metric than branch coverage — has landed; see
below.

### 7. No corpus-to-canonical-fixture lifecycle

The repo's crown jewel is that a frozen fixture is a permanent
industry-wide regression test; nothing distills discovered cases into that
form.

**Fix:** minimized FuzzerOutput → static fixture immediately (via
`BlocktestBuilder`); properly, a `gentest from-fuzzer` mode rendering the
case as human-readable `BlockchainTestFiller` source with docstring and
checklist markers, reviewed as a normal PR. Budget-capped (for example, at
most ~20 candidates a week) so the pipeline throttles to maintainer review
bandwidth.

### 8. No agentic tooling, in a near-best-case repo for it

Deterministic seeds fully reproduce cases; property suites run in seconds;
the spec is the most readable EVM implementation in existence, with
spec-grade docstrings. The agentic workflow maps directly:

- `/mine-properties <module>` — read the spec module, its docstrings, and
  linked EIPs (plus the fork diff for new forks); emit candidate properties
  as YAML with spec-line citations and confidence.
- `/write-property-test` — candidate → Hypothesis test using the shared
  strategy library; run it; apply the self-reflection loop ("property wrong
  vs. spec suspect"); record the reasoning.
- `/triage-divergence` — consume a minimized corpus case plus trace diff
  (via a deterministic preprocessor script); score against a checked-in
  rubric (reproducibility, spec-clause citation, attribution, severity,
  minimality).
- Coverage-auditor — read branch-coverage gaps; write targeted strategies
  or prove and annotate unreachability.
- Checklist-mapper — map fixtures to `checklists/eip_checklist.py` items
  automatically; gaps feed back as generation work items.

### 9. Missing governing principle: agents choose inputs, EELS computes outputs

Adopt as policy: agents and generators never author expected post-states —
EELS remains the sole source of expectations, exactly as in today's fill.
This one rule eliminates the dominant false-positive channel and makes the
agentic layer safe in a conformance-suite context, where a wrong frozen
fixture (poisoning every client's CI) is worse than a missed bug. Human
gates: property admission, distilled-fixture PR review, and immediate
escalation of confirmed consensus splits.

## North star ("if designed today")

The frozen JSON fixture and the consume/hive pipeline survive untouched —
**authorship inverts**. The primary artifact becomes a
(property, generator, constraint) registry; hand-written example tests
remain for exact scenario boundaries; fixtures are *distilled* from an
explored space (tens frozen per fork out of millions explored).

Three-oracle stack:

1. **EELS invariants** — registry properties checked in-process during fill.
2. **Cross-client differential** — native-speed pre-filter, EELS
   adjudication.
3. **Cross-fork differential** — fork N vs. N+1 behavioral diffs must match
   the scheduled EIP set.

A `@property_test(invariant=..., strategy=...)` spec type beside
`StateTestFiller`: in CI it draws N deterministic seeds and fills N
fixtures; under a fuzzing service it draws unboundedly. One authoring
artifact, two execution modes.

About 80% of today's framework survives unchanged. No EELS refactor is
required. The WET fork copies are load-bearing — do **not** DRY them; they
power oracle 3.

**Coverage upside (defensible estimates):** spec branch coverage 85% →
95–98% (the remainder proven-unreachable and annotated); the EIP checklist
from manually-tracked to fully evidenced, plus cross-EIP interaction
properties the checklist cannot express; adversarial input diversity
against clients up two to three orders of magnitude, with consensus-split
discovery moving from external ad-hoc fuzzers into the canonical pipeline
where every find freezes into a fixture. Calibration points: OSS-Fuzz-gen's
+29% line coverage over mature human-written fuzz targets; Fluffy's 10/11
known consensus bugs re-found in 12 hours.

## Phased roadmap

| Phase | What | Depends on | Effort | Ship signal |
| ----- | ---- | ---------- | ------ | ----------- |
| 1 | `tests_property/` + strategy library (gap 2) | — | M | `just test-spec-properties` green in CI |
| 1' | Fill-time invariant checker (gap 1) | — | M | warnings-clean full `just fill` |
| 2 | Generator → fuzzer_bridge + ddmin + corpus (gap 3) | 1 | M | **landed** — `fuzz --fork --count` replayable |
| 2' | Cross-fork differential gate (gap 5) | 2 | S–M | zero-divergence gate on fork copy |
| 3 | Differential harness, EELS vs. client t8ns (gap 4) | 2 | M–L | **landed** — `fuzz-differential --evm-bin` vs geth |
| 4 | Coverage feedback + corpus distillation (gap 6) | 2, 3 | M | distilled corpus + gap report |
| 5 | Distillation → canonical fixtures (gap 7) | 2, 3 | M | **landed** — `fuzz-distill` case.json → fillable test |
| 6 | Agentic skills + rubric + triage (gap 8) | 1, 3 | M | first agent-mined property merged |

## PoC validation (mutation experiments)

Realistic bugs were injected into the spec one at a time, and each layer
was checked for whether it catches what the existing suite misses:

| Injected spec bug | Existing fill suite | Property suite | Invariant checker |
| --- | --- | --- | --- |
| Trie deletion keeps key with default value (`merkle_patricia_trie.py`) | not exercised | **caught** (2 properties: insert-then-delete, default-equals-absence) | n/a |
| High-s signature malleability check removed (osaka `transactions.py`) | not exercised | **caught**, and localized to `[osaka]` (untouched `[amsterdam]` kept passing) | n/a |
| Coinbase credited +1 wei per transaction (osaka `fork.py` fee settlement) | **1185/1185 tests passed silently** | relational properties hold (self-consistent) | **caught on all 1185 tests** with exact drift (`unexplained=1`) |

The third row is the core argument: because EELS is the oracle that
computes fixture expectations, an EELS accounting bug propagates into
every generated fixture unless something independent of the computation
checks the result. The ledger invariant is that independent check. The
same reasoning motivates the cross-client differential harness (phase 3)
for bug classes that are self-consistent even at the ledger level, such
as a mispriced gas constant: relational properties and conservation both
hold, and only comparison against an independent implementation catches
it.

Known warn-only false-positive classes, confirmed on real fills and
documented in the check docstrings: SELFDESTRUCT-to-self burns
(EIP-6780 tests) and same-block account death + re-creation resetting a
nonce (withdrawals `test_self_destructing_account`).

Warning-noise measurements on unmutated fills (`--invariant-checks`):

| Scope | Cases | Warnings |
| --- | --- | --- |
| `tests/osaka` (entire fork directory) | 3,922 | 0 |
| `tests/prague/eip2537` G1ADD | 273 | 0 |
| `tests/prague/eip7702` nonce/self-sponsor subset | 138 | 0 |
| `tests/cancun/eip4844` blobhash contexts | 33 | 0 |
| `tests/shanghai/eip4895` withdrawals | 80 | 2 (documented account-rebirth) |
| `tests/cancun/eip6780` same-tx selfdestruct | 144 | 48 (documented self-burn blind spot) |

Signal-to-noise is high enough that after modeling selfdestruct burns
(needs per-tx destroyed-account info from the t8n), the checker can
plausibly flip to default-on hard-fail per fork.

## Generator + fuzz engine (phase 2, landed)

`uv run fuzz --fork Osaka --count N [--corpus DIR]` generates seeded
`FuzzerOutput` cases, fills them through EELS with the invariant oracle
enabled, and saves any violating/crashing case to the corpus, minimized
via delta-debugging. Every case is reproducible from
`(fork, GENERATOR_VERSION, seed)`.

The generator is *stack-aware*: it tracks a virtual stack height and
pushes operands before each opcode, which is what keeps generated
programs executing real logic instead of reverting on underflow.
Measured on Osaka (in-process EELS, no coverage):

- ~60 cases/s single-core;
- 200/200 generated transactions accepted (none intrinsically invalid);
- 100% of accepted transactions execute non-trivial logic (mean ~279k
  gas/tx), versus the "random bytecode reverts immediately" failure mode
  the plan flagged;
- 100/100 clean seeds produce zero false invariant violations.

End-to-end bug-finding, verified: the +1-wei coinbase mutation is caught
on every seed and delta-debugged from 5 transactions / 6 accounts down
to the minimal 1 transaction / 2 accounts that still triggers it. This
closes the loop from "generate" to "minimized, reproducible,
corpus-persisted finding" — the input to phase 3 (differential) and
phase 5 (distillation to canonical fixtures).

## Mutation testing of the spec (landed)

`uv run mutate --module <spec file> --test <path> --fork <fork>` mutates a
spec source file one operator at a time (comparison swaps, arithmetic swaps,
boolean flips; constant tweaks opt-in), and for each mutant runs a targeted
`fill` with the invariant checks enabled. A mutant is *killed* if a test
fails, a new invariant fires, or the run times out; a *survivor* is a spec
error the conformance suite cannot tell apart from correct behavior — a
coverage gap. The original source is always restored.

This measures test-suite strength directly, which branch coverage cannot:
the +1-wei coinbase bug earlier passed 1185/1185 tests at 100% branch
coverage. Killed mutants exit fast under `-x`; only survivors pay the full
run, so cost scales with survivor count.

Demonstrated discrimination on `frontier/vm/gas.py` (same 12 mutants,
same seed):

| Test set | Mutation score |
| --- | --- |
| `tests/frontier/opcodes/` | 5/12 (42%) |
| `tests/frontier/` | 10/12 (83%) |

Widening the test set killed five more of the *same* mutants, confirming the
score is a property of the suite, not the tool. Two mutants survive the full
Frontier suite, both in memory-expansion gas
(`size_in_words * MEMORY_PER_WORD` and `total_cost - already_paid`): the
Frontier tests never assert an exact memory-expansion gas cost, so those
coefficient errors go unnoticed. That is a concrete, actionable gap and the
kind of work item a test-writing agent can act on.

The runner also distinguishes *killed by invariant only* — a mutant the test
suite misses but the fill-time invariant layer catches — quantifying what
the invariant checker adds on top of the frozen fixtures.

## Applying the stack to a live fork: Amsterdam (landed)

The whole point is impact on the fork under development. Two Amsterdam
results, each a different tool answering a different question:

**Repricing is already pinned (a positive-assurance result).** EIP-2780/
7976/8037/8038 move ~21 gas constants. Reverting each repriced constant to
its Osaka value in EELS and re-running the conformance fills killed every
directly-expressed one (9/9 testable; the rest are *derived* expressions
like `AUTH_BASE = 23 * COST_PER_STATE_BYTE`, not flat literals — a confirmed
limitation of value-diff mapping manifest totals back to spec source). So if
a client ships an old price, `fill` catches it. The differential also caught
a *real* stale-client drift: an older geth build diverged on 50/50 cases with
a gas fingerprint localizing to the EIP-2780 commits; a fresh master build
agreed 10,000/10,000 (BAL hash included).

**BAL semantics were a real gap (a coverage-win result).** EIP-7928's
`block_access_lists.py` builder — canonical ordering, per-index dedup,
read/write exclusion, net-zero filtering — is consensus-critical, brand new,
and had *no* property coverage; fills only ever see the aggregate BAL hash,
not these internal rules. Full-module mutation baseline with the existing
suite as oracle: **5/21 (24%)**. A `/mine-properties` agent (EIP mode, ground
in EIP-7928 prose + docstrings) produced a model-based reference machine plus
14 grounded properties; independently re-measured, the kill score rose to
**19/21 (90%)**, a **+14 kill-delta**. The 2 residual survivors are provably
equivalent mutants (`>`→`>=` on a nonce comparison that only differs when the
values are equal — writing the same value either way; and a `//`→`*` inside
an exception *message* f-string, not the accept/reject comparison). Tests in
`tests_property/test_eip7928_bal.py`; amsterdam-only, skip-guarded on osaka.

This is the clearest single demonstration of the thesis: fills answer "does
the client match the frozen answer"; mutation + property mining answer "does
any test even distinguish this spec from a subtly wrong one" — and for a new
data structure the answer was mostly no, until it wasn't.

## Cross-client differential (landed)

`uv run fuzz-differential --fork Osaka --evm-bin <path> --count N
[--corpus DIR]` runs each generated case through EELS in-process *and* a
client transition tool (geth's `evm`), then compares the transition
results field by field — state root, receipts root, logs hash, gas used,
withdrawals/blob/requests/BAL hashes, and the rejected-transaction set.
Any disagreement, or one tool failing where the other succeeds, is a
finding: on adversarial input two implementations that must agree do
not. Divergences are delta-debug minimized and saved to the corpus.

This is the only layer that catches *self-consistent* spec bugs — a
mispriced gas constant, say — that relational properties and
single-operator mutation testing both miss, because a wrong-but-coherent
EELS agrees with itself. A client that computes the value differently
does not.

Verified end-to-end against geth (`evm` built from source):

- clean run: 30/30 generated Osaka cases agree, ~5 cases/s including the
  client subprocess;
- with a +1-wei coinbase bug injected into EELS only, every case
  diverges on `state_root` (EELS root vs geth root both printed), and
  minimizes to 1 transaction / 2 accounts.

The comparison is client-agnostic (any `TransitionTool`); geth is the
first wired client because its `evm t8n` is readily built.

**Throughput.** Each seed is independent, so `fuzz-differential -j N`
runs them across worker processes, each building EELS and the client
tool once. Output order stays deterministic regardless of worker count,
and minimization of divergent cases runs in the main process. Measured
on a 16-core machine: 100 seeds went 17.8s → 4.3s (`-j 8`), and 500
seeds run at ~48 cases/s (`-j 12`) versus ~5.6 serial — roughly an
8–9× wall-clock win once worker startup amortizes. Parallel divergence
detection was verified with an injected EELS bug: workers re-import the
mutated spec and all cases diverge and minimize correctly.

Parallelism raises the EELS-in-loop ceiling by the core count; the next
order-of-magnitude still needs the tiered model in the north star
(native clients pre-filter at high throughput, EELS adjudicates only
flagged cases), which in turn needs a second native client wired in to
form a real pre-filter.

## Generator coverage: reaching the divergence-prone surface (landed)

A differential harness is only as good as where its generator aims. The
v1 generator produced legacy transactions into pre-deployed contracts
running arithmetic / memory / SSTORE / env-read opcodes — the legacy
interpreter core. That surface has been stable for years, so a large
clean run there is *reassuring but low-information*: it re-confirms the
least-likely-to-diverge part and, critically, never issues a `CALL`, so
it cannot reach a single precompile — the densest source of cross-client
divergence (input parsing, gas schedules, the address-range boundary).

Measured: 3050 Osaka cases agreed 3050/3050 (v1). Expected, and weak
signal.

**v2 — precompile coverage.** `fuzzed_bytecode` gained an optional
`precompiles=` argument; when supplied it injects stack-neutral
`STATICCALL`s into the fork's precompiles (drawn from `fork.precompiles()`,
so it auto-tracks every fork), with fuzzed input, one guaranteed call per
contract body, and an occasional `max+1` target to probe the range
boundary. Each call `SSTORE`s its success flag and returndata size as
post-state witnesses, so an output/success divergence surfaces in the
state diff (gas divergence is already caught globally). `GENERATOR_VERSION`
1→2. Proven with teeth, not just a null result: an injected +1-word
`identity` gas bug diverges (`gas_used`, then `state_root`/`receipts_root`)
within 300 cases — a precompile consensus bug v1 could not observe; 5300
clean cases otherwise agree 5300/5300.

**v3 — manifest-driven targeting.** This is where the change manifest
earns its keep: it is not only a covariant test source, it is a *targeting
system for the fuzzer*. `eip_properties.targeting` reads the manifest's
`PRECOMPILE_ADDED` changes for a fork versus its parent, maps them back to
concrete addresses, and up-weights those in the generator's target list. A
fork's freshly-added precompiles — p256verify (`0x100`) in Osaka, the BLS
range (`0x0b`–`0x11`) in Prague — are where a new consensus bug hides;
decade-old ecrecover is not. For Osaka this lifts `0x100`'s share of
precompile calls from ~5.6% (uniform) to ~18.5%. `GENERATOR_VERSION` 2→3.
Proven: a gas bug injected into the *newly-added* p256verify diverges
within 100 cases; 1000 clean cases otherwise agree.

The general lesson: the harness was sound; the generator was the
bottleneck on usefulness, and the manifest is the layer that decides where
to point the strongest (cross-client) oracle. The next surfaces, in
descending divergence-likelihood, are typed transactions (1559 /
access-list / blob / set-code), `CALL`/`CREATE` families, and
`SELFDESTRUCT`/`LOG`/`EXTCODE*` — each reachable the same way, and each a
candidate for manifest-driven targeting (`OPCODE_ADDED`, `GAS_CONSTANT`,
`FORMULA_CHANGED`).

## Distillation to reviewable tests (landed)

`uv run fuzz-distill <case.json> <out.py>` turns a corpus case (the
minimized `FuzzerOutput` a `fuzz` or `fuzz-differential` run saved) into a
readable `BlockchainTestFiller` module: explicit `EOA(key=…)` senders, an
`Alloc` of exact accounts and contract code, the transactions, and a
provenance docstring (fork, generator version, seed, why it was
interesting). `post` is left empty for the reviewer to fill with explicit
expectations before the test is landed.

This closes the lifecycle that makes findings permanent — the repo's crown
jewel is that a frozen fixture is a forever cross-client regression test:

```
fuzz / fuzz-differential  →  minimized corpus JSON
        →  fuzz-distill    →  reviewable BlockchainTestFiller .py
        →  fill            →  canonical fixtures every client consumes
```

The rendering is deliberately faithful (exact addresses/keys/code/values,
via controlled codegen — EEST type `repr()` does not round-trip) rather
than idiomatic, because the distilled test must reproduce the original
execution. It reuses `gentest`'s template rendering and ruff formatting.

Verified end-to-end: a geth-vs-EELS `state_root` divergence was distilled
to a Python test and then *filled* successfully by the reference spec,
proving the distilled case is valid and reproduces. (Note: ddmin had
stripped the contract's code, since the divergence rode on the fee payment,
not the code — the distilled test is a minimal value transfer, exactly the
minimized case.)

## In-file fuzz authoring (landed)

The north star's "one authoring artifact, two execution modes" now has a
concrete surface: a public strategy library, `execution_testing.fuzzing`,
exposing `fuzzed_bytecode(rng)` and `fuzzed_calldata(rng)` — the same
stack-aware helpers the generator uses. A test author writes an ordinary
seed-parametrized test in the normal idiom:

```python
@pytest.mark.valid_from("Osaka")
@pytest.mark.parametrize("seed", range(8))
def test_fuzzed_contract_execution(state_test, pre, seed):
    rng = random.Random(seed)
    contract = pre.deploy_contract(code=fuzzed_bytecode(rng))
    sender = pre.fund_eoa()
    tx = Transaction(sender=sender, to=contract, gas_limit=1_000_000,
                     data=fuzzed_calldata(rng))
    state_test(env=Environment(), pre=pre, post={}, tx=tx)  # EELS fills post
```

`post={}` embodies the governing principle: the author chooses inputs, the
reference spec computes the expected state, and `--invariant-checks`
validates it. Under `fill` this is a plain parametrized test — N seeds fill
N deterministic fixtures that clients then consume (differential by
consumption); under a fuzzing service the identical artifact is driven over
an unbounded seed range. No new test-runner machinery was needed: it reuses
`StateTest`, the `pre` fixture's `deploy_contract`/`fund_eoa`, the existing
formats, and the invariant checker. The generator was refactored to draw
from the same library, so authors and the generator never drift.

Verified: an example suite (`tests/fuzzing/test_fuzzed_execution.py`) fills
8 seeds × 3 formats = 24 fixtures, invariant-clean.

## EIP change manifest — deriving what to test from the fork (landed, prototype)

A redesign insight for the agent era: the fork object is *already* a
machine-readable description of the protocol (the `BaseFork` predicate
surface + `GasCosts` + opcode/system-contract sets + the calculator methods
each EIP mixin overrides). The repo's pre-AI gap was that nothing consumed it
as one — the testing checklist was authored as prose *beside* the code rather
than *derived from* it, creating two sources of truth that drift.

`execution_testing.eip_properties.manifest` closes that: `uv run eip-manifest
--from Osaka --to Amsterdam` diffs two forks and derives an EIP-attributed,
classified change manifest via three detectors:

- **value-diff** — scalars, `GasCosts` fields, opcode/system-contract/
  precompile sets. Complete over everything parameterized by value.
- **override-diff** — calculator/formula methods a *new* EIP mixin overrides
  (pricing / state-transition logic a value cannot capture), attributed to
  the mixin that defines them.
- source-diff — pure logic behind no fork method; left to the agent.

Each change is classified (`bound_added`, `gas_constant`, `opcode_added`,
`feature_enabled`, `formula_changed`, …) and mapped to the checklist
section(s) it implies, so the required-test surface is **derived, not
hand-copied**. Verified on real forks:

- Prague→Osaka surfaces `transaction_gas_limit_cap: None → 16777216`,
  attributed to **EIP-7825**, classified `bound_added` → *New
  Transaction-Validity Constraint* — exactly the kind of subtle bounded-
  quantity change a coarse taxonomy would miss.
- Osaka→Amsterdam: 68 changes across 11 EIPs — 19 individual `GasCosts`
  constants, 4 new opcodes, 2 system contracts, EIP-8037's state-gas
  calculators — deriving 5 checklist sections that are a subset of the real
  16.

This is the foundation the archetype layer and the change-type-aware mining
agent consume: the manifest says *what* changed and *which EIP*; archetypes
say *how to test* each kind; the agent's brief is manifest + archetype + EIP
text.

**Prototype limits (honest):** `GasCosts`/opcode changes attribute to the
*candidate set* of new EIP mixins overriding the producing method (e.g. all
five EIPs that override `gas_costs`), not the exact constant→EIP mapping —
precise per-field attribution needs incremental MRO application. Some
fork-level values (blob params) change without a new mixin override and land
"unattributed". The kind→section map is coarse (blob-count changes currently
fall under a generic constraint section). All refinements, not blockers.

## Property archetypes, keyed to change kind (design)

The manifest says *what* changed; an **archetype** says *how to test* each
kind. Archetypes are written once and sourced from the fork diff (see the
covariant-source note below), so they never need per-fork rewriting.

**The load-bearing finding: the fork surface cannot test itself.** A property
derived from the fork's own parameters and asserted back against those same
parameters is circular — "Amsterdam's `TX_BASE` is 12000" is read *from* the
fork, so asserting it proves nothing. A non-circular conformance property
needs an **oracle from outside the fork surface**. There are only four:

- **parent fork** — the cross-fork differential (behavior differs from the
  prior fork only on the changed surface);
- **another client** — the cross-client differential we built (EELS vs geth);
- **the EIP text / spec prose** — an agent reads intent and grounds an
  assertion (the paper's approach);
- **end-to-end execution presence** — fill a block and observe the plumbing
  (mildly circular, but confirms wiring, not just declaration).

So the manifest is a **targeting system, not an oracle.** It tells you what
changed and where to look; the judgment of correctness comes from one of the
oracles above. That reshapes archetypes into three tiers by oracle:

| Change kind | Tier | Oracle | Property shape | Altitude | Agent? |
| --- | --- | --- | --- | --- | --- |
| `gas_constant`, `formula_changed`, `value_changed` | Differential | parent fork / client | behavior differs from parent only where the changed surface is exercised | transition | no |
| `feature_enabled/disabled` | Structural | execution presence | field/behavior absent before the fork, present after; header commits to it | transition | no |
| `opcode_added/removed` (validity) | Structural | execution presence | undefined/invalid before, valid after (not its semantics) | transition | no |
| `system_contract_added`, `precompile_added/removed` (presence) | Structural | execution presence | pre-deployed/callable at/after fork, absent before | transition | no |
| `version_bump` | Structural | execution presence | engine API accepts the new version after fork | transition | no |
| `bound_added`, `limit_changed` | Assertion | EIP text / spec | exact boundary (`>` vs `>=`), failure class (invalid-tx vs OOG), interactions | transition + standing | **yes** |
| `opcode_added`, `precompile_added`, `system_contract_added` (semantics) | Assertion | EIP text / spec | what the opcode/precompile/contract *does* | transition + standing | **yes** |

Two consequences that were not obvious before:

- The **differential tier needs no baked-in assertion** and no agent — it
  reuses the cross-client engine we built and the cross-fork engine (gap 5,
  still to build). It is the safest backbone and adheres to the governing
  principle (no hand-authored expectations).
- The **assertion tier is exactly where the paper's agent belongs** — the
  gas-limit cap showed a generic template would likely get `>` vs `>=`, the
  failure class, and the framework-method-vs-spec-constant relationship
  wrong. Those assertions must be spec-grounded and self-triaged, not
  templated.

**Transition vs standing.** A transition property holds at the boundary
(rejected before, accepted after); a standing property holds at every fork
where the change is active (the cap stays enforced). These are two covariant
sources over the manifest — `with_each_new_*` (at introduction) and
`with_each_active_*` (all forks where active) — both cheap.

### `diff_forks` as a covariant source, not test-body code

The framework already parametrizes a single test from fork-derived values:
`with_all_precompiles` reads `fork.precompiles()` at fill time and generates
one case per precompile (`plugins/forks/forks.py`, `covariant_decorator`).
Those markers are *state*-covariant (what the fork *has*). The manifest adds a
*change*-covariant axis (what the fork *changed* vs its parent). So the
production home for archetypes is a manifest-sourced covariant decorator —
`diff_forks` runs once in the parametrization layer, and archetype bodies are
fork-agnostic and permanent.

**Landed:** `with_each_change(kind)` in `eip_properties.covariant`. It sources
`(parent, child, change)` cases from `diff_forks` across **every adjacent
fork pair** (`adjacent_fork_pairs()`, from `get_forks()`), so one archetype
body covers every transition — and a newly added fork joins automatically,
with zero test edits. Verified: the observability archetype expands to 47
cases spanning Frontier→Homestead through Prague→Osaka from a single function.

This deliberately lives in the pure-property layer (`pytest.mark.parametrize`
over fork pairs), which needs no fill machinery and, because cases are
collected across pairs, has no "this fork lacks the change kind" edge case.
Archetypes needing full block execution graduate to a fill-side covariant
marker — that path needs one shared-infra decision (the fill-side
`covariant_decorator` asserts a non-empty value list, so it would *error*
rather than *skip* on a fork without the change kind; graduation means adding
empty→skip semantics). Deferred deliberately rather than rushed.

### Keeping three things top of mind (per the design intent)

- **Agent test-writing flow.** An agent writing an archetype does not pick
  forks or enumerate changes. It: (1) picks a `ChangeKind` from the manifest;
  (2) decides the oracle tier (differential / structural / assertion); (3)
  writes one `@with_each_change(kind)` body; (4) for the assertion tier,
  grounds the exact claim in the EIP text / spec line and self-triages (the
  paper's loop). The framework supplies the cases; the agent supplies the
  judgment where — and only where — it is needed.
- **Scope / surface.** Change-covariant coverage scales with the fork's
  *declared* surface (predicates, `GasCosts`, opcode/system-contract sets,
  overridden calculators). It is complete over that surface by construction,
  and blind to changes expressed only in un-parameterized spec logic — the
  residue the source-diff + agent must cover. Stating that boundary explicitly
  is how we avoid a false sense of completeness.
- **Fidelity.** The load-bearing rule stands: the fork surface cannot be its
  own oracle. Assumption-free archetypes (differential, structural,
  observability) are safe to templatize; assertion-bearing archetypes must be
  agent-grounded and triaged, never templated — a template would get the
  gas-limit-cap boundary and failure-class wrong, and a wrong canonical
  fixture is worse than a missing one.

## Honest limits

- **EELS throughput bounds in-process fuzzing.** The design answer is
  architectural, not heroic: EELS adjudicates only what the native tier
  flags or what strategy-level guidance requests.
- **Determinism is a generation-time discipline.** Every generated fixture
  must be regenerable: pinned seed + strategy version + spec commit
  recorded in fixture `_info`. Shrinking replays from the recorded seed,
  never re-searches.
- **False positives are asymmetric.** Nothing freezes without cross-client
  green consume and human review; rubric-ranked queues concentrate review
  attention where measured validity is highest.
- **Maintainer bandwidth is the hard ceiling.** The pipeline must throttle
  itself to the review budget; the corpus and dashboard hold the long tail.
- **Property quality risk.** Mined properties must cite the spec
  function/line they constrain; wrong properties then fail loudly during
  self-reflection rather than silently shaping the suite.
