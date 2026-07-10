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
Later: mutation testing of EELS ("does any fixture kill this mutant of the
gas formula?") — a much stronger metric than branch coverage.

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
| 3 | Differential harness, EELS vs. client t8ns (gap 4) | 2 | M–L | nightly run, dedup'd divergence report |
| 4 | Coverage feedback + corpus distillation (gap 6) | 2, 3 | M | distilled corpus + gap report |
| 5 | Distillation → canonical fixtures (gap 7) | 2, 3 | M | first fuzz-found frozen fixture PR |
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
