# BAL execution interface for client test runners

Shared interface for each client's block-test (block import) and engine-test (Engine API) runners, agreed 2026-10-01 for the LCC2 upstreaming work. A node's own behavior and defaults do not change.

The end goal is full standardization of these runners across clients: the same commands, flags, results and reports everywhere. These PRs are the first step.

## Command names

Every client exposes its runners as `blocktest`, `enginetest` and `statetest`, as a subcommand or the client's nearest equivalent. Where a client uses another name today, the standard name is added as an alias and the old one keeps working. `statetest` is naming only in this round; nothing else about it changes.

## 0. Engine-test drives the real Engine API handler, and nothing else

Engine-test calls the client's own Engine API handler: the code that serves `engine_newPayloadV<n>` and `engine_forkchoiceUpdatedV<n>`, at the versions the fixture names (`newPayloadVersion`, `forkchoiceUpdatedVersion`). The fixture's params are decoded with the client's own decoder, so the access list reaches the validator as it would from the wire.

- **Required:** the client's real handler, version checks, payload validator and engine tree (or execution module) run. Nothing is copied or re-implemented, and nothing is replaced with a mock provider or a direct executor call.
- **Not allowed:** starting a node per fixture, and any RPC server, HTTP, JWT or networking. Payloads and forkchoice updates go straight to the handler as function calls.
- **Lifetime:** one handler instance per runner process (per worker), reused across fixtures, with fresh in-memory or temporary state for each fixture.

A runner that bypasses the real handler can pass while the node fails; a runner that starts a node per fixture is too slow and heavy to run campaigns through.

| Client | Reaches the handler by | Started per fixture | ms per fixture (500-fixture engine batch, 1 worker) | Payload and forkchoice at fixture version | Real validator and engine tree |
|---|---|---|---|---|---|
| reth | node (`lcc2/ef-tests-engine-runner`); v2 to do | a full `EthereumNode`, auth RPC server, temp MDBX datadir | 580 (42 with the datadir on a RAM disk) | yes (`engine_api.rs:270`, `:348-452`); forkchoice version only checks payload attributes | yes |
| geth | in-process RPC to `ConsensusAPI`; to re-check | an in-memory node with an `eth.New` backend (`cmd/evm/enginerunner.go:247-290`) | 34 | yes (`tests/engine_test_util.go:186`, `:259`); forkchoice version only checks payload attributes | yes |
| besu | `EngineNewPayloadV1..V5` / `EngineForkchoiceUpdatedV1..V4` method objects; to re-check | to check | to measure | yes (`EngineTestSubCommand.java:665`, `:633`, `:777`); anything but VALID fails | yes, the node's `MergeCoordinator` (`:487-517`) |
| nethermind | in-process RPC through `IJsonRpcService` to `EngineRpcModule`; to re-check | to check | 150 | yes (`BlockchainTestBase.cs:462`, `:464`, `:805`); head = safe = finalized | yes; MemDb, timestamper and tx pool are test doubles |
| ethrex | in-process RPC dispatch through `map_engine_requests`; to re-check | to check (`RpcApiContext`, `Blockchain`) | to measure | yes (`harness.rs:147`, `:141`); forkchoice version only checks payload attributes | yes |
| erigon | to do | to do (the engine_x tester starts a full node with an engine API port, so it is not the base) | to measure | to do | to do |

## 1. Block-test delivers the access list

Block-test attaches the fixture block's access list to the block before import: `blockAccessList`, or `rlp_decoded.blockAccessList` for an expected-invalid block. The client then validates it as it would a delivered list.

## 2. Execution switch

One setting with two values on both runners: `parallel` (the default) and `sequential`.

- `parallel`: the client's BAL-driven parallel executor runs every block that has an access list.
- `sequential`: the client's sequential executor runs every block.
- Both modes validate the delivered access list against execution and the header hash. The switch chooses the executor, never whether the list is checked.

Each client spells it in its own CLI style, reusing a flag the client already has:

| Client | Spelling |
|---|---|
| reth | `--engine.disable-bal-parallel-execution` (the node flag) |
| geth | `--bal.sequential` |
| besu | `--bal-sequential` |
| nethermind | `--parallelExecution false` (exists; default from config, true) |
| ethrex | `--no-bal-parallel-exec` (the node flag) |
| erigon | `--exec.serial` (the node flag's name; maps to one worker, never to the unvalidated serial executor) |

## 3. Decision report

One line per executed block on stderr: a single-line JSON object, written at the point where the client chooses the path.

```json
{"event":"balExecution","block":12,"hash":"0x…","path":"sequential","reason":"disabled"}
```

- `path` is `parallel` or `sequential`: the executor that actually ran the block.
- `reason` is empty for `parallel`. For `sequential` it is the first condition, in the client's own gate order, that ruled parallel out. Shared values: `disabled` (the switch), `no-access-list`, `pre-amsterdam`. A client-specific condition uses its own lowercase name, such as `tracer`, `witness` or `single-worker`.
- Genesis, and blocks rejected before execution, print nothing.
- A client may add fields of its own; consumers ignore keys they do not know. Besu adds `scheduler` (`bal` or `optimistic`), because without an access list it runs its optimistic parallel scheduler, which is neither BAL-driven nor sequential.

## 4. Fallback report

Where a client re-runs a block sequentially after its parallel executor failed (today nethermind and besu), one more line for that block:

```json
{"event":"balFallback","block":12,"hash":"0x…","parallelError":"…","sequentialResult":"invalid","sequentialError":"…"}
```

`sequentialResult` is `valid` or `invalid`, and `sequentialError` is empty when valid. The block's verdict in the runner's results stays the sequential one, as today.

## Output and wiring

- stdout carries only the runner's JSON results, whose format does not change. Both events go to stderr.
- Optional, low priority: an output-format flag offering JSONL (one result object per line) beside the default JSON array. A client adds it only where it takes a few lines.
- A node never prints these lines. The runner turns them on, by a callback it installs or a logger it enables, whichever fits the client.
- Under `--workers`, lines from different fixtures interleave; `hash` ties each line to its block.

## Future work: decisions in execution traces

The two events stay separate stderr lines for now. Later they may fold into the clients' execution traces. Each line is a self-contained object (camelCase keys, `event` naming its kind, `block` and `hash` identifying the block, nothing that depends on its position in a stream), so it can become a trace record or field with the same content.

## Verification, per client

Before a branch is pushed: a corrupted delivered access list is rejected; decision lines read `parallel` by default and `sequential`/`disabled` under the switch; where the client falls back, a forced parallel failure prints a `balFallback` line; the client's own tests for each touched package pass.
