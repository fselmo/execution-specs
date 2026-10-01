# BAL execution interface for client test runners

Shared interface for each client's block-test (block import) and engine-test (Engine API) runners, agreed 2026-10-01 for the LCC2 upstreaming work. A node's own behavior and defaults do not change.

The end goal is full standardization of these runners across clients: the same commands, flags, results and reports everywhere. These PRs are the first step.

## Command names

Every client exposes its runners as `blocktest`, `enginetest` and `statetest`, as a subcommand or the client's nearest equivalent. Where a client uses another name today, the standard name is added as an alias and the old one keeps working. `statetest` is naming only in this round; nothing else about it changes.

## 0. Engine-test drives the real Engine API handler

Engine-test runs the client's own Engine API handler in-process. Each payload goes through the code that serves `engine_newPayloadV<n>`, and each forkchoice update through the code that serves `engine_forkchoiceUpdatedV<n>`, at the versions the fixture names (`newPayloadVersion`, `forkchoiceUpdatedVersion`). The runner may not copy or re-implement the handler, its version checks or the validator, and may not swap a mock provider or executor for the node's own. The payload's access list reaches the validator exactly as it would from the wire. A runner that bypasses any of this can pass while the node fails.

| Client | Payload at fixture version | Forkchoice at fixture version | Real handler and validator |
|---|---|---|---|
| reth | to do: new runner | to do | to do |
| geth | to do: replace #34650's handler copy with `ConsensusAPI` | to do | to do |
| besu | `EngineNewPayloadV5` | to check | to check: `EvmToolMergeCoordinator` |
| nethermind | `engine_newPayloadV<n>`, raw params | to check | yes for payloads |
| ethrex | `handle_new_payload_v4` via the RPC layer | to check | to check |
| erigon | engine_x tester's in-process node | to check | yes (full node) |

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
