# BAL execution interface for client test runners

Shared interface for each client's block-test (block import) and engine-test (Engine API) runners, agreed 2026-10-01 for the LCC2 upstreaming work. A node's own behavior and defaults do not change.

The end goal is full standardization of these runners across clients: the same commands, flags, results and reports everywhere. These PRs are the first step.

## Command names

Every client exposes its runners as `blocktest`, `enginetest` and `statetest`, as a subcommand or the client's nearest equivalent. Where a client uses another name today, the standard name is added as an alias and the old one keeps working. `statetest` is naming only in this round; nothing else about it changes.

Every runner binary answers `--version` with one line on stdout that names the client and the tool, and exits 0. Tools that already have one keep it (`evm version …`, `Besu evm …`, nethtest's). A new binary names itself `<client>-<runner>`: ethrex's are `ethrex-blocktest`, `ethrex-enginetest` and `ethrex-statetest`, and reth's runner stays `ef-test-runner`. Harnesses identify a runner by that line.

## 0. Engine-test drives the real Engine API handler, and nothing else

Engine-test calls the client's own Engine API handler: the code that serves `engine_newPayloadV<n>` and `engine_forkchoiceUpdatedV<n>`, at the versions the fixture names (`newPayloadVersion`, `forkchoiceUpdatedVersion`). The fixture's params are decoded with the client's own decoder, so the access list reaches the validator as it would from the wire.

- **Required:** the client's real handler, version checks, payload validator and engine tree (or execution module) run. Nothing is copied or re-implemented, and nothing is replaced with a mock provider or a direct executor call.
- **Allowed, and preferred where the parameter and version checks live there:** calling the client's engine RPC methods in-process, through its own method dispatch (for example nethermind's `IJsonRpcService`, geth's RPC method layer, ethrex's request dispatch), or calling the handler's methods directly.
- **Not allowed:** an RPC server, any transport (HTTP, IPC, WebSocket), JWT, networking, and anything node-level started per fixture.
- **Lifetime:** reuse the handler per runner process (per worker) where the client allows it, with fresh in-memory or temporary state for each fixture. Where the handler is bound to one chain or genesis (geth's `ConsensusAPI`), or carries per-chain caches such as invalid blocks, build the minimum per fixture instead: a fresh chain, the backend the handler needs, and the handler, with no node services.

A runner that bypasses the real handler can pass while the node fails; a runner that starts a node per fixture is too slow and heavy to run campaigns through.

Timings: the 500-fixture engine batch at one worker, median of three runs on an M-series Mac under light load, 2026-10-01.

| Client | Reaches the handler by (direct call, in-process dispatch, or server) | Handler lifetime (per worker, or minimum per fixture) | Started per fixture | ms per fixture (500-fixture engine batch, 1 worker) | Payload and forkchoice at fixture version | Real validator and engine tree |
|---|---|---|---|---|---|---|
| reth | in-process dispatch: `EngineApi`'s JSON-RPC method table (`into_rpc()`, `RpcModule::raw_json_request`) (`lcc2/ef-tests-engine-runner-v2`) | per fixture: `EngineApi` and the engine tree are bound to one provider, and each fixture has its own genesis and database | state plus the handler: a temp datadir (MDBX on `safe-no-sync`, static files, RocksDB) with genesis under `--datadir-root`, `BlockchainProvider`, `BasicEngineValidator`, the persistence and engine-tree threads, `EngineApi`, and a small runtime; no-op payload builder, txpool, network and downloader, none reached by newPayload or attribute-less forkchoice; no node, server, JWT or networking | 482 on disk, 33 with `--datadir-root` on a RAM disk | yes (`engine_api.rs:270`, `:348-452`); forkchoice version only checks payload attributes | yes: `BasicEngineValidator` and the engine tree |
| geth | in-process dispatch to `ConsensusAPI` (`lcc2/enginetest-bal-v2`; `tests/engine_test_util.go:221`, `:294`) | minimum per fixture: `ConsensusAPI` is bound to one chain and caches invalid blocks | state plus the handler: a fresh in-memory `core.BlockChain`, `eth.NewEngineBackend` (chain, database, idle downloader), `ConsensusAPI` and the in-process dispatcher; no node, P2P, txpool, miner or log index. A geth chain cannot change genesis, so the handler is rebuilt with it | 4.2 (state in memory) | yes (`ConsensusAPI.NewPayloadV1..V5`, `ForkchoiceUpdatedV1..V4`); forkchoice version only checks payload attributes | yes: `InsertBlockWithoutSetHead` on a real chain |
| besu | direct call: `syncResponse` on the `EngineNewPayloadV1..V5` / `EngineForkchoiceUpdatedV1..V4` method objects (`lcc2/bal-runner-interface-v2`) | minimum per fixture: `MergeCoordinator` and the method objects are rebuilt on each fixture's blockchain | state only: blockchain, in-memory Bonsai world state and protocol context, `MergeCoordinator`, method objects; no threads or services (Vert.x, scheduler, peers, metrics are per process) | 4.2 after JIT warm-up (state in memory) | yes (`EngineTestSubCommand.java:665`, `:633`, `:777`); anything but VALID fails | yes, the node's `MergeCoordinator` |
| nethermind | in-process dispatch through `IJsonRpcService` to `EngineRpcModule`; the engine `RpcModuleProvider` is built once per process (`lcc2/bal-runner-interface-v2`) | minimum per fixture: `EngineRpcModule` and its caches live in the same container as the block tree and databases, with no reset | a DI container with in-memory databases, block tree, world state, `EngineRpcModule` and its handlers, the block-processing thread and an idle payload-cleanup timer; no RPC server, transport, JWT or networking | 29 (state in memory) | yes (`BlockchainTestBase.cs:462`, `:464`, `:805`); head = safe = finalized | yes; MemDb, timestamper and tx pool are test doubles |
| ethrex | in-process dispatch through `map_engine_requests` (`lcc2/ef-tests-runners-v2`; `tooling/ef_tests/engine/src/harness.rs:108`, `crates/networking/rpc/rpc.rs:1541-1562`) | mixed: dispatch, node identity and namespaces per worker; store and `Blockchain` per fixture | state only: an in-memory store with genesis, its `Blockchain` and that chain's block executor thread; node identity, gas tip estimator and namespaces are per worker, the syncer per process with its peer-lookup loop shut down; no server, transport or sockets | 4.7 (state in memory) | yes (`harness.rs:147`, `:141`); forkchoice version only checks payload attributes | yes: the node's executor and `add_block_pipeline` |
| erigon | direct call: `EngineServer.NewPayloadV1..V5` / `ForkchoiceUpdatedV1..V4`, the methods the RPC layer serves (`lcc2/enginetest-bal-v2`; `execution/tests/testutil/engine_test_util.go:135-143`, `:173-179`) | minimum per fixture: `EngineServer` binds its exec module and chain config at construction (`engine_server.go:100-133`) | state plus the handler: a temp dir and MDBX database, the exec module and staged sync, an in-process direct sentry, and the `EngineServer` struct; no node, RPC server, port, JWT or networking | 90 on disk, 18 with TMPDIR on a RAM disk | yes; forkchoice version only checks payload attributes (`engine_server.go:219`, `:242`) | yes: the fixture's `ExecModule` |

## 1. Block-test delivers the access list

Block-test attaches the fixture block's access list to the block before import: `blockAccessList`, or `rlp_decoded.blockAccessList` for an expected-invalid block.

On this path the list is delivered beside the block, not as part of it. A delivered list that does not match the header's `blockAccessListHash` is a bad list, not an invalid block: the client must not use it, and should fall back to computing the list itself. The block's validity comes from the header alone, so a block whose only fault is its delivered list is a valid block on the import path.

The runner handles the delivered list the way the client's own sync handles a list from a peer: it hashes the list as delivered (its RLP in the order given, not a sorted or normalized copy) and compares that with the header's `blockAccessListHash`. On a match it attaches the list, even when the client then finds the list malformed (out of order, duplicated, undecodable): the header commits to that list, so the client judges the block with it and rejects it, as it would on the engine path. Only when the hash does not match, or the list cannot be encoded at all to compute one, does the runner drop the list; the block then executes without one, and the decision line reports it (§3). On the shared corpus this drops exactly one EEST block, `test_bal_invalid_hash_mismatch`, in every client.

## 2. Execution switch

One setting with two values on both runners: `parallel` (the default) and `sequential`.

- `parallel`: the client's BAL-driven parallel executor runs every block that has an access list.
- `sequential`: the client's sequential executor runs every block.
- On the engine path the access list is part of the payload, and the header commits to it: a list that does not match the block's execution makes the payload INVALID, in either mode.
- On the import path (§1), a delivered list that does not match the header's commitment is dropped by the runner, in either mode, and the block is judged on its header.
- The switch chooses the executor, never how the list is judged.

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

With `--bal-report`, one line per executed block on stderr: a single-line JSON object, written at the point where the client chooses the path.

```json
{"event":"balExecution","block":12,"hash":"0x…","path":"sequential","reason":"disabled"}
```

- `path` is `parallel` or `sequential`: the executor that actually ran the block.
- `reason` is `bad-access-list` whenever the runner dropped the block's delivered list (§1), whatever path the block then took: on a `parallel` line, and under the switch, it takes precedence over every other reason. `path` (and `scheduler`, where present) still says what ran, and the switch is known from the run's own flags.
- Otherwise `reason` is empty for `parallel`. For `sequential` it is the first condition, in the client's own gate order, that ruled parallel out. Shared values: `disabled` (the switch), `no-access-list` (none was delivered), `pre-amsterdam`. A client-specific condition uses its own lowercase name, such as `tracer`, `witness` or `single-worker`.
- Genesis, and blocks rejected before execution, print nothing.
- A client may add fields of its own; consumers ignore keys they do not know. Besu and erigon add `scheduler` (`bal` or `optimistic`), because without an access list they still run the block in parallel, which is neither BAL-driven nor sequential. For them a dropped list shows as `path` `parallel`, `scheduler` `optimistic` and `reason` `bad-access-list`.

## 4. Fallback report

Where a client re-runs a block sequentially after its parallel executor failed (today nethermind and besu), one more line for that block:

```json
{"event":"balFallback","block":12,"hash":"0x…","parallelError":"…","sequentialResult":"invalid","sequentialError":"…"}
```

`sequentialResult` is `valid` or `invalid`, and `sequentialError` is empty when valid. The block's verdict in the runner's results stays the sequential one, as today.

A block that falls back prints exactly two lines: its `balExecution` line with `path` `parallel`, then the `balFallback` line. The sequential re-run does not print a second `balExecution` line.

## 5. Expected exceptions

When a fixture names an expected exception (`expectException` on a block, or the payload's `validationError`), the runner checks that the client rejected the block for that reason, not only that it rejected it. The match uses the client's own mapping from its errors to the fixture's exception names, the one `consume` uses for that client, and a fixture may list several names separated by `|`, any of which matches. A block rejected for a different reason fails the fixture, with both the expected and the actual reason in its result. A client error that maps to no name fails too, so the mapping stays complete. One exception: a block that fails to decode at all counts as rejected without a reason check, as nethermind, geth, besu's reference tests and hive's consume-rlp already treat it, because no client mapping (EEST's included) names decoder errors.

Where a client's own CI pins fixtures that would fail the check for fixture reasons, the check may ship behind an opt-in flag, off by default, until EEST fixes those fixtures and the pin moves. Today that applies to nethermind's block-test path: its CI pins `tests@v21.0.0`, where 7 fixtures name the engine-path reason and 43 have two defects but one expected name.

## Output and wiring

- stdout carries only the runner's JSON results, whose format does not change. Both events go to stderr.
- Optional, low priority: an output-format flag offering JSONL (one result object per line) beside the default JSON array. A client adds it only where it takes a few lines.
- **`--bal-report`**, spelled the same in every client, turns both events on, on both runners. Off by default: without it the runners print neither event and their stderr is as before. A node never prints these lines; with the flag, the runner turns them on by a callback it installs or a logger it enables, whichever fits the client.
- Under `--workers`, lines from different fixtures interleave; `hash` ties each line to its block.

## Runner notes

- To cap CPU, use the runner's `--workers` and run it under `nice`. Do not set `DOTNET_PROCESSOR_COUNT` (or `DOTNET_GCHeapCount`) for nethtest: at 4 it crashed nethtest at random with a SIGBUS in .NET's background garbage collector.

## Future work: decisions in execution traces

The two events stay separate stderr lines for now. Later they may fold into the clients' execution traces. Each line is a self-contained object (camelCase keys, `event` naming its kind, `block` and `hash` identifying the block, nothing that depends on its position in a stream), so it can become a trace record or field with the same content.

## Verification, per client

Before a branch is pushed: on the engine path, a payload with a corrupted access list is INVALID in both modes; on the import path, a delivered list that does not match the header is not used and the block's verdict follows its header, in both modes; decision lines read `parallel` by default and `sequential`/`disabled` under the switch; where the client falls back, a forced parallel failure prints a `balFallback` line; the client's own tests for each touched package pass.
