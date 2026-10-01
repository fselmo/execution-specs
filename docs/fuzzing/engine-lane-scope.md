# Engine lane: scope

A written scope for review before anything is built. The lane has three parts:
- client runners that consume `blockchain_test_engine` fixtures through each client's Engine API path;
- an EELS import leg, needed for the acceptance targets;
- the negative BAL lane.

## What the acceptance targets need

The six block-import survivors of the v26 held-out set are mutants in EELS's own `validate_header` and `execute_block`. By half:

| # | half | check |
| --- | --- | --- |
| 71 | tuning | `header.number != parent_header.number + 1` |
| 77 | tuning | `receipt_root != block.header.receipt_root` |
| 78 | tuning | `requests_hash != block.header.requests_hash` |
| 72 | evaluation | `len(rlp.encode(block)) > MAX_RLP_BLOCK_SIZE` |
| 73 | evaluation | `header.timestamp <= parent_header.timestamp` |
| 76 | evaluation | `header.gas_used > header.gas_limit` |

**Client engine runners cannot kill any of them.** Each runner runs its client's code and never EELS's, and EELS takes part in a case only as the filler. The fill runs EELS's transition tool, which builds a block and never imports one, so `validate_header` and `execute_block` never run. That is why the diagnostic found them never evaluated.

What reaches them is an **EELS import leg**: each filled block imported again through EELS's own `state_transition`, as `tests/json_loader/helpers/load_blockchain_tests.py` already does for the conformance fixtures. It runs in-process and needs no client. It gives an oracle that runs on every case: EELS must import every block it filled as valid, and reject every block the fixture expects to be rejected, with the same exception.

- Under 71, 73, 76, 77 and 78, EELS rejects every valid block it imports, so each is killed on the first seed.
- Under 72, EELS rejects every block smaller than the RLP limit, which is every generated block. It is killed on the first seed too.

The three evaluation mutants are reported by half with the rest. They do not shape the design: the import leg is built for the tuning three, and the evaluation three are what it measures on mutants it was not built for.

The import leg belongs in the diff lane (`fuzz diff`) and the campaign's fill step alike. It is a self-check of the filler and costs one extra EELS pass per case, roughly a fill's worth. It can be sampled like the contrasts if that cost matters.

## Client engine runners

The campaign already writes `blockchain_test_engine` fixtures (`fixture_format:`, abb92c8b18), with the BAL carried in `params[0].blockAccessList`. `runners.py` dispatches by consumer class to each client's block-import command. An engine runner is a second command per client, chosen by the campaign's format.

- **nethermind:** `nethtest --engineTest` exists at 5246d0c7. It takes `--parallelExecution` for engine tests as well as block tests, so its engine path needs no unlock. Work: a `--engineTest` branch in `runners.py`, and a check that its result list parses like `--blockTest`'s. The print patches 0002/0003 sit in `Consensus`, below the engine handler, so they should print on this path unchanged. To be checked on the first run.
- **besu:** `evmtool engine-test` exists at cf89071f, with `--json-array` output and `--workers`. It builds its schedule through `ReferenceTestProtocolSchedules.cached(...)`, the same factory patch 0001 parameterized because it hard-codes parallel processing off. So **the engine path needs the same unlock**: thread the flag into `engine-test`'s cached schedule and default it on, as 0002 did for `block-test`, with a sequential contrast flag.
  - The BAL arrives through `engine_newPayloadV5`'s parameters, so no attach patch like 0002's should be needed. That has to be verified the way 0002 was, with a probe at `ParallelTransactionPreprocessing.run` counting the blocks that take the parallel processor.
- **geth:** master has no engine runner. go-ethereum#34650 (spencer-tb, open, +1028/−40) adds `evm enginetest`. It is a lightweight handler mirroring `eth/catalyst.ConsensusAPI`: payload validation, `InsertBlockWithoutSetHead`, forkchoice and invalid-ancestor tracking. It matches Hive `consume engine`'s failures on the v5.3.0 fixtures. Work:
  - rebase it onto 920c0777 as a series patch;
  - check that the payload's BAL reaches `supportsParallelExecution`, which the import path needed 0002 for;
  - carry `--bal.sequential` over from 0001.

  The decision print (0003) is in `core` and applies unchanged.
- **erigon:** no engine runner. Erigon's newPayload runs through the engine API server into its execution module and the staged pipeline, which is much more to stand up in-process than geth's handler. A minimal runner is estimated at several days, against about a day for the geth rebase. Its import lane already runs the parallel path by default, so the recommendation is to leave erigon out of the engine lane at first.

## Negative BAL lane

In the engine format the delivered list is the payload's `blockAccessList`, and the header commits to its hash. A client must reject a payload whose delivered list does not match what the block's execution produces, and answer `INVALID`.

The oracle is the fixture's expected status, not EELS: EELS computes its own list and never sees the delivered bytes.

- **Generation:** a share of cases is written with the delivered list modified and `INVALID` expected. EEST already has the machinery: `Block.engine_new_payload_block_access_list` and the BAL modifiers from #3486. The modifications are:
  - drop an account;
  - drop a storage read;
  - change a written value;
  - move a change to another block access index;
  - add an entry the block never touched;
  - reorder a list;
  - duplicate an entry.

  Each keeps the header's hash of the true list, so the check under test is the client comparing what was delivered with what it executes, not a hash mismatch alone. A second variant re-hashes the modified list into the header and expects the block's own validation to reject it.
- **Findings:** a client that answers `VALID` to a modified list is a finding, as is one that answers `INVALID` to an unmodified one. The parallel-path series already showed the stock import path accepting a corrupted delivered list that the series rejects, so this is where the lane is expected to pay.
- **Clients:** nethermind and besu from the start, geth after #34650's rebase.

### As built (generator v37)

`fuzzer_bridge/negative.py`. A tenth of cases with no block already expected rejected are drawn negative, in four families: the list's content (a quarter), its canonical form (35%), its encoding (15%) and a header field (a quarter). An engine-format fill fills the case clean first, picks the target from the block's real list or header, then fills it again with the last block modified and its exception expected; other formats ignore the draw. The fixture's `_info.negative` records the draw and whether it applied.

- **Content (`bal`):** drop an account or an account's reads, change a balance or nonce, swap two indices, add an untouched account (sorted into place). Through the `expected_block_access_list` modifier, with the header re-hashed to the modified list. A list with nothing the kind can change (no storage read, one block access index) fills clean and records `applied: false`.
- **Canonical form (`form`, v37):** accounts reversed or one listed twice, both named `INCORRECT_BLOCK_FORMAT` as EEST names them, with `INVALID_BLOCK_ACCESS_LIST` beside it because EELS checks only the hash; then, each `INVALID_BLOCK_ACCESS_LIST`: one field list reversed, one field entry duplicated, a written key also read, an empty `slot_changes`, a change at index n+2, and a change to the value the account already holds. Each breaks one rule and leaves the rest canonical.
- **Encoding (`encoding`, v37):** the header commits to bytes no canonical encoder writes, through `override_rlp`: a scalar with a leading zero, a byte after the list, a 19-byte address, an empty string where an empty list goes. The first three also accept `INVALID_BLOCK_HASH`, for a client that re-encodes what it decoded; the string is `INVALID_BLOCK_ACCESS_LIST` alone, as EEST's `0x80` payload is. Engine only.
- **Every kind's block hash is the one its modified payload rebuilds to**, since that is the header a client derives on `newPayload`.
- **The variant above that keeps the true list's hash is not on the engine path** (dropped at v33). A client derives the header's list hash from the delivered list, so the payload fails its block hash before any list check runs: at v32 that was 669 besu and nethermind failures, a harness artefact rather than findings. The variant belongs on the import lane, where the parallel-path series attach the fixture's own list beside an unchanged header. It is built there from v40 (`delivered_list_fixture`), as information rather than a judged negative: the block is valid, its header committing to the true list, so a runner that ignores the delivered list rightly imports it, and the fixture format cannot yet say "valid block, bad delivered list". Each lane's answer, refused or imported, is recorded and reported; none is a finding.
- **Header:** `number`, `timestamp` (equal to the parent's), `gas_used` (limit + 1), `receipts_root`; and from v37 the two-dimensional `gas_used` (EIP-8037), `INVALID_GAS_USED`: the block's execution plus state gas, or what its senders paid where that differs from the sum, on blocks where the value is not the header's max and fits the limit. Both dimensions come from importing the clean fixture through EELS with `apply_body` watched, since a header and the transition tool report only the max. The requests are corrupted through `Block.requests`, one random deposit, because the engine payload carries the requests and not their hash: a header-only hash change would test only the block hash on that path.
- **Not built: block RLP above the size limit.** No generated block comes near it within the block's gas, and one that did would be a ten-megabyte fixture per case.
- **Witnesses** (`test_negative_cases.py`): every kind's engine fixture, imported as `newPayload` receives it, hashes to its block hash and is refused with the exception it names. In the blockchain format every kind but the encodings is refused, the same case unmodified imports, and the two headers differ only in the kind's field. Breaking `number` to a no-op fails its witness with "expected INVALID_BLOCK_NUMBER, imported". In a campaign, a negative EELS does not refuse as named is dropped before any client sees it.
- **Guard axes:** `negative_case`, `negative_family`, and one `negative_<family>_kind` axis per family.
- **To check on the first engine run:** a client may answer a payload whose `number` is off by one with `SYNCING` rather than `INVALID`, which the runner would score as a finding. Classify it before counting it.

## Order

1. **The EELS import leg** in `fuzz diff` and the campaign fill, with a witness test that a filled case imports cleanly. Measure it on the v26 held-out set: the tuning three should fall at once, and the evaluation three are reported beside them.
2. **nethermind's `--engineTest` in `runners.py`**, on engine-format campaigns.
3. **besu's engine-path unlock** as a series patch, with the probe.
4. **The negative BAL lane's generation and oracle**, on nethermind and besu.
5. **geth: #34650 rebased**, with the BAL check.
6. **erigon:** deferred.

## Open questions

- **Where the import leg runs.** Should it run on every case, or sampled? One more EELS pass per case roughly doubles the filler's work in the diff lane. In producer mode it could run only on escalated cases, but then it would not check the producer's fixtures.
- **Server CC or here.** Building the geth and besu series patches needs the client build toolchains on the server. This machine cannot compile until its Xcode license is accepted.
