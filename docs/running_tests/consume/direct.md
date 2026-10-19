# The `consume direct` Command

The `direct` method provides the fastest way to test EVM functionality by executing tests directly through a client's dedicated test interface (e.g. [`statetest`](https://github.com/ethereum/go-ethereum/blob/4bb097b7ffc32256791e55ff16ca50ef83c4609b/cmd/evm/staterunner.go) or [`blocktest`](https://github.com/ethereum/go-ethereum/blob/35dd84ce2999ecf5ca8ace50a4d1a6abc231c370/cmd/evm/blockrunner.go)).

```bash
uv run consume direct --bin=<evm-binary> [OPTIONS]
```

- `--bin BIN`: A client's test binary: a host path, or a binary in a container image (see [Running a Binary From an Image](#running-a-binary-from-an-image)). Repeat it to run several binaries.
- `--bal-modes MODES`: Comma-separated ways to execute blocks with access lists, each run as its own test (see [Access List Modes](#access-list-modes)).
- `--require-bal-parallel`: Fail, instead of warn, when a block that should run on the parallel executor does not.
- `--traces`: Collect execution traces from the evm executable.

!!! warning "Limited Client Support"

    Not all clients are supported. The `consume direct` command requires a client-specific test
    interface. See the table below for currently supported clients.

## Supported Clients

| Client | Binary | State Tests | Block Tests | Engine Tests |
|--------|--------|-------------|-------------|--------------|
| go-ethereum | `evm` | `statetest` | `blocktest` | `enginetest`[^1] |
| Besu | `evmtool` | `state-test` | `block-test` | `engine-test`[^1] |
| Nethermind | `nethtest` | `nethtest` | `nethtest --blockTest`, or `blocktest`[^1] | `enginetest`[^1] |
| Erigon | `evm` | `statetest` | `blocktest` | `enginetest`[^1] |
| Reth | `ef-test-runner` | | `blocktest`[^1] | `enginetest`[^1] |
| ethrex | `blocktest`, `enginetest` | | `blocktest`[^1] | `enginetest`[^1] |
| evmone | `evmone-statetest`, `evmone-blockchaintest` | `evmone-statetest` | `evmone-blockchaintest` | |

[^1]: Only for a binary that speaks the [client runner interface](#client-runners).

## Client Runners

The interface clients share for their block and engine test runners is described in [Client Test Runners](client_runners.md). A binary speaks it when the help of its block test command lists `--bal-sequential`. For such a binary, `consume direct`:

- runs each fixture file once and looks each test's fixture up in the results by its full name;
- trusts the results only after exit code `0` or `1`, and otherwise fails the file's tests with the runner's stderr;
- checks why each block or payload was rejected, by mapping the runner's error through the client's [exception mapper](exceptions.md), and names both sides when they differ: `block 4: expected TransactionException.X, client said "…" (maps to TransactionException.Y)`;
- also collects Blockchain Engine Tests and runs them through the engine test command; `-m blockchain_test` or `-m blockchain_test_engine` selects one of the two.

A binary that does not speak the interface runs as before, one fixture at a time, and no Blockchain Engine Tests are collected for it.

## Access List Modes

`--bal-modes` takes any of `parallel`, `sequential` and `withhold`, and runs each as its own test, with the mode in the test ID (`bal_sequential`):

- `parallel` runs blocks on the client's default executor and passes `--bal-report`. A valid block with an access list that did not run on the parallel executor, or any fallback to the sequential one, is reported as a `BalExecutionWarning`, or as a failure with `--require-bal-parallel`.
- `sequential` passes `--bal-sequential`.
- `withhold` passes `--bal-withhold`, and applies to block tests only.

Without `--bal-modes`, tests run once in the `parallel` mode and their IDs carry no mode. Modes other than `parallel` are skipped for binaries that do not speak the interface.

```bash
uv run consume direct --input ./fixtures --bin=evm --bal-modes parallel,sequential,withhold
```

## Running a Binary From an Image

`--bin docker:<image>` runs the image's entrypoint, and `--bin docker:<image>#<binary>` runs another binary in the image, by name or path. `#` cannot appear in an image reference, so the image's tag never gets in the way. Each command runs as `docker run --rm` without network, with the fixture files mounted read-only, and the `--dump-dir` output writable, at the same paths as on the host. The client is detected from the binary's version output, as for a host binary. Docker keeps the image after the first pull.

```bash
uv run consume direct --input ./fixtures --bin=docker:ethpandaops/besu:main#evmtool
```

To test a branch, build the client's image with [hive](https://github.com/ethereum/hive)'s `Dockerfile.git`, or a local checkout with its `Dockerfile.local`, from a hive checkout:

```bash
docker build -f clients/besu/Dockerfile.git \
  --build-arg github=<user>/besu --build-arg tag=<branch> -t besu-branch clients/besu
docker build -f clients/besu/Dockerfile.local \
  --build-arg local_path=besu -t besu-local clients/besu  # checkout at clients/besu/besu
uv run consume direct --input ./fixtures --bin=docker:besu-branch#/opt/besu/bin/evmtool
```

Besu's image carries `evmtool` beside the node. The other clients' hive images hold only the node, so build the runner from the same checkout and add it to a small image:

```dockerfile
FROM ubuntu:24.04
COPY evm /usr/local/bin/evm
ENTRYPOINT ["evm"]
```

## Advantages

- **Speed**: Fastest test execution method.
- **Simplicity**: No container or network overhead.
- **Debugging**: Easy access to traces and logs.

## Limitations

- **Limited client support**: Not all clients are supported (see [Supported Clients](#supported-clients) above).
- **Module scope**: Tests EVM, respectively block import, in isolation, not full client behavior.
- **Interface dependency**: Requires client-specific test interfaces.

## Example Usage

Only run state tests (by using a mark filter, `-m`) from a local `fixtures` folder with go-ethereum:

```bash
uv run consume direct --input ./fixtures -m state_test --bin=evm
```

or Besu:

```bash
uv run consume direct --input ./fixtures -m state_test --bin=evmtool
```

or Nethermind:

```bash
uv run consume direct --input ./fixtures -m state_test --bin=nethtest
```

or evmone:

```bash
uv run consume direct --input ./fixtures --bin=evmone-statetest --bin=evmone-blockchaintest
```

Run fixtures in the blockchain test format for the Prague fork:

```bash
uv run consume direct --input ./fixtures -m "blockchain_test and Prague" --bin=evm
```

Test selection via a regular expression match on collected fixture IDs:

```bash
uv run consume direct --input ./fixtures --sim.limit ".*push0.*"
```

Test selection via [pytest keyword expression match](https://docs.pytest.org/en/8.3.x/how-to/usage.html):

```bash
uv run consume direct --input ./fixtures -k "eip3855 or Prague"
```

Use `--collect-only -q` to get a list of available test fixture IDs:

```bash
uv run consume direct --input ./fixtures -k "eip3855 or Prague" --collect-only -q
```
