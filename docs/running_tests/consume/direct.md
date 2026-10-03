# The `consume direct` Command

The `direct` method provides the fastest way to test EVM functionality by executing tests directly through a client's dedicated test interface (e.g. [`statetest`](https://github.com/ethereum/go-ethereum/blob/4bb097b7ffc32256791e55ff16ca50ef83c4609b/cmd/evm/staterunner.go) or [`blocktest`](https://github.com/ethereum/go-ethereum/blob/35dd84ce2999ecf5ca8ace50a4d1a6abc231c370/cmd/evm/blockrunner.go)).

```bash
uv run consume direct --bin=<evm-binary> [OPTIONS]
```

- `--bin EVM_BIN`: Path to an evm executable that can process `StateTestFixture` and/or `BlockTestFixture` formats.
- `--traces`: Collect execution traces from the evm executable.
- `--disable-strict-exception-matching CLIENTS_OR_FORKS`: Comma-separated client names or forks for which a block rejected for an unexpected reason only warns (see [Rejection Reasons](#rejection-reasons)).

!!! warning "Limited Client Support"

    Not all clients are supported. The `consume direct` command requires a client-specific test
    interface. See the table below for currently supported clients.

## Supported Clients

| Client | Binary | State Tests | Block Tests |
|--------|--------|-------------|-------------|
| go-ethereum | `evm` | `statetest` | `blocktest` |
| Besu | `evmtool` | `state-test` | `block-test` |
| Nethermind | `nethtest` | `nethtest` | `nethtest --blockTest` |
| evmone | `evmone-statetest`, `evmone-blockchaintest` | `evmone-statetest` | `evmone-blockchaintest` |

## Rejection Reasons

For block tests, `consume direct` also checks why the client rejected each invalid block: each error is mapped through the client's exception mapper and must match the fixture's `expectException`, as `consume engine` does for `validationError`. This needs a runner that lists its rejections in a `rejections` field of each JSON result (`[{"index", "hash", "error"}]`, with `index` the block's position in the fixture's `blocks`); with an older runner only the outcome is checked, and a warning says so. An error the mapper does not recognize fails the test with the raw message, which usually means the mapper needs a new entry.

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
