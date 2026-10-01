# Upstream sources the series copy

Patches below are copied from an upstream pull request rather than written here. The weekly pin refresh compares each PR's current head with the commit recorded here: if it moved, re-snapshot and re-prove; if it merged, drop the patch and use the client's own code.

| series | patch | upstream | head copied | what was taken |
| --- | --- | --- | --- | --- |
| geth-main | 0004 | ethereum/go-ethereum#34650 | `1b1c90a400e8e4d1149f427ff3aec58983f5e82b` | the whole PR, squashed and rebased onto the pin |
| reth-main | 0001 | paradigmxyz/reth#23361 | `a1bc4e9cba66df1de55263ffb8e24763919001b7` | `blocktest --json-array` only, without the PR's engine runners |
