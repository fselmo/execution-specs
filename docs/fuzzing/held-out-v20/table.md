| # | stratum | module | mutation | outcome |
| --- | --- | --- | --- | --- |
| 00 | gas-arithmetic | gas.py | `int(state_gas_reservoir) - int(gas_meter.state_gas_left) + i` → `int(state_gas_reservoir) - int(gas_meter.state_gas_left) + i` | killed 179/300 |
| 01 | gas-arithmetic | gas.py | `Uint(gas_meter.state_gas_left) + Uint(gas_meter.gas_left) >=` → `Uint(gas_meter.state_gas_left) + Uint(gas_meter.gas_left) > ` | **survived** |
| 02 | gas-arithmetic | gas.py | `GasCosts.PER_BLOB * U64(len(tx.blob_versioned_hashes))` → `GasCosts.PER_BLOB // U64(len(tx.blob_versioned_hashes))` | **survived** |
| 03 | gas-arithmetic | gas.py | `tx_gas > state_gas_available` → `tx_gas < state_gas_available` | spec crash |
| 04 | gas-arithmetic | gas.py | `GasCosts.BLOB_SCHEDULE_MAX - GasCosts.BLOB_SCHEDULE_TARGET` → `GasCosts.BLOB_SCHEDULE_MAX + GasCosts.BLOB_SCHEDULE_TARGET` | **survived** |
| 05 | gas-arithmetic | gas.py | `gas_left < extra_gas + memory_cost` → `gas_left > extra_gas + memory_cost` | killed 237/300 |
| 06 | gas-arithmetic | gas.py | `block_env.block_gas_limit - block_output.block_state_gas_use` → `block_env.block_gas_limit + block_output.block_state_gas_use` | **survived** |
| 07 | gas-arithmetic | gas.py | `int(state_gas_reservoir) - int(gas_meter.state_gas_left) + i` → `int(state_gas_reservoir) - int(gas_meter.state_gas_left) - i` | killed 70/300 |
| 08 | frame-handling | interpreter.py | `evm.depth > STACK_DEPTH_LIMIT` → `evm.depth < STACK_DEPTH_LIMIT` | spec crash |
| 09 | frame-handling | interpreter.py | `not account_deployable(tx_env.state, current_target)` → `account_deployable(tx_env.state, current_target)` | **survived** |
| 10 | frame-handling | interpreter.py | `not evm.error` → `evm.error` | killed 5/300 |
| 11 | frame-handling | interpreter.py | `len(contract_code) > MAX_CODE_SIZE` → `len(contract_code) < MAX_CODE_SIZE` | killed 3/300 |
| 12 | frame-handling | interpreter.py | `evm.running and evm.pc < ulen(evm.code)` → `evm.running or evm.pc < ulen(evm.code)` | spec crash |
| 13 | frame-handling | interpreter.py | `contract_code[0] == 0xEF` → `contract_code[0] != 239` | killed 3/300 |
| 14 | frame-handling | interpreter.py | `evm.code_address in PRE_COMPILED_CONTRACTS` → `evm.code_address not in PRE_COMPILED_CONTRACTS` | spec crash |
| 15 | frame-handling | interpreter.py | `not evm.disable_precompiles` → `evm.disable_precompiles` | killed 213/300 |
| 16 | call-paths | system.py | `value != 0` → `value == 0` | killed 83/300 |
| 17 | call-paths | system.py | `GasCosts.CREATE_ACCESS + GasCosts.OPCODE_KECCAK256_PER_WORD ` → `GasCosts.CREATE_ACCESS - GasCosts.OPCODE_KECCAK256_PER_WORD ` | spec crash |
| 18 | call-paths | system.py | `GasCosts.CREATE_ACCESS + extend_memory.cost + init_code_gas` → `GasCosts.CREATE_ACCESS + extend_memory.cost - init_code_gas` | **survived** |
| 19 | call-paths | system.py | `2**64 - 1` → `2 ** 64 + 1` | **survived** |
| 20 | call-paths | system.py | `gas_cost + account_write_gas` → `gas_cost - account_write_gas` | **survived** |
| 21 | call-paths | system.py | `sender.balance < endowment` → `sender.balance <= endowment` | killed 91/300 |
| 22 | call-paths | system.py | `to not in evm.accessed_addresses` → `to in evm.accessed_addresses` | killed 144/300 |
| 23 | call-paths | system.py | `b"\x00" * extend_memory.expand_by` → `b'\x00' // extend_memory.expand_by` | spec crash |
| 24 | state-tracker | state_tracker.py | `get_account_optional(tx_state, address) is not None` → `get_account_optional(tx_state, address) is None` | killed 188/300 |
| 25 | state-tracker | state_tracker.py | `account is not None` → `account is None` | killed 17/300 |
| 26 | state-tracker | state_tracker.py | `address in tx_state.created_accounts` → `address not in tx_state.created_accounts` | spec crash |
| 27 | state-tracker | state_tracker.py | `address not in tx_state.storage_writes` → `address in tx_state.storage_writes` | spec crash |
| 28 | state-tracker | state_tracker.py | `account.nonce == Uint(0)` → `account.nonce != Uint(0)` | spec crash |
| 29 | state-tracker | state_tracker.py | `address in tx_state.parent.storage_writes` → `address not in tx_state.parent.storage_writes` | spec crash |
| 30 | state-tracker | state_tracker.py | `account is None` → `account is not None` | killed 24/300 |
| 31 | state-tracker | state_tracker.py | `code_hash == EMPTY_CODE_HASH` → `code_hash != EMPTY_CODE_HASH` | spec crash |
