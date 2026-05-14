"""
Setup helpers for the CALL family matrix driver.

These functions build the runtime resources (target account, capsule
contract) that the test body needs. They are opcode-agnostic where
possible and opcode-aware only where required (e.g., `build_capsule`
uses the opcode's own kwargs structure).

Design — test capsule + harness pattern:

    tx ──► harness (built by assemble_wrapped) ──► capsule (built here)

The capsule runs the opcode-under-test and conveys the measured gas
to the harness via RETURN-from-memory — read-only operations that are
safe in any execution context (including static / under-STATICCALL).
The harness, which is always the top-level tx target and thus never
in a static context, captures the return data and SSTOREs it. The test
body asserts on the harness's storage slot.

This decouples *what is tested* (the opcode in the capsule) from *how it
is invoked* (the wrapper opcode in the harness), making the matrix
genuinely composable across execution contexts.
"""

from typing import Optional

from execution_testing import Address, Alloc, Fork, Op

# Module-level starting balances — exported so the test body and any
# expectation helper can refer to the same numbers.
CALLER_STARTING_BALANCE = 1_000_000
TARGET_STARTING_BALANCE = 1_000

# Fixed precompile representative for target_kind="precompile". Step 9
# uses one cheap precompile (IDENTITY at 0x04, 15 gas for empty input)
# so the matrix has uniform precompile coverage across forks. A future
# interaction test crosses all precompiles via `with_all_precompiles`.
PRECOMPILE_IDENTITY_ADDRESS = Address(4)
# IDENTITY base cost is 15 (per word: 3). With empty input (args_size=0)
# the total is 15.
PRECOMPILE_IDENTITY_BASE_GAS = 15


def target_starting_balance(target_kind: str) -> int:
    """
    Starting wei balance of the target for a given `target_kind`.

    Funded kinds (eoa, contract, 7702-delegated) pre-exist with
    `TARGET_STARTING_BALANCE`. Precompile addresses are not deployed and
    start at 0 wei.
    """
    if target_kind in ("eoa", "contract", "7702-delegated"):
        return TARGET_STARTING_BALANCE
    if target_kind == "precompile":
        return 0
    raise NotImplementedError(
        f"target_kind={target_kind!r} not yet handled in "
        "`_scenarios.target_starting_balance`."
    )


def caller_starting_balance_for(gas_variant: str) -> int:
    """
    Starting wei balance of the caller for a given `gas_variant`.

    - "sufficient": caller has plenty of wei to send the value transfer.
    - "insufficient-balance": caller has 0 wei; nonzero-value CALL/CALLCODE
      fails the `sender_balance < value` check and pushes 0.
    """
    if gas_variant == "sufficient":
        return CALLER_STARTING_BALANCE
    if gas_variant == "insufficient-balance":
        return 0
    raise NotImplementedError(
        f"gas_variant={gas_variant!r} not yet handled in "
        "`_scenarios.caller_starting_balance_for`."
    )


def build_target(
    pre: Alloc, target_kind: str, fork: Fork
) -> tuple[Address, Optional[Address]]:
    """
    Construct the *CALL target according to `target_kind`.

    Returns a (target_address, secondary_address) pair. `target_address`
    is the address the *CALL goes to; the target pre-exists in `pre`
    with `target_starting_balance(target_kind)` wei (when the kind is
    balance-bearing). Precompiles aren't deployed — their addresses are
    protocol-provided.

    `secondary_address` is `None` for most target kinds. For
    `target_kind="7702-delegated"`, it carries the delegate's address
    (the contract whose code the EVM runs when the delegated account is
    invoked). The expectations function uses it to assert the delegate
    is touched in the BAL.

    `fork` is taken because later target kinds (e.g., `7702` delegation)
    embed fork-specific bytecode.
    """
    if target_kind == "eoa":
        return pre.fund_eoa(TARGET_STARTING_BALANCE), None
    if target_kind == "contract":
        addr = pre.deploy_contract(Op.STOP, balance=TARGET_STARTING_BALANCE)
        return addr, None
    if target_kind == "precompile":
        return PRECOMPILE_IDENTITY_ADDRESS, None
    if target_kind == "7702-delegated":
        # EIP-7702 delegated account. Pre-state contains:
        #   - The delegate (a regular contract with body = STOP).
        #   - The delegated account, whose runtime code is
        #     `0xef0100 ++ <20-byte delegate address>`. Calling this
        #     account causes the EVM to fetch and run the delegate's
        #     code in the delegated account's storage/balance context.
        delegate = pre.deploy_contract(Op.STOP)
        delegation_code = b"\xef\x01\x00" + bytes(delegate)
        delegated_account = pre.deploy_contract(
            code=delegation_code,
            balance=TARGET_STARTING_BALANCE,
        )
        return delegated_account, delegate
    raise NotImplementedError(
        f"target_kind={target_kind!r} not yet handled. Extend "
        "`_scenarios.build_target` when adding new target kinds."
    )


def build_capsule(
    pre: Alloc,
    fork: Fork,
    opcode: Op,
    target: Address,
    transfer_value: int,
    starting_balance: int = CALLER_STARTING_BALANCE,
) -> Address:
    """
    Construct the *capsule*: a contract that runs the opcode-under-test
    and RETURNs the measured gas as 32 bytes via memory.

    The capsule uses only read-side ops (GAS, MSTORE, RETURN) for its
    bookkeeping, so it works inside *any* execution context — including
    static contexts where SSTORE would revert. This is what makes
    composition with `wrapper=under-STATICCALL` work.

    Bookkeeping is structurally identical to the framework's
    `CodeGasMeasure` (sandwich the opcode between two `GAS` reads, then
    a small dance to subtract overhead), but the final emission is
    MSTORE+RETURN instead of SSTORE.

    `starting_balance` controls the gas_variant axis: a capsule funded
    with 0 wei fails the `sender_balance < value` check on nonzero-value
    CALL/CALLCODE, exercising spec lines 438-440 in call().
    """
    push_cost = (Op.PUSH1(0) * len(opcode.kwargs)).gas_cost(fork)

    call_kwargs: dict = dict(
        gas=0,
        address=target,
        args_offset=0,
        args_size=0,
        ret_offset=0,
        ret_size=0,
    )
    if "value" in opcode.kwargs:
        call_kwargs["value"] = transfer_value

    # CodeGasMeasure-equivalent bookkeeping ending in MSTORE+RETURN.
    # Stack-tracking (each `+` separator is one bytecode step):
    #   GAS                      -> [G_init]
    #   <opcode kwargs pushes>   -> [G_init, kw...]
    #   <opcode>                 -> [G_init, success_bit]  (kwargs consumed)
    #   GAS                      -> [G_init, success_bit, G_after]
    #   SWAP1 + POP              -> [G_init, G_after]  (discard success)
    #   SWAP1                    -> [G_after, G_init]
    #   SUB                      -> [G_init - G_after]  = code_cost
    #                                                     (incl. 2nd GAS)
    #   PUSH push_cost           -> [code_cost, push_cost]
    #   GAS + GAS + SWAP1 + SUB  -> [code_cost, push_cost, 2]
    #                                                  (cost of GAS opcode)
    #   ADD                      -> [code_cost, push_cost + 2]
    #   SWAP1                    -> [push_cost + 2, code_cost]
    #   MSTORE(0, SUB)            -> SUB pops code_cost & overhead -> pushes
    #                                code_cost - (push_cost + 2); MSTORE writes
    #                                this value to mem[0..32].
    #   RETURN(0, 32)             -> return mem[0..32].
    capsule_code = (
        Op.GAS
        + opcode(**call_kwargs)
        + Op.GAS
        + Op.SWAP1
        + Op.POP
        + Op.SWAP1
        + Op.SUB
        + Op.PUSH1[push_cost]
        + Op.GAS
        + Op.GAS
        + Op.SWAP1
        + Op.SUB
        + Op.ADD
        + Op.SWAP1
        + Op.MSTORE(0, Op.SUB)
        + Op.RETURN(0, 32)
    )

    return pre.deploy_contract(capsule_code, balance=starting_balance)
