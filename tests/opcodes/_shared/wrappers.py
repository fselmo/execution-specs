"""
Execution-context wrappers — cross-family helper.

`assemble_wrapped` returns the *harness* address: a contract that wraps a
capsule (built by the opcode family's `_scenarios.build_capsule`) under a
given execution context, captures the capsule's RETURN data (the measured
gas), and SSTOREs it to its own storage. The test body asserts on the
harness's storage slot — the harness is always the top-level tx target
and is therefore never in a static context, so its SSTORE always works.

Architecture (test capsule pattern):

    tx ─► harness ─► [(optional) intermediate]  ─► capsule
                     (wrapper opcode lives here)    (opcode-under-test,
                                                     RETURNs gas via mem)

The harness reads the chain's return data and SSTOREs it. If the chain
reverts (e.g., the capsule's CALL hits WriteInStaticContext under
STATICCALL), no return data is written, the harness's `MLOAD(0)` reads
zero from fresh memory, and `SSTORE(0, 0)` records the revert.

Wrapper kinds implemented:

  direct              — no intermediate; harness CALLs capsule directly.
  under-CALL          — intermediate CALLs capsule (one extra non-static
                         wrapping CALL — covers nested-call paths).
  under-STATICCALL    — intermediate STATICCALLs capsule (capsule runs in
                         static context).

Wrapper kinds deferred (require additional driver work — see Step 10b):

  under-CALLCODE      — capsule's code would run in intermediate's
                         storage/balance context; balance assertions
                         shift to intermediate. Doable but needs the
                         driver to know which contract is the
                         "balance owner."
  under-DELEGATECALL  — same as CALLCODE.
  under-CREATE-init / under-CREATE2-init — capsule runs as init code;
                         distinct shape, RETURNs runtime code.
  under-tx-init       — tx.to=None with capsule bytecode in tx.data.
"""

from execution_testing import Address, Alloc, Fork, Op

# Storage slot the harness uses to record the capsule's measured gas.
HARNESS_RESULT_SLOT = 0


def assemble_wrapped(
    *,
    capsule_address: Address,
    wrapper: str,
    pre: Alloc,
    fork: Fork,
) -> Address:
    """
    Deploy the harness (and any intermediate) for the given wrapper, and
    return the harness address. The tx in the test body targets this
    address.

    Test body assertion target: `harness.storage[HARNESS_RESULT_SLOT]`
    holds either the capsule's measured gas (if the chain succeeded) or
    zero (if the chain reverted; e.g., under-STATICCALL × CALL × value>0
    hits WriteInStaticContext).
    """
    if wrapper == "direct":
        return _build_harness_calling(
            pre=pre, target=capsule_address, via=Op.CALL
        )

    if wrapper == "under-CALL":
        intermediate = _build_passthrough_intermediate(
            pre=pre, target=capsule_address, via=Op.CALL
        )
        return _build_harness_calling(
            pre=pre, target=intermediate, via=Op.CALL
        )

    if wrapper == "under-STATICCALL":
        intermediate = _build_passthrough_intermediate(
            pre=pre, target=capsule_address, via=Op.STATICCALL
        )
        return _build_harness_calling(
            pre=pre, target=intermediate, via=Op.CALL
        )

    raise NotImplementedError(
        f"wrapper={wrapper!r} not yet implemented. "
        "See `tests/opcodes/_shared/wrappers.py` docstring for status."
    )


def _build_harness_calling(*, pre: Alloc, target: Address, via: Op) -> Address:
    """
    Build the outermost harness. The harness invokes `target` via `via`
    (CALL), forwards all available gas, captures 32 bytes of return data
    into local memory, then SSTOREs that value to `HARNESS_RESULT_SLOT`.

    The harness itself is always invoked by the tx directly, so it runs
    in non-static context — its SSTORE is always safe.
    """
    # `via` here is always CALL — the harness needs to forward gas + read
    # return data from a non-static context. STATIC/CALLCODE/DELEGATECALL
    # at the harness level would change the storage-attribution semantics
    # we rely on. The wrapper opcode is applied by the intermediate, not
    # the harness.
    assert via is Op.CALL, "harness must use plain CALL"

    return pre.deploy_contract(
        Op.CALL(
            gas=Op.GAS,
            address=target,
            value=0,
            args_offset=0,
            args_size=0,
            ret_offset=0,
            ret_size=32,
        )
        + Op.POP  # discard the *CALL's success bit
        + Op.SSTORE(HARNESS_RESULT_SLOT, Op.MLOAD(0))
    )


def _build_passthrough_intermediate(
    *, pre: Alloc, target: Address, via: Op
) -> Address:
    """
    Build a thin intermediate contract that invokes `target` via `via`
    (CALL or STATICCALL), captures up to 32 bytes of return data into
    its own memory, and RETURNs those 32 bytes to its caller.

    The wrapper-opcode semantics (e.g., propagating is_static under
    STATICCALL) are applied here.
    """
    if via is Op.CALL:
        wrap_op = Op.CALL(
            gas=Op.GAS,
            address=target,
            value=0,
            args_offset=0,
            args_size=0,
            ret_offset=0,
            ret_size=32,
        )
    elif via is Op.STATICCALL:
        wrap_op = Op.STATICCALL(
            gas=Op.GAS,
            address=target,
            args_offset=0,
            args_size=0,
            ret_offset=0,
            ret_size=32,
        )
    else:
        raise NotImplementedError(
            f"intermediate via={via!r} not implemented; expand the "
            "dispatch when adding under-CALLCODE / under-DELEGATECALL."
        )

    return pre.deploy_contract(wrap_op + Op.POP + Op.RETURN(0, 32))
