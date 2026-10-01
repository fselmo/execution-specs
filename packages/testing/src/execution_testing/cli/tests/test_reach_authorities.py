"""
Authorizations whose authority the case also uses, and at the nonce's top.

Each test finds a generated case holding the shape, fills it, and reads
the authority's block access list entry, and for aliasing the reasons
recorded at one index: the shape is reached when the fill shows it, not
when the draw says so.
"""

import contextlib
import io
import warnings
from typing import Any, Callable, Dict, FrozenSet, Optional, Tuple

import pytest

from execution_testing.base_types import Address, Bytes, Hash, HexNumber
from execution_testing.forks import Amsterdam
from execution_testing.test_types.account_types import EOA

from ..fuzzer_bridge import campaign as mod
from ..fuzzer_bridge.bal_reach import observer_spec
from ..fuzzer_bridge.density import axis_collapse_warnings, axis_coverage
from ..fuzzer_bridge.generator import (
    AUTHORITY_PROBE_ADDRESS,
    BURNER_ADDRESS,
    MAX_NONCE,
    auth_prepare_gas,
    generate_fuzzer_output,
)
from ..fuzzer_bridge.models import (
    FuzzerAccountInput,
    FuzzerAuthorizationInput,
    FuzzerOutput,
    FuzzerTransactionInput,
)
from .template import template_case

PROBE = Address(AUTHORITY_PROBE_ADDRESS)

Shape = Callable[
    [FuzzerOutput, int, FuzzerTransactionInput, FuzzerAuthorizationInput],
    bool,
]


def _find(shape: Shape) -> Tuple[FuzzerOutput, int, Address]:
    """
    The first one-block case with a transaction, at its position, whose
    one authorization ``shape`` accepts, and that authorization's
    authority.
    """
    for seed in range(2000):
        case = generate_fuzzer_output(Amsterdam, seed)
        if case.block_count != 1 or any(tx.error for tx in case.transactions):
            continue
        for position, tx in enumerate(case.transactions):
            auths = tx.authorization_list or []
            if len(auths) == 1 and shape(case, position, tx, auths[0]):
                key = auths[0].signer_key
                assert key is not None
                return case, position, Address(EOA(key=key))
    raise AssertionError("no generated case holds the shape")


def _fill(
    case: FuzzerOutput, address: Address
) -> Tuple[Optional[Dict[str, Any]], FrozenSet[Tuple[str, ...]]]:
    """
    ``address``'s entry in the filled case's list, None if absent, and
    the pairs of reasons recorded at one block access index.
    """
    mod._init_fill_worker("Amsterdam")
    fork, eels = mod._FILL["fork"], mod._FILL["eels"]
    eels.bal_reach = observer_spec(fork)
    eels.last_bal_observation = None
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                fixture = mod.fill_case(case, fork, eels)
        aliases = frozenset(eels.last_bal_observation.aliases)
    finally:
        eels.bal_reach = None
    (block,) = fixture["blocks"]
    entry = next(
        (
            entry
            for entry in block["blockAccessList"]
            if Address(entry["address"]) == address
        ),
        None,
    )
    return entry, aliases


def _changes(entry: Dict[str, Any], field: str, value: str) -> Dict:
    return {
        int(c["blockAccessIndex"], 16): int(c[value], 16) for c in entry[field]
    }


def _sends_later(case: FuzzerOutput, authority: Address) -> bool:
    return any(tx.from_ == authority for tx in case.transactions)


SET_DELEGATION = "vm.eoa_delegation.set_delegation"


@pytest.mark.parametrize(
    "kind,used_by",
    [
        pytest.param("target", {"vm.interpreter.process_call"}, id="target"),
        pytest.param(
            "probe",
            {
                "vm.instructions.environment.balance",
                "vm.instructions.environment.extcodehash",
                "vm.instructions.system.call",
            },
            id="probe",
        ),
    ],
)
def test_an_authority_is_used_where_it_is_delegated(
    kind: str, used_by: set
) -> None:
    """
    The transaction delegating an authority also calls it, straight or
    through the probe, which reads it and calls it; the authority then
    sends a transaction of its own. The delegation is recorded at the
    same index as each of those accesses, and the authority's entry
    holds the delegation and both nonce bumps: the authorization's and
    its own transaction's.
    """

    def shape(
        case: FuzzerOutput,
        position: int,
        tx: FuzzerTransactionInput,
        auth: FuzzerAuthorizationInput,
    ) -> bool:
        del position
        assert auth.signer_key is not None
        authority = Address(EOA(key=auth.signer_key))
        target = authority if kind == "target" else PROBE
        return tx.to == target and _sends_later(case, authority)

    case, position, authority = _find(shape)
    (later,) = [
        i for i, tx in enumerate(case.transactions) if tx.from_ == authority
    ]
    entry, aliases = _fill(case, authority)
    assert entry is not None
    delegated, sent = position + 1, later + 1
    assert _changes(entry, "nonceChanges", "postNonce") == {
        delegated: 1,
        sent: 2,
    }
    assert delegated in _changes(entry, "codeChanges", "newCode")
    for reason in used_by:
        assert tuple(sorted((SET_DELEGATION, reason))) in aliases


@pytest.mark.parametrize(
    "nonce,listed",
    [
        pytest.param(MAX_NONCE - 1, True, id="below_max"),
        pytest.param(MAX_NONCE, False, id="max"),
    ],
)
def test_an_authorization_at_the_highest_nonce_never_loads_its_authority(
    nonce: int, listed: bool
) -> None:
    """
    An authorization declaring its authority's own nonce one below the
    highest applies and moves the nonce to the highest. At the highest it
    is skipped before the authority is loaded, so nothing else touching
    it, the authority is absent from the list.
    """

    def shape(
        case: FuzzerOutput,
        position: int,
        tx: FuzzerTransactionInput,
        auth: FuzzerAuthorizationInput,
    ) -> bool:
        del case, position, tx
        return int(auth.nonce) == nonce

    case, position, authority = _find(shape)
    entry, _ = _fill(case, authority)
    if listed:
        assert entry is not None
        assert _changes(entry, "nonceChanges", "postNonce") == {
            position + 1: MAX_NONCE
        }
    else:
        assert entry is None


@pytest.mark.parametrize("exists", [False, True], ids=["absent", "existing"])
@pytest.mark.parametrize(
    "margin,committed",
    [
        pytest.param(0, True, id="exact"),
        pytest.param(-1, False, id="one_short"),
        pytest.param(1, True, id="one_over"),
    ],
)
def test_an_authorization_commits_only_with_gas_for_its_charges(
    exists: bool, margin: int, committed: bool
) -> None:
    """
    A transaction to the burner carrying one authorization, with gas for
    exactly its intrinsic cost and the authority's charges, commits the
    delegation and then halts on the dispatch: the delegation survives.
    One gas short, preparation fails and rolls it back, so the authority
    holds no delegation and its nonce is unmoved.
    """
    case = template_case()
    key = Hash(0x1234567)
    authority = Address(EOA(key=key))
    accounts = dict(case.accounts)
    if exists:
        accounts[authority] = FuzzerAccountInput(
            balance=HexNumber(1), nonce=HexNumber(0)
        )
    (first, *_) = case.transactions
    tx = first.model_copy(
        update={
            "to": Address(BURNER_ADDRESS),
            "gas": HexNumber(auth_prepare_gas(Amsterdam, exists) + margin),
            "data": Bytes(b""),
            "value": HexNumber(0),
            "authorization_list": [
                FuzzerAuthorizationInput(
                    chain_id=HexNumber(1),
                    address=Address(BURNER_ADDRESS),
                    nonce=HexNumber(0),
                    signer_key=key,
                )
            ],
            "access_list": None,
            "gas_need_fraction": None,
            "block": 0,
        }
    )
    entry, _ = _fill(
        case.model_copy(
            update={
                "accounts": accounts,
                "transactions": [tx],
                "block_count": 1,
                "withdrawals": [],
            }
        ),
        authority,
    )
    delegated = entry is not None and bool(entry["codeChanges"])
    assert delegated == committed
    if committed:
        assert entry is not None
        assert _changes(entry, "nonceChanges", "postNonce") == {1: 1}


def test_every_authority_axis_keeps_all_its_values() -> None:
    """
    Aliased authorities, both ways of reaching them, sending and not, and
    both top nonces stay drawn.
    """
    coverage = axis_coverage(Amsterdam, range(0, 800))
    warnings_ = [
        w
        for w in axis_collapse_warnings(coverage)
        if w.startswith(("authority", "max_nonce_authority"))
    ]
    assert warnings_ == []
